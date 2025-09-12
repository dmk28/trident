use clap::{Parser, ValueEnum};
use std::net::IpAddr;

mod domain_resolver;
mod evasion;
mod os_fingerprint;
mod plugins;
mod scanner;
mod vulndb;

use evasion::{EvasionConfig, PortSpoofingConfig, PortSpoofingStrategy};
use plugins::{
    ExecutionMode, PluginManager, service_detection::ServiceDetectionPlugin,
    vulnerability_scanner::VulnerabilityPlugin,
};
use scanner::{ConnectScanner, EvasiveScannerWrapper, ScanConfig, UdpScanner, parse_port_range};
use std::sync::Arc;

use crate::domain_resolver::resolve_ip;

// Function to parse CIDR and return list of IPs
fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    // Simple CIDR parsing - can be enhanced
    if let Some((ip_str, mask_str)) = cidr.split_once('/') {
        let base_ip: IpAddr = ip_str.parse()?;
        let mask: u32 = mask_str.parse()?;
        let mut ips = Vec::new();

        // For IPv4, generate IPs in range
        if let IpAddr::V4(base) = base_ip {
            let base_u32 = u32::from(base);
            let num_hosts = 2u32.pow(32 - mask);
            for i in 0..num_hosts {
                let ip_u32 = base_u32 + i;
                ips.push(IpAddr::V4(ip_u32.into()));
            }
        }

        Ok(ips)
    } else {
        Err("Invalid CIDR format".into())
    }
}

#[derive(Parser, Debug)]
#[command(name = "project_trident")]
#[command(about = "A comprehensive network scanner and vulnerability detector")]
#[command(version = "1.0")]
struct Args {
    /// Target IP address, hostname, or CIDR range (e.g., 192.168.1.0/24) to scan
    target: String,

    /// Network interface to use for scanning (auto-selected if not specified)
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// Port range to scan (e.g., "80", "1-1024", "22,80,443,8080")
    ports: Option<String>,

    /// Script categories to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    script: Option<Vec<ScriptCategory>>,

    /// Only run safe scripts (no potentially harmful checks)
    #[arg(long)]
    safe: bool,

    /// Run all available scripts
    #[arg(long)]
    script_all: bool,

    /// List available script categories
    #[arg(long)]
    script_help: bool,

    /// Timeout for scan operations in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,

    /// Scan type: syn or connect
    #[arg(long, value_enum, default_value = "syn")]
    scan_type: ScanType,

    #[arg(short = 'D', long, default_value = "0")]
    decoys: usize,

    #[arg(short = 'g', long)]
    source_port: Option<u16>,

    #[arg(long)]
    ipv6_decoys: bool,

    /// Port spoofing strategy (trusted, high-privilege, noise, service-matching)
    #[arg(long, value_enum, default_value = "trusted")]
    spoof_strategy: SpoofStrategy,

    /// Enable port spoofing for firewall bypass
    #[arg(long)]
    spoof_ports: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScanType {
    /// SYN scan (default)
    Syn,
    /// TCP connect scan
    Connect,
    /// UDP scan
    Udp,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SpoofStrategy {
    /// Use well-known trusted ports (DNS, HTTP, HTTPS)
    Trusted,
    /// Use high privilege ports (1-1024)
    HighPrivilege,
    /// Mix trusted ports with noise
    Noise,
    /// Match source port to target service
    ServiceMatching,
}

impl From<SpoofStrategy> for PortSpoofingStrategy {
    fn from(strategy: SpoofStrategy) -> Self {
        match strategy {
            SpoofStrategy::Trusted => PortSpoofingStrategy::TrustedPorts,
            SpoofStrategy::HighPrivilege => PortSpoofingStrategy::HighPrivilege,
            SpoofStrategy::Noise => PortSpoofingStrategy::TrustedWithNoise,
            SpoofStrategy::ServiceMatching => PortSpoofingStrategy::ServiceMatching,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum ScriptCategory {
    /// Vulnerability detection scripts
    Vuln,
    /// Service detection and enumeration
    Discovery,
    /// Authentication testing scripts
    Auth,
    /// Database-specific checks
    Database,
    /// Web application testing
    Web,
    /// Network service analysis
    Network,
    /// Information gathering
    Info,
    /// Safe scripts only (no potentially harmful operations)
    Safe,
    /// Default set of scripts
    Default,
}

impl ScriptCategory {
    fn description(&self) -> &'static str {
        match self {
            ScriptCategory::Vuln => "Detect known vulnerabilities and security issues",
            ScriptCategory::Discovery => "Enumerate services and gather system information",
            ScriptCategory::Auth => "Test authentication mechanisms and weak credentials",
            ScriptCategory::Database => "Database-specific vulnerability checks",
            ScriptCategory::Web => "Web application security testing",
            ScriptCategory::Network => "Network service analysis and configuration checks",
            ScriptCategory::Info => "Information gathering and reconnaissance",
            ScriptCategory::Safe => "Only safe scripts that don't modify target systems",
            ScriptCategory::Default => "Default set of commonly used scripts",
        }
    }
}

fn print_script_help() {
    println!("Available script categories:");
    println!();
    for category in [
        ScriptCategory::Vuln,
        ScriptCategory::Discovery,
        ScriptCategory::Auth,
        ScriptCategory::Database,
        ScriptCategory::Web,
        ScriptCategory::Network,
        ScriptCategory::Info,
        ScriptCategory::Safe,
        ScriptCategory::Default,
    ] {
        println!(
            "  {:12} - {}",
            format!("{:?}", category).to_lowercase(),
            category.description()
        );
    }
    println!();
    println!("Examples:");
    println!("  --script vuln,discovery     Run vulnerability and discovery scripts");
    println!("  --script safe               Run only safe scripts");
    println!("  --script-all                Run all available scripts");
    println!("  --safe                      Equivalent to --script safe");
}

fn get_interface_ip_from_name(interface_name: &str) -> Result<IpAddr, Box<dyn std::error::Error>> {
    use pnet::datalink;
    let interfaces = datalink::interfaces();

    for interface in interfaces {
        if interface.name == interface_name {
            if let Some(ip_network) = interface.ips.first() {
                return Ok(ip_network.ip());
            }
        }
    }

    Err(format!("Interface {} not found or has no IP", interface_name).into())
}

fn auto_select_interface() -> Result<(String, IpAddr), Box<dyn std::error::Error>> {
    use pnet::datalink;
    let interfaces = datalink::interfaces();

    // First, try to find a non-loopback interface with an assigned IP
    for interface in &interfaces {
        if !interface.is_loopback() && !interface.ips.is_empty() {
            // Prefer IPv4 addresses
            for ip_network in &interface.ips {
                if ip_network.is_ipv4() {
                    println!(
                        "🔧 Auto-selected interface: {} ({})",
                        interface.name,
                        ip_network.ip()
                    );
                    return Ok((interface.name.clone(), ip_network.ip()));
                }
            }

            // Fall back to IPv6 if no IPv4 found
            if let Some(ip_network) = interface.ips.first() {
                println!(
                    "🔧 Auto-selected interface: {} ({})",
                    interface.name,
                    ip_network.ip()
                );
                return Ok((interface.name.clone(), ip_network.ip()));
            }
        }
    }

    // If no non-loopback interface found, try loopback as last resort
    for interface in &interfaces {
        if interface.is_loopback() && !interface.ips.is_empty() {
            if let Some(ip_network) = interface.ips.first() {
                println!(
                    "⚠️  Only loopback interface available: {} ({})",
                    interface.name,
                    ip_network.ip()
                );
                return Ok((interface.name.clone(), ip_network.ip()));
            }
        }
    }

    Err("No suitable network interface found with an assigned IP address".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.script_help {
        print_script_help();
        return Ok(());
    }

    let (interface_name, interface_ip) = if let Some(ref interface) = args.interface {
        // Use specified interface
        let ip = get_interface_ip_from_name(interface)?;
        (interface.clone(), ip)
    } else {
        // Auto-select interface
        auto_select_interface()?
    };

    // Parse target as IP, hostname, or CIDR range
    let target_ips = if args.target.contains('/') {
        // CIDR notation
        parse_cidr(&args.target)?
    } else {
        // Single IP or hostname
        match args.target.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                println!(
                    "🔍 Could not parse '{}' as IP address, attempting DNS resolution...",
                    args.target
                );
                match resolve_ip(&args.target).await {
                    Ok(ip) => {
                        println!("✅ Resolved '{}' to {}", args.target, ip);
                        vec![ip]
                    }
                    Err(e) => {
                        println!("❌ Error resolving hostname '{}': {}", args.target, e);
                        std::process::exit(1);
                    }
                }
            }
        }
    };

    let ports_to_scan: Vec<u16> = if let Some(ref port_range) = args.ports {
        parse_port_range(&port_range)
    } else {
        vec![
            22, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5432, 8080, 8443,
        ]
    };

    // Create evasion configuration from CLI arguments
    let evasion_config = EvasionConfig {
        decoy_count: args.decoys,
        use_ipv6: args.ipv6_decoys,
        source_port: args.source_port,
        decoy_delay_us: 100,
        randomize_order: true,
    };

    // Create port spoofing configuration
    let port_spoofing_config = if args.spoof_ports || args.decoys > 0 {
        Some(PortSpoofingConfig {
            strategy: args.spoof_strategy.into(),
            noise_probability: match args.spoof_strategy {
                SpoofStrategy::Noise => 0.3,
                _ => 0.1,
            },
            prefer_dns: true,
            prefer_http: true,
            avoid_ephemeral: true,
        })
    } else {
        None
    };

    // Determine which script categories to run
    let script_categories = determine_script_categories(&args);

    if script_categories.is_empty() {
        println!(
            "\n⚠️  No scripts selected. Use --script to specify categories or --script-help for options."
        );
        return Ok(());
    }

    // Scan each IP in the range
    for (i, destination_ip) in target_ips.iter().enumerate() {
        println!(
            "\n🔍 Scanning IP {}/{}: {}",
            i + 1,
            target_ips.len(),
            destination_ip
        );

        let mut syn_scanner = None;
        let scan_results = match args.scan_type {
            ScanType::Syn => {
                // Create evasive scanner wrapper with proper source port configuration
                let use_dynamic_ports = args.spoof_ports || args.source_port.is_none();
                let config = ScanConfig::new_with_source_port_config(
                    *destination_ip,
                    ports_to_scan.clone(),
                    interface_ip,
                    args.timeout,
                    use_dynamic_ports,
                    args.source_port,
                );
                let mut scanner = if args.decoys > 0 || args.spoof_ports {
                    if args.decoys > 0 {
                        println!(
                            "🚀 Starting evasion-enabled SYN scan with {} decoys...",
                            args.decoys
                        );
                    }
                    if args.spoof_ports {
                        println!(
                            "🔧 Port spoofing enabled: {:?} strategy",
                            args.spoof_strategy
                        );
                    }
                    if args.source_port.is_some() {
                        println!("🔧 Using fixed source port: {}", args.source_port.unwrap());
                    }
                    if args.ipv6_decoys {
                        println!("🌐 IPv6 decoys enabled");
                    }
                    EvasiveScannerWrapper::new_with_evasion_and_spoofing(
                        config,
                        evasion_config.clone(),
                        port_spoofing_config.clone(),
                    )
                } else {
                    println!("🚀 Starting SYN scan...");
                    EvasiveScannerWrapper::new(config)
                };

                scanner.scan().await?;
                syn_scanner = Some(scanner);
                syn_scanner.as_ref().unwrap().get_results().clone()
            }
            ScanType::Connect => {
                println!("🚀 Starting TCP connect scan...");
                let use_dynamic_ports = args.spoof_ports || args.source_port.is_none();
                let config = ScanConfig::new_with_source_port_config(
                    *destination_ip,
                    ports_to_scan.clone(),
                    interface_ip,
                    args.timeout,
                    use_dynamic_ports,
                    args.source_port,
                );
                let scanner = ConnectScanner::new(config);
                let (results, _) = scanner
                    .scan_tcp(*destination_ip, ports_to_scan.clone())
                    .await?;
                results
            }
            ScanType::Udp => {
                println!("🚀 Starting UDP scan...");
                let use_dynamic_ports = args.spoof_ports || args.source_port.is_none();
                let config = ScanConfig::new_with_source_port_config(
                    *destination_ip,
                    ports_to_scan.clone(),
                    interface_ip,
                    args.timeout,
                    use_dynamic_ports,
                    args.source_port,
                );
                let mut scanner = UdpScanner::new(config);
                scanner.scan()?
            }
        };

        println!("\n=== Port Scan Results for {} ===", destination_ip);
        for result in &scan_results {
            println!("Port {}: {:?}", result.port, result.status);
        }

        // Print evasion statistics if evasion was enabled
        if let Some(scanner) = syn_scanner {
            if scanner.is_evasion_enabled() {
                println!("\n🥷 === Evasion Statistics ===");
                let stats = scanner.get_evasion_stats();
                println!("{}", stats);
            }
        }

        // Initialize plugin system
        println!("\n🔌 Initializing plugin system...");
        println!("📝 Running script categories: {:?}", script_categories);
        let mut plugin_manager = PluginManager::new();

        // Register plugins based on selected categories
        register_plugins_for_categories(&mut plugin_manager, &script_categories);

        // Configure plugin execution
        plugin_manager.set_execution_mode(ExecutionMode::Priority);

        // Run plugins against scan results
        println!("\n🔍 Running security analysis plugins...");
        let plugin_results = plugin_manager
            .execute_plugins_with_target(&scan_results, *destination_ip)
            .await;

        // Display plugin findings
        println!("\n🎯 Security Analysis Results for {}:", destination_ip);
        println!("=====================================");

        for result in &plugin_results {
            if !result.findings.is_empty() {
                println!(
                    "\n📋 {} ({}:{})",
                    result.plugin_name, result.target_ip, result.target_port
                );
                println!("   Execution time: {:?}", result.execution_time);

                for (i, finding) in result.findings.iter().enumerate() {
                    let severity_emoji = match finding.severity {
                        plugins::Severity::Critical => "🔴",
                        plugins::Severity::High => "🟠",
                        plugins::Severity::Medium => "🟡",
                        plugins::Severity::Low => "🔵",
                        plugins::Severity::Info => "ℹ️",
                    };

                    println!(
                        "   {} [{:?}] {}",
                        severity_emoji, finding.severity, finding.title
                    );
                    println!("      Description: {}", finding.description);
                    println!("      Confidence: {:.1}%", finding.confidence * 100.0);

                    if !finding.evidence.is_empty() {
                        println!("      Evidence: {}", finding.evidence.join(", "));
                    }

                    if !finding.recommendations.is_empty() {
                        println!("      Recommendations:");
                        for rec in &finding.recommendations {
                            println!("        • {}", rec);
                        }
                    }

                    if i < result.findings.len() - 1 {
                        println!();
                    }
                }
            }
        }

        // Summary
        let total_findings = plugin_results
            .iter()
            .map(|r| r.findings.len())
            .sum::<usize>();
        if total_findings > 0 {
            println!(
                "\n📊 Found {} security findings across {} services on {}",
                total_findings,
                plugin_results.len(),
                destination_ip
            );
        } else {
            println!(
                "\n✅ No security issues detected by plugins on {}",
                destination_ip
            );
        }
    }

    println!("\n🎉 Scan and analysis complete!");
    Ok(())
}

fn determine_script_categories(args: &Args) -> Vec<ScriptCategory> {
    if args.script_all {
        return vec![
            ScriptCategory::Vuln,
            ScriptCategory::Discovery,
            ScriptCategory::Auth,
            ScriptCategory::Database,
            ScriptCategory::Web,
            ScriptCategory::Network,
            ScriptCategory::Info,
        ];
    }

    if args.safe {
        return vec![ScriptCategory::Safe];
    }

    if let Some(ref categories) = args.script {
        return categories.clone();
    }

    // Default categories if none specified
    vec![ScriptCategory::Default]
}

fn register_plugins_for_categories(
    plugin_manager: &mut PluginManager,
    categories: &[ScriptCategory],
) {
    for category in categories {
        match category {
            ScriptCategory::Vuln => {
                plugin_manager.register_plugin(Arc::new(VulnerabilityPlugin::new()));
            }
            ScriptCategory::Discovery => {
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
            }
            ScriptCategory::Default => {
                plugin_manager.register_plugin(Arc::new(VulnerabilityPlugin::new()));
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
            }
            ScriptCategory::Safe => {
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                // Only add safe vulnerability checks
            }
            _ => {
                // For now, register basic plugins for other categories
                // TODO: Implement category-specific plugins
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(VulnerabilityPlugin::new()));
            }
        }
    }
}
