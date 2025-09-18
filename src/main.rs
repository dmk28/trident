use chrono;
use clap::{Parser, ValueEnum};
mod data;
use data::common_ports::*;
use std::net::IpAddr;
mod domain_resolver;
mod errors;
mod evasion;
mod os_fingerprint;
mod output;
mod plugins;
mod scanner;
mod vulndb;

use plugins::shared_services::init_shared_services_with_verbose;

use evasion::{EvasionConfig, PortSpoofingConfig, PortSpoofingStrategy};
use plugins::{
    ExecutionMode, PluginManager,
    database_detection::DatabaseDetectionPlugin,
    os_fingerprint_plugin::OsFingerprintPlugin,
    service_detection::ServiceDetectionPlugin,
    vuln_database_plugin::VulnDatabasePlugin,
    vulnerability_plugins::{
        auth_vulns::{DefaultAccountScanner, WeakPasswordScanner},
        config_vulns::{DebugModeScanner, MisconfigurationScanner},
        crypto_vulns::{CertificateScanner, WeakEncryptionScanner},
        database_vulns::{DefaultCredsScanner, SqlInjectionScanner, WeakAuthScanner},
        injection_vulns::{CommandInjectionScanner, LdapInjectionScanner, NoSqlInjectionScanner},
        network_vulns::{PlaintextProtocolScanner, WeakCipherScanner},
        web_vulns::{DirectoryTraversalScanner, SecurityHeaderScanner, XssScanner},
    },
    vulnerability_scanner::VulnerabilityPlugin,
};
use scanner::{
    ConnectScanner, EvasiveScannerWrapper, PortStatus, ScanConfig, UdpScanner, parse_port_range,
};
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
    #[arg(long, default_value = "30")]
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

    /// Output format for results (json, markdown)
    #[arg(long)]
    output_format: Option<String>,

    /// Output directory for result files (default: trident_outputs)
    #[arg(long)]
    output_dir: Option<String>,

    /// Maximum scan rate (packets per second)
    #[arg(long, default_value = "1000")]
    rate: u32,

    /// Maximum number of retries for failed connections
    #[arg(long, default_value = "3")]
    max_retries: u32,

    /// Maximum RTT timeout in milliseconds for adaptive timing
    #[arg(long, default_value = "5000")]
    max_rtt_timeout: u64,

    /// Enable verbose output with detailed progress and debug information
    #[arg(short = 'v', long)]
    verbose: bool,
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

fn auto_select_interface(verbose: bool) -> Result<(String, IpAddr), Box<dyn std::error::Error>> {
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
                if verbose {
                    println!(
                        "🔧 Auto-selected interface: {} ({})",
                        interface.name,
                        ip_network.ip()
                    );
                }
                return Ok((interface.name.clone(), ip_network.ip()));
            }
        }
    }

    // If no non-loopback interface found, try loopback as last resort
    for interface in &interfaces {
        if interface.is_loopback() && !interface.ips.is_empty() {
            if let Some(ip_network) = interface.ips.first() {
                if verbose {
                    println!(
                        "🔧 Using loopback interface: {} ({})",
                        interface.name,
                        ip_network.ip()
                    );
                }
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

    // Initialize shared services early
    init_shared_services_with_verbose(args.verbose).await;
    if args.verbose {
        println!("🚀 Project Trident initialized with shared services");
    }

    // Initialize output writer if format is specified
    let output_writer = if let Some(ref format) = args.output_format {
        let output_format = match format.to_lowercase().as_str() {
            "json" => output::OutputFormat::Json,
            "markdown" | "md" => output::OutputFormat::Markdown,
            _ => {
                println!("❌ Invalid output format. Use 'json' or 'markdown'");
                std::process::exit(1);
            }
        };
        Some(output::OutputWriter::new(
            output_format,
            args.output_dir.clone(),
        ))
    } else {
        None
    };

    let (interface_name, interface_ip) = if let Some(ref interface) = args.interface {
        // Use specified interface
        let ip = get_interface_ip_from_name(interface)?;
        (interface.clone(), ip)
    } else {
        // Auto-select interface
        auto_select_interface(args.verbose)?
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
                if args.verbose {
                    println!(
                        "🔍 Could not parse '{}' as IP address, attempting DNS resolution...",
                        args.target
                    );
                }
                match resolve_ip(&args.target).await {
                    Ok(ip) => {
                        if args.verbose {
                            println!("✅ Resolved '{}' to {}", args.target, ip);
                        }
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
        get_default_ports()
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

        let scan_start = std::time::Instant::now();
        let mut syn_scanner = None;
        let scan_results = match args.scan_type {
            ScanType::Syn => {
                // Create evasive scanner wrapper with proper source port configuration
                let use_dynamic_ports = args.spoof_ports || args.source_port.is_none();
                let config = ScanConfig::new_with_rate_control(
                    *destination_ip,
                    ports_to_scan.clone(),
                    interface_ip,
                    args.timeout,
                    args.rate,
                    args.max_retries,
                    use_dynamic_ports,
                    args.source_port,
                    args.verbose,
                );
                let mut scanner = if args.decoys > 0 || args.spoof_ports {
                    if args.verbose {
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
                    }
                    if args.ipv6_decoys && args.verbose {
                        println!("🌐 IPv6 decoys enabled");
                    }
                    EvasiveScannerWrapper::new_with_evasion_and_spoofing_verbose(
                        config,
                        evasion_config.clone(),
                        port_spoofing_config.clone(),
                        args.verbose,
                    )
                } else {
                    if args.verbose {
                        println!("🚀 Starting SYN scan...");
                    }
                    EvasiveScannerWrapper::new_verbose(config, args.verbose)
                };

                scanner.scan().await?;
                syn_scanner = Some(scanner);
                syn_scanner.as_ref().unwrap().get_results().clone()
            }
            ScanType::Connect => {
                if args.verbose {
                    println!("🚀 Starting TCP connect scan...");
                }
                let use_dynamic_ports = args.spoof_ports || args.source_port.is_none();
                let config = ScanConfig::new_with_rate_control(
                    *destination_ip,
                    ports_to_scan.clone(),
                    interface_ip,
                    args.timeout,
                    args.rate,
                    args.max_retries,
                    use_dynamic_ports,
                    args.source_port,
                    args.verbose,
                );
                let scanner = ConnectScanner::new(config, args.verbose);
                let (results, _) = scanner
                    .scan_tcp(*destination_ip, ports_to_scan.clone())
                    .await?;
                results
            }
            ScanType::Udp => {
                if args.verbose {
                    println!("🚀 Starting UDP scan...");
                }
                let use_dynamic_ports = args.spoof_ports || args.source_port.is_none();
                let config = ScanConfig::new_with_rate_control(
                    *destination_ip,
                    ports_to_scan.clone(),
                    interface_ip,
                    args.timeout,
                    args.rate,
                    args.max_retries,
                    use_dynamic_ports,
                    args.source_port,
                    args.verbose,
                );
                let mut scanner = UdpScanner::new(config);
                scanner.scan()?
            }
        };

        // Only show open ports by default, all results in verbose mode
        let open_results: Vec<_> = scan_results
            .iter()
            .filter(|r| matches!(r.status, PortStatus::Open))
            .collect();

        if !open_results.is_empty() {
            println!("Host {}:", destination_ip);
            for result in &open_results {
                println!("port {}: open", result.port);
            }
            println!(); // Add blank line after each host
        } else if args.verbose {
            println!("Host {}: No open ports found", destination_ip);
        }

        if args.verbose {
            println!(
                "\n=== Detailed Port Scan Results for {} ===",
                destination_ip
            );
            for result in &scan_results {
                println!("Port {}: {:?}", result.port, result.status);
            }
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
        if args.verbose {
            println!("🔌 Initializing plugin system...");
        }
        if args.verbose {
            println!("📝 Running script categories: {:?}", script_categories);
        }
        let mut plugin_manager = PluginManager::new_with_verbose(args.verbose);

        // Register plugins based on selected categories
        register_plugins_for_categories(&mut plugin_manager, &script_categories);

        // Configure plugin execution
        plugin_manager.set_execution_mode(ExecutionMode::Priority);

        // Run plugins against scan results
        if args.verbose {
            println!("\n🔍 Running security analysis plugins...");
        }
        let plugin_results = plugin_manager
            .execute_plugins_with_target(&scan_results, *destination_ip)
            .await;

        // Display plugin findings
        if args.verbose {
            println!("\n🎯 Security Analysis Results for {}:", destination_ip);
            println!("=====================================");
        }

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

        // Write output file if format is specified
        if let Some(ref writer) = output_writer {
            let scan_duration = scan_start.elapsed();
            match writer.write_scan_results(
                &destination_ip.to_string(),
                &scan_results,
                &plugin_results,
                scan_duration,
            ) {
                Ok(filepath) => {
                    println!("📄 Report written to: {}", filepath);
                }
                Err(e) => {
                    println!("⚠️  Failed to write report: {}", e);
                }
            }

            // Also print summary to console
            let session_data = output::ScanSession {
                session_id: format!("trident-{}", chrono::Local::now().timestamp()),
                timestamp: chrono::Local::now().to_rfc3339(),
                target_ip: destination_ip.to_string(),
                total_ports_scanned: scan_results.len(),
                open_ports: scan_results
                    .iter()
                    .filter(|r| matches!(r.status, PortStatus::Open))
                    .count(),
                filtered_ports: scan_results
                    .iter()
                    .filter(|r| {
                        matches!(
                            r.status,
                            PortStatus::Filtered
                                | PortStatus::OpenFiltered
                                | PortStatus::ClosedFiltered
                        )
                    })
                    .count(),
                closed_ports: scan_results
                    .iter()
                    .filter(|r| matches!(r.status, PortStatus::Closed))
                    .count(),
                scan_duration_ms: scan_duration.as_millis(),
                plugin_results: plugin_results.iter().map(|r| r.into()).collect(),
            };
            writer.print_summary(&session_data);
        }
    }

    if args.verbose {
        println!("\n🎉 Scan and analysis complete!");
    }
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
                plugin_manager.register_plugin(Arc::new(VulnDatabasePlugin::new()));
                plugin_manager.register_plugin(Arc::new(SqlInjectionScanner::new()));
                plugin_manager.register_plugin(Arc::new(CommandInjectionScanner::new()));
                plugin_manager.register_plugin(Arc::new(XssScanner::new()));
                plugin_manager.register_plugin(Arc::new(DirectoryTraversalScanner::new()));
            }
            ScriptCategory::Discovery => {
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(DatabaseDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(OsFingerprintPlugin::new()));
            }
            ScriptCategory::Default => {
                plugin_manager.register_plugin(Arc::new(VulnerabilityPlugin::new()));
                plugin_manager.register_plugin(Arc::new(VulnDatabasePlugin::new()));
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(DatabaseDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(OsFingerprintPlugin::new()));
                plugin_manager.register_plugin(Arc::new(DefaultAccountScanner::new()));
                plugin_manager.register_plugin(Arc::new(MisconfigurationScanner::new()));
                plugin_manager.register_plugin(Arc::new(PlaintextProtocolScanner::new()));
            }
            ScriptCategory::Safe => {
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(DatabaseDetectionPlugin::new()));
                // Only add safe vulnerability checks
                plugin_manager.register_plugin(Arc::new(MisconfigurationScanner::new()));
                plugin_manager.register_plugin(Arc::new(SecurityHeaderScanner::new()));
                plugin_manager.register_plugin(Arc::new(PlaintextProtocolScanner::new()));
            }
            ScriptCategory::Database => {
                plugin_manager.register_plugin(Arc::new(DatabaseDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(SqlInjectionScanner::new()));
                plugin_manager.register_plugin(Arc::new(WeakAuthScanner::new()));
                plugin_manager.register_plugin(Arc::new(DefaultCredsScanner::new()));
            }
            ScriptCategory::Auth => {
                plugin_manager.register_plugin(Arc::new(DefaultAccountScanner::new()));
                plugin_manager.register_plugin(Arc::new(WeakPasswordScanner::new()));
                plugin_manager.register_plugin(Arc::new(WeakAuthScanner::new()));
                plugin_manager.register_plugin(Arc::new(DefaultCredsScanner::new()));
            }
            ScriptCategory::Web => {
                plugin_manager.register_plugin(Arc::new(XssScanner::new()));
                plugin_manager.register_plugin(Arc::new(DirectoryTraversalScanner::new()));
                plugin_manager.register_plugin(Arc::new(SecurityHeaderScanner::new()));
            }
            ScriptCategory::Network => {
                plugin_manager.register_plugin(Arc::new(PlaintextProtocolScanner::new()));
                plugin_manager.register_plugin(Arc::new(WeakCipherScanner::new()));
                plugin_manager.register_plugin(Arc::new(WeakEncryptionScanner::new()));
                plugin_manager.register_plugin(Arc::new(CertificateScanner::new()));
            }
            ScriptCategory::Info => {
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(VulnDatabasePlugin::new()));
                plugin_manager.register_plugin(Arc::new(OsFingerprintPlugin::new()));
                plugin_manager.register_plugin(Arc::new(SecurityHeaderScanner::new()));
                plugin_manager.register_plugin(Arc::new(CertificateScanner::new()));
            }
            _ => {
                // For any other categories, register basic plugins
                plugin_manager.register_plugin(Arc::new(ServiceDetectionPlugin::new()));
                plugin_manager.register_plugin(Arc::new(VulnerabilityPlugin::new()));
                plugin_manager.register_plugin(Arc::new(DebugModeScanner::new()));
                plugin_manager.register_plugin(Arc::new(LdapInjectionScanner::new()));
                plugin_manager.register_plugin(Arc::new(NoSqlInjectionScanner::new()));
            }
        }
    }
}
