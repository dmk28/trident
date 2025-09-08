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

#[derive(Parser, Debug)]
#[command(name = "project_trident")]
#[command(about = "A comprehensive network scanner and vulnerability detector")]
#[command(version = "1.0")]
struct Args {
    /// Network interface to use for scanning
    interface: String,

    /// Target IP address or hostname to scan
    target: String,

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.script_help {
        print_script_help();
        return Ok(());
    }

    let interface_name = args.interface.clone();
    let destination_ip = match args.target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            println!(
                "🔍 Could not parse '{}' as IP address, attempting DNS resolution...",
                args.target
            );
            match resolve_ip(&args.target).await {
                Ok(ip) => {
                    println!("✅ Resolved '{}' to {}", args.target, ip);
                    ip
                }
                Err(e) => {
                    println!("❌ Error resolving hostname '{}': {}", args.target, e);
                    std::process::exit(1);
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

    let interface_ip = get_interface_ip_from_name(&interface_name)?;

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

    let mut syn_scanner = None;
    let scan_results = match args.scan_type {
        ScanType::Syn => {
            // Create evasive scanner wrapper
            let config = ScanConfig::new(
                destination_ip,
                ports_to_scan.clone(),
                interface_ip,
                args.timeout,
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
                    port_spoofing_config,
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
            let config = ScanConfig::new(
                destination_ip,
                ports_to_scan.clone(),
                interface_ip,
                args.timeout,
            );
            let scanner = ConnectScanner::new(config);
            let (results, _) = scanner
                .scan_tcp(destination_ip, ports_to_scan.clone())
                .await?;
            results
        }
        ScanType::Udp => {
            println!("🚀 Starting UDP scan...");
            let config = ScanConfig::new(
                destination_ip,
                ports_to_scan.clone(),
                interface_ip,
                args.timeout,
            );
            let mut scanner = UdpScanner::new(config);
            scanner.scan()?
        }
    };

    println!("\n=== Port Scan Results ===");
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

    // Determine which script categories to run
    let script_categories = determine_script_categories(&args);

    if script_categories.is_empty() {
        println!(
            "\n⚠️  No scripts selected. Use --script to specify categories or --script-help for options."
        );
        return Ok(());
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
        .execute_plugins_with_target(&scan_results, destination_ip)
        .await;

    // Display plugin findings
    println!("\n🎯 Security Analysis Results:");
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
            "\n📊 Found {} security findings across {} services",
            total_findings,
            plugin_results.len()
        );
    } else {
        println!("\n✅ No security issues detected by plugins");
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
