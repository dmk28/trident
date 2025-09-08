use super::{detect_service, get_essential_probes};
use crate::domain_resolver::resolve_ip;
use std::io::{self, Write};
use std::net::IpAddr;

pub async fn test_comprehensive_service_detection() {
    println!("🚀 Project Trident - Comprehensive Service Detection Test\n");

    // Load essential service probes
    let probes = match get_essential_probes() {
        Ok(probes) => {
            println!("📋 Loaded {} essential service probes:", probes.len());
            for probe in &probes {
                println!(
                    "   - {} (default ports: {:?})",
                    probe.name, probe.default_ports
                );
            }
            println!();
            probes
        }
        Err(e) => {
            println!("❌ Failed to load service probes: {}", e);
            return;
        }
    };

    // Test targets - educational and common servers
    let test_targets = vec![
        ("DESEC Training Target", "businesscorp.com.br"),
        ("GitHub", "github.com"),
        ("Google", "google.com"),
    ];

    for (name, hostname) in test_targets {
        println!("🎯 === Testing {} ({}) ===", name, hostname);

        // First resolve the hostname to IP
        let ip = match resolve_ip(hostname).await {
            Ok(ip) => {
                println!("   🌐 Resolved {} → {}", hostname, ip);
                ip
            }
            Err(e) => {
                println!("   ❌ DNS resolution failed for {}: {:?}", hostname, e);
                println!();
                continue;
            }
        };

        // Test common ports for services
        let common_ports = vec![
            21,   // FTP
            22,   // SSH
            23,   // Telnet
            25,   // SMTP
            53,   // DNS
            80,   // HTTP
            110,  // POP3
            143,  // IMAP
            443,  // HTTPS
            993,  // IMAPS
            995,  // POP3S
            3306, // MySQL
            5432, // PostgreSQL
        ];

        println!(
            "   🔍 Scanning {} common service ports...",
            common_ports.len()
        );
        println!();

        let mut services_found = 0;
        let mut total_attempts = 0;

        for &port in &common_ports {
            total_attempts += 1;

            // Show progress
            print!(
                "   [{}] Port {:<4}: ",
                format!("{}/{}", total_attempts, common_ports.len()),
                port
            );
            io::stdout().flush().unwrap();

            match detect_service(ip, port, &probes).await {
                Ok(service_info) => {
                    services_found += 1;

                    let service_name = service_info.name.unwrap_or("Unknown".to_string());
                    let version = service_info
                        .version
                        .unwrap_or("No version info".to_string());
                    let confidence = service_info.confidence.unwrap_or(0.0);

                    println!(
                        "✅ {} v{} (confidence: {:.1})",
                        service_name, version, confidence
                    );

                    // Show banner preview if available
                    if let Some(banner) = &service_info.raw_banner {
                        let preview = if banner.len() > 80 {
                            format!("{}...", &banner[..77])
                        } else {
                            banner.clone()
                        };
                        println!("      📄 Banner: {}", preview.trim().replace('\n', " "));
                    }
                }
                Err(_) => {
                    println!("❌ No service detected / Port closed");
                }
            }
        }

        println!();
        println!("   📊 Summary for {}:", hostname);
        println!(
            "      🎯 Services Found: {}/{}",
            services_found, total_attempts
        );
        println!(
            "      📈 Detection Rate: {:.1}%",
            (services_found as f32 / total_attempts as f32) * 100.0
        );
        println!("   {}", "─".repeat(60));
        println!();
    }

    println!("✨ Comprehensive service detection test complete!");
    println!("💡 This demonstrates your scanner's ability to automatically");
    println!("   identify services without prior knowledge of what's running!");
}

pub async fn test_businesscorp_focused() {
    println!("🎯 DESEC Training Target - Focused Service Detection\n");

    let hostname = "businesscorp.com.br";

    // Load all probes for thorough testing
    let probes = match get_essential_probes() {
        Ok(probes) => probes,
        Err(e) => {
            println!("❌ Failed to load service probes: {}", e);
            return;
        }
    };

    println!("🌐 Resolving {}...", hostname);
    let ip = match resolve_ip(hostname).await {
        Ok(ip) => {
            println!("✅ Resolved {} → {}", hostname, ip);
            ip
        }
        Err(e) => {
            println!("❌ DNS resolution failed: {:?}", e);
            return;
        }
    };

    println!("\n🔍 Starting comprehensive service detection scan...\n");

    // Extended port range for educational target
    let extended_ports = vec![
        20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432,
        8080, 8443,
    ];

    let mut detected_services = Vec::new();

    for (i, &port) in extended_ports.iter().enumerate() {
        print!(
            "[{:2}/{:2}] Scanning port {:<4}... ",
            i + 1,
            extended_ports.len(),
            port
        );
        io::stdout().flush().unwrap();

        match detect_service(ip, port, &probes).await {
            Ok(service_info) => {
                let service_name = service_info.name.clone().unwrap_or("Unknown".to_string());
                println!("✅ {}", service_name);
                detected_services.push((port, service_info));
            }
            Err(_) => {
                println!("❌");
            }
        }
    }

    println!("\n📊 === SCAN RESULTS for {} ===", hostname);
    println!("IP Address: {}", ip);
    println!("Services Detected: {}", detected_services.len());
    println!();

    if detected_services.is_empty() {
        println!("🔒 No services detected - target may be heavily filtered");
        println!("💡 This could mean:");
        println!("   - Firewall blocking connections");
        println!("   - Services running on non-standard ports");
        println!("   - Rate limiting preventing detection");
    } else {
        for (port, service_info) in detected_services {
            println!(
                "🎯 Port {}: {} {}",
                port,
                service_info.name.unwrap_or("Unknown".to_string()),
                service_info.version.unwrap_or("".to_string())
            );

            if let Some(banner) = &service_info.raw_banner {
                let clean_banner = banner.replace('\r', "").replace('\n', " ");
                if clean_banner.len() > 100 {
                    println!("   Banner: {}...", &clean_banner[..97]);
                } else {
                    println!("   Banner: {}", clean_banner);
                }
            }
            println!();
        }
    }

    println!("🏁 Educational scan complete!");
}
