use super::{grab_ftp_banner, grab_ssh_banner};
use std::net::IpAddr;

pub async fn test_banners() {
    println!("🔍 Testing Banner Grabbing Functions\n");

    // Test SSH servers
    println!("=== SSH Banner Testing ===");
    let ssh_targets = vec![
        ("GitHub", "140.82.112.4", 22),
        ("Localhost", "127.0.0.1", 22),
    ];

    for (name, ip_str, port) in ssh_targets {
        println!("Testing SSH {}:{}...", name, port);
        match ip_str.parse::<IpAddr>() {
            Ok(ip) => match grab_ssh_banner(ip, port).await {
                Ok(banner) => println!("  ✅ SSH {}: {}", name, banner.trim()),
                Err(e) => println!("  ❌ SSH {} failed: {:?}", name, e),
            },
            Err(e) => println!("  ❌ Invalid IP {}: {}", ip_str, e),
        }
        println!();
    }

    // Test FTP servers
    println!("=== FTP Banner Testing ===");
    let ftp_targets = vec![
        ("GNU FTP", "ftp.gnu.org", 21),
        ("Debian FTP", "ftp.debian.org", 21),
        ("Localhost", "127.0.0.1", 21),
    ];

    for (name, hostname, port) in ftp_targets {
        println!("Testing FTP {}:{}...", name, port);

        // For hostnames, we'd need DNS resolution, so let's test with IPs
        match hostname {
            "127.0.0.1" => match hostname.parse::<IpAddr>() {
                Ok(ip) => match grab_ftp_banner(ip, port).await {
                    Ok(banner) => println!("  ✅ FTP {}: {}", name, banner.trim()),
                    Err(e) => println!("  ❌ FTP {} failed: {:?}", name, e),
                },
                Err(e) => println!("  ❌ Invalid IP {}: {}", hostname, e),
            },
            _ => println!("  ⚠️  FTP {} skipped (hostname resolution needed)", name),
        }
        println!();
    }
}
