pub mod decoy_generator;
pub mod ip_spoofing;
pub mod port_spoofing;

pub use decoy_generator::*;
pub use ip_spoofing::*;
pub use port_spoofing::*;

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Configuration for evasion techniques
#[derive(Debug, Clone)]
pub struct EvasionConfig {
    /// Number of decoy IPs to generate
    pub decoy_count: usize,
    /// Whether to use IPv6 decoys
    pub use_ipv6: bool,
    /// Custom source port for spoofing (None = random)
    pub source_port: Option<u16>,
    /// Delay between decoy packets (microseconds)
    pub decoy_delay_us: u64,
    /// Whether to randomize packet order
    pub randomize_order: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            decoy_count: 5,
            use_ipv6: false,
            source_port: None,
            decoy_delay_us: 100,
            randomize_order: true,
        }
    }
}

/// Result of evasion operations
#[derive(Debug)]
pub struct EvasionResult {
    pub real_scan_sent: bool,
    pub decoys_sent: usize,
    pub errors: Vec<String>,
}

/// Main evasion engine that coordinates decoy generation and spoofing
pub struct EvasionEngine {
    config: EvasionConfig,
    decoy_generator: DecoyGenerator,
}

impl EvasionEngine {
    pub fn new(config: EvasionConfig) -> Self {
        Self {
            decoy_generator: DecoyGenerator::new(),
            config,
        }
    }

    /// Generate random IPv4 address avoiding reserved ranges
    pub fn generate_random_ipv4() -> Ipv4Addr {
        let mut rng = rand::thread_rng();

        loop {
            let a = rng.gen_range(1..=223); // Avoid 0.x.x.x and 224+ (multicast)
            let b = rng.gen_range(0..=255);
            let c = rng.gen_range(0..=255);
            let d = rng.gen_range(1..=254); // Avoid .0 and .255

            let ip = Ipv4Addr::new(a, b, c, d);

            // Skip reserved ranges
            if Self::is_reserved_ipv4(&ip) {
                continue;
            }

            return ip;
        }
    }

    /// Generate random IPv6 address in global unicast range
    pub fn generate_random_ipv6() -> Ipv6Addr {
        let mut rng = rand::thread_rng();

        // Generate in 2000::/3 global unicast range
        let segments: [u16; 8] = [
            rng.gen_range(0x2000..=0x3fff), // First segment in global unicast
            rng.r#gen::<u16>(),
            rng.r#gen::<u16>(),
            rng.r#gen::<u16>(),
            rng.r#gen::<u16>(),
            rng.r#gen::<u16>(),
            rng.r#gen::<u16>(),
            rng.gen_range(1..=0xfffe), // Avoid all zeros in last segment
        ];

        Ipv6Addr::from(segments)
    }

    /// Check if IPv4 address is in reserved range
    fn is_reserved_ipv4(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();

        match octets[0] {
            10 => true,                                        // Private 10.0.0.0/8
            127 => true,                                       // Loopback 127.0.0.0/8
            169 if octets[1] == 254 => true,                   // Link-local 169.254.0.0/16
            172 if octets[1] >= 16 && octets[1] <= 31 => true, // Private 172.16.0.0/12
            192 if octets[1] == 168 => true,                   // Private 192.168.0.0/16
            224..=255 => true,                                 // Multicast and reserved
            _ => false,
        }
    }

    /// Generate a list of decoy IP addresses
    pub fn generate_decoys(&self) -> Vec<IpAddr> {
        let mut decoys = Vec::with_capacity(self.config.decoy_count);

        for _ in 0..self.config.decoy_count {
            let ip = if self.config.use_ipv6 && rand::thread_rng().gen_bool(0.3) {
                IpAddr::V6(Self::generate_random_ipv6())
            } else {
                IpAddr::V4(Self::generate_random_ipv4())
            };
            decoys.push(ip);
        }

        decoys
    }

    pub async fn execute_decoy_scan(
        &mut self,
        real_source: IpAddr,
        target: IpAddr,
        target_port: u16,
        scan_type: ScanType,
    ) -> Result<EvasionResult, Box<dyn std::error::Error>> {
        if !self.decoy_generator.is_available() {
            return Ok(EvasionResult {
                real_scan_sent: false,
                decoys_sent: 0,
                errors: vec![
                    "Raw socket capabilities not available. Run with sudo for full functionality."
                        .to_string(),
                ],
            });
        }

        let decoys = self.generate_decoys();

        if decoys.is_empty() {
            return Ok(EvasionResult {
                real_scan_sent: false,
                decoys_sent: 0,
                errors: vec!["No decoys generated".to_string()],
            });
        }

        match self
            .decoy_generator
            .send_decoy_scan(real_source, target, target_port, decoys, scan_type)
            .await
        {
            Ok(packets_sent) => Ok(EvasionResult {
                real_scan_sent: true,
                decoys_sent: packets_sent.saturating_sub(1),
                errors: vec![],
            }),
            Err(e) => Ok(EvasionResult {
                real_scan_sent: false,
                decoys_sent: 0,
                errors: vec![format!("Failed to send decoy scan: {}", e)],
            }),
        }
    }

    pub fn has_raw_socket_capability(&self) -> bool {
        self.decoy_generator.is_available()
    }

    pub fn capabilities_info(&self) -> String {
        self.decoy_generator.capabilities().to_string()
    }

    /// Generate random source port, avoiding reserved ranges
    pub fn generate_source_port() -> u16 {
        let mut rng = rand::thread_rng();

        // Prefer ephemeral port range (32768-65535) but occasionally use "trusted" ports
        if rng.gen_bool(0.8) {
            rng.gen_range(32768..=65535)
        } else {
            // Use commonly trusted ports
            let trusted_ports = [53, 80, 443, 993, 995];
            trusted_ports[rng.gen_range(0..trusted_ports.len())]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_ipv4() {
        for _ in 0..100 {
            let ip = EvasionEngine::generate_random_ipv4();
            assert!(!EvasionEngine::is_reserved_ipv4(&ip));
            assert_ne!(ip.octets()[0], 0);
            assert_ne!(ip.octets()[3], 0);
            assert_ne!(ip.octets()[3], 255);
        }
    }

    #[test]
    fn test_generate_decoys() {
        let config = EvasionConfig::default();
        let engine = EvasionEngine::new(config);
        let decoys = engine.generate_decoys();

        assert_eq!(decoys.len(), 5);

        // Ensure we got unique IPs (mostly)
        let unique_count = decoys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique_count >= 4); // Allow for small chance of duplicates
    }

    #[test]
    fn test_reserved_ip_detection() {
        assert!(EvasionEngine::is_reserved_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(EvasionEngine::is_reserved_ipv4(&Ipv4Addr::new(
            127, 0, 0, 1
        )));
        assert!(EvasionEngine::is_reserved_ipv4(&Ipv4Addr::new(
            192, 168, 1, 1
        )));
        assert!(EvasionEngine::is_reserved_ipv4(&Ipv4Addr::new(
            172, 16, 0, 1
        )));

        assert!(!EvasionEngine::is_reserved_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!EvasionEngine::is_reserved_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_source_port_generation() {
        let mut trusted_count = 0;
        let mut ephemeral_count = 0;

        for _ in 0..1000 {
            let port = EvasionEngine::generate_source_port();
            if [53, 80, 443, 993, 995].contains(&port) {
                trusted_count += 1;
            } else {
                assert!(port >= 32768);
                ephemeral_count += 1;
            }
        }

        // Should be roughly 80% ephemeral, 20% trusted
        assert!(ephemeral_count > trusted_count);
        assert!(trusted_count > 0); // Should have some trusted ports
    }
}
