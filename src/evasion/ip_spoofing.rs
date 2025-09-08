use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP spoofing utilities for source port and address manipulation
pub struct IpSpoofer {
    /// Preferred source ports for spoofing (trusted ports)
    trusted_ports: Vec<u16>,
}

impl IpSpoofer {
    /// Create a new IP spoofer with default trusted ports
    pub fn new() -> Self {
        Self {
            trusted_ports: vec![53, 80, 443, 993, 995, 25, 110, 143],
        }
    }

    /// Create IP spoofer with custom trusted ports
    pub fn with_trusted_ports(ports: Vec<u16>) -> Self {
        Self {
            trusted_ports: ports,
        }
    }

    /// Generate a source port that might bypass filtering
    pub fn generate_trusted_source_port(&self) -> u16 {
        let mut rng = rand::rng();

        // 70% chance to use trusted port, 30% chance for high ephemeral port
        if rng.random_bool(0.7) && !self.trusted_ports.is_empty() {
            self.trusted_ports[rng.random_range(0..self.trusted_ports.len())]
        } else {
            // Use high ephemeral ports that some systems trust
            rng.random_range(49152..=65535)
        }
    }

    /// Generate source IP that appears to be from a different geographic region
    pub fn generate_geographic_decoy_ip(&self, region: GeographicRegion) -> IpAddr {
        let mut rng = rand::rng();

        match region {
            GeographicRegion::NorthAmerica => {
                // Common US/Canada IP ranges
                let ranges = [
                    (8, 8, 8, 0),      // Google DNS range
                    (1, 1, 1, 0),      // Cloudflare
                    (4, 4, 4, 0),      // Level3
                    (208, 67, 222, 0), // OpenDNS
                ];
                let base = ranges[rng.random_range(0..ranges.len())];
                IpAddr::V4(Ipv4Addr::new(
                    base.0,
                    base.1,
                    base.2,
                    rng.random_range(1..=254),
                ))
            }
            GeographicRegion::Europe => {
                // European IP ranges
                IpAddr::V4(Ipv4Addr::new(
                    rng.random_range(80..=95),
                    rng.random_range(1..=255),
                    rng.random_range(1..=255),
                    rng.random_range(1..=254),
                ))
            }
            GeographicRegion::Asia => {
                // Asian IP ranges
                IpAddr::V4(Ipv4Addr::new(
                    rng.random_range(110..=125),
                    rng.random_range(1..=255),
                    rng.random_range(1..=255),
                    rng.random_range(1..=254),
                ))
            }
            GeographicRegion::Random => {
                // Completely random but valid public IP
                loop {
                    let ip = Ipv4Addr::new(
                        rng.random_range(1..=223),
                        rng.random_range(0..=255),
                        rng.random_range(0..=255),
                        rng.random_range(1..=254),
                    );

                    if !self.is_private_or_reserved(&ip) {
                        return IpAddr::V4(ip);
                    }
                }
            }
        }
    }

    /// Generate IPv6 decoy IP addresses that appear to be from different geographic regions
    pub fn generate_geographic_decoy_ipv6(&self, region: GeographicRegion) -> IpAddr {
        let mut rng = rand::rng();

        match region {
            GeographicRegion::NorthAmerica => {
                // North American IPv6 ranges (simplified examples)
                let prefixes = [
                    0x2001, 0x2600, 0x2610, // Various North American allocations
                ];
                let prefix = prefixes[rng.random_range(0..prefixes.len())];

                IpAddr::V6(Ipv6Addr::new(
                    prefix,
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0001..=0xFFFE), // Avoid all zeros
                ))
            }
            GeographicRegion::Europe => {
                // European IPv6 ranges
                let prefixes = [
                    0x2001, 0x2a00, 0x2a01, 0x2a02, 0x2a03, // RIPE NCC allocations
                ];
                let prefix = prefixes[rng.random_range(0..prefixes.len())];

                IpAddr::V6(Ipv6Addr::new(
                    prefix,
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0001..=0xFFFE),
                ))
            }
            GeographicRegion::Asia => {
                // Asian IPv6 ranges
                let prefixes = [
                    0x2001, 0x2400, 0x2401, 0x240a, // APNIC allocations
                ];
                let prefix = prefixes[rng.random_range(0..prefixes.len())];

                IpAddr::V6(Ipv6Addr::new(
                    prefix,
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0001..=0xFFFE),
                ))
            }
            GeographicRegion::Random => {
                // Random global unicast IPv6 address in 2000::/3
                IpAddr::V6(Ipv6Addr::new(
                    rng.random_range(0x2000..=0x3FFF), // Global unicast range
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0000..=0xFFFF),
                    rng.random_range(0x0001..=0xFFFE),
                ))
            }
        }
    }

    /// Generate either IPv4 or IPv6 geographic decoy IP with specified probability
    pub fn generate_mixed_geographic_decoy(
        &self,
        region: GeographicRegion,
        ipv6_probability: f64,
    ) -> IpAddr {
        let mut rng = rand::rng();

        if rng.random_bool(ipv6_probability) {
            self.generate_geographic_decoy_ipv6(region)
        } else {
            self.generate_geographic_decoy_ip(region)
        }
    }

    /// Check if an IPv4 address is private or reserved
    fn is_private_or_reserved(&self, ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();

        match octets[0] {
            10 => true,                                    // 10.0.0.0/8
            127 => true,                                   // 127.0.0.0/8 (loopback)
            169 if octets[1] == 254 => true,               // 169.254.0.0/16 (link-local)
            172 if (16..=31).contains(&octets[1]) => true, // 172.16.0.0/12
            192 if octets[1] == 168 => true,               // 192.168.0.0/16
            224..=255 => true,                             // Multicast and reserved
            0 => true,                                     // 0.0.0.0/8
            _ => false,
        }
    }

    /// Create a spoofing configuration for port scanning
    pub fn create_spoofing_config(&self, target_port: u16) -> SpoofingConfig {
        let source_port = match target_port {
            // For common services, use related trusted ports
            80 | 8080 | 8000 => 443, // HTTPS to HTTP
            443 | 8443 => 80,        // HTTP to HTTPS
            25 => 587,               // SMTP variations
            53 => 5353,              // DNS variations
            _ => self.generate_trusted_source_port(),
        };

        SpoofingConfig {
            source_port,
            spoof_ttl: self.generate_realistic_ttl(),
            spoof_window_size: self.generate_realistic_window_size(),
            geographic_region: GeographicRegion::Random,
        }
    }

    /// Generate realistic TTL values that might match different OS types
    fn generate_realistic_ttl(&self) -> u8 {
        let mut rng = rand::rng();

        // Common OS TTL values
        let common_ttls = [64, 128, 255, 60, 30];
        common_ttls[rng.random_range(0..common_ttls.len())]
    }

    /// Generate realistic TCP window sizes
    fn generate_realistic_window_size(&self) -> u16 {
        let mut rng = rand::rng();

        // Common window sizes
        let common_windows = [1024, 2048, 4096, 8192, 16384, 32768, 65535];
        common_windows[rng.random_range(0..common_windows.len())]
    }
}

/// Geographic regions for IP spoofing
#[derive(Debug, Clone, Copy)]
pub enum GeographicRegion {
    NorthAmerica,
    Europe,
    Asia,
    Random,
}

/// Configuration for spoofing operations
#[derive(Debug, Clone)]
pub struct SpoofingConfig {
    pub source_port: u16,
    pub spoof_ttl: u8,
    pub spoof_window_size: u16,
    pub geographic_region: GeographicRegion,
}

impl Default for IpSpoofer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_port_generation() {
        let spoofer = IpSpoofer::new();

        for _ in 0..100 {
            let port = spoofer.generate_trusted_source_port();
            assert!(port > 0);
            assert!(port <= 65535);
        }
    }

    #[test]
    fn test_private_ip_detection() {
        let spoofer = IpSpoofer::new();

        assert!(spoofer.is_private_or_reserved(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(spoofer.is_private_or_reserved(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(spoofer.is_private_or_reserved(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(spoofer.is_private_or_reserved(&Ipv4Addr::new(127, 0, 0, 1)));

        assert!(!spoofer.is_private_or_reserved(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!spoofer.is_private_or_reserved(&Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_geographic_ip_generation() {
        let spoofer = IpSpoofer::new();

        // Test each region
        for region in [
            GeographicRegion::NorthAmerica,
            GeographicRegion::Europe,
            GeographicRegion::Asia,
            GeographicRegion::Random,
        ] {
            let ip = spoofer.generate_geographic_decoy_ip(region);

            match ip {
                IpAddr::V4(ipv4) => {
                    assert!(!spoofer.is_private_or_reserved(&ipv4));
                }
                IpAddr::V6(_) => {} // IPv6 handling would be added here
            }
        }
    }

    #[test]
    fn test_spoofing_config_creation() {
        let spoofer = IpSpoofer::new();

        let config = spoofer.create_spoofing_config(80);
        assert!(config.source_port > 0);
        assert!(config.spoof_ttl > 0);
        assert!(config.spoof_window_size > 0);
    }

    #[test]
    fn test_realistic_values() {
        let spoofer = IpSpoofer::new();

        // Test TTL generation
        for _ in 0..50 {
            let ttl = spoofer.generate_realistic_ttl();
            assert!(ttl > 0);
            assert!([30, 60, 64, 128, 255].contains(&ttl));
        }

        // Test window size generation
        for _ in 0..50 {
            let window = spoofer.generate_realistic_window_size();
            assert!(window > 0);
            assert!(window.is_power_of_two() || window == 65535);
        }
    }
}
