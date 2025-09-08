use rand::Rng;
use std::collections::HashMap;

/// Strategies for selecting spoofed source ports
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PortSpoofingStrategy {
    /// Use well-known trusted ports that are commonly allowed through firewalls
    TrustedPorts,
    /// Use high privilege ports (1-1024) to appear as system services
    HighPrivilege,
    /// Mix trusted ports with some randomization for noise
    TrustedWithNoise,
    /// Use ports that match the target service (HTTP->HTTP, HTTPS->HTTPS, etc.)
    ServiceMatching,
}

/// Configuration for port spoofing behavior
#[derive(Debug, Clone)]
pub struct PortSpoofingConfig {
    pub strategy: PortSpoofingStrategy,
    pub noise_probability: f32, // Probability of using random port instead of trusted (0.0-1.0)
    pub prefer_dns: bool,       // Prefer port 53 (DNS) as it's commonly allowed
    pub prefer_http: bool,      // Prefer ports 80/443 (HTTP/HTTPS)
    pub avoid_ephemeral: bool,  // Avoid ephemeral port range (32768-65535)
}

impl Default for PortSpoofingConfig {
    fn default() -> Self {
        Self {
            strategy: PortSpoofingStrategy::TrustedPorts,
            noise_probability: 0.1, // 10% noise
            prefer_dns: true,
            prefer_http: true,
            avoid_ephemeral: true,
        }
    }
}

/// Port spoofing engine that provides strategic source port selection
pub struct PortSpoofer {
    config: PortSpoofingConfig,
    trusted_ports: Vec<u16>,
    service_port_map: HashMap<u16, Vec<u16>>, // target_port -> preferred_source_ports
    usage_stats: HashMap<u16, u32>,           // Track port usage for rotation
}

impl PortSpoofer {
    /// Create a new port spoofing engine
    pub fn new(config: PortSpoofingConfig) -> Self {
        let mut spoofer = Self {
            config,
            trusted_ports: Vec::new(),
            service_port_map: HashMap::new(),
            usage_stats: HashMap::new(),
        };

        spoofer.initialize_trusted_ports();
        spoofer.initialize_service_mappings();
        spoofer
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(PortSpoofingConfig::default())
    }

    /// Initialize the list of trusted ports based on configuration
    fn initialize_trusted_ports(&mut self) {
        let mut ports = Vec::new();

        // Core trusted ports that are commonly allowed
        if self.config.prefer_dns {
            ports.push(53); // DNS - most commonly allowed
        }

        if self.config.prefer_http {
            ports.push(80); // HTTP
            ports.push(443); // HTTPS
        }

        // Other commonly trusted ports
        ports.extend_from_slice(&[
            25,  // SMTP
            110, // POP3
            143, // IMAP
            993, // IMAPS
            995, // POP3S
            22,  // SSH (often allowed outbound)
            21,  // FTP
            23,  // Telnet
            123, // NTP
            161, // SNMP
            389, // LDAP
            636, // LDAPS
        ]);

        // Add high privilege ports if strategy requires it
        if matches!(self.config.strategy, PortSpoofingStrategy::HighPrivilege) {
            // Add system service ports (1-1024)
            for port in [
                1, 7, 9, 13, 17, 19, 20, 37, 42, 49, 50, 79, 87, 88, 135, 139, 445, 514, 515, 543,
                544, 548, 631, 749, 750, 873,
            ] {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }

        self.trusted_ports = ports;
    }

    /// Initialize service-to-port mappings for intelligent spoofing
    fn initialize_service_mappings(&mut self) {
        let mut mappings = HashMap::new();

        // Web services - use web-related source ports
        mappings.insert(80, vec![80, 443, 8080, 8443]);
        mappings.insert(443, vec![443, 80, 8443, 8080]);
        mappings.insert(8080, vec![80, 8080, 443]);
        mappings.insert(8443, vec![443, 8443, 80]);

        // Mail services - use mail-related source ports
        mappings.insert(25, vec![25, 587, 465]);
        mappings.insert(110, vec![110, 995, 143]);
        mappings.insert(143, vec![143, 993, 110]);
        mappings.insert(993, vec![993, 143, 995]);
        mappings.insert(995, vec![995, 110, 993]);

        // DNS - use DNS or web ports
        mappings.insert(53, vec![53, 80, 443]);

        // SSH - use SSH or other administrative ports
        mappings.insert(22, vec![22, 80, 443, 23]);

        // Database ports - use web or administrative ports
        mappings.insert(3306, vec![80, 443, 53]); // MySQL
        mappings.insert(5432, vec![80, 443, 53]); // PostgreSQL
        mappings.insert(1521, vec![80, 443, 53]); // Oracle
        mappings.insert(1433, vec![80, 443, 53]); // SQL Server

        self.service_port_map = mappings;
    }

    /// Get a spoofed source port for scanning the given target port
    pub fn get_spoofed_source_port(&mut self, target_port: u16) -> u16 {
        match self.config.strategy {
            PortSpoofingStrategy::TrustedPorts => self.get_trusted_port(),
            PortSpoofingStrategy::HighPrivilege => self.get_high_privilege_port(),
            PortSpoofingStrategy::TrustedWithNoise => self.get_trusted_with_noise(),
            PortSpoofingStrategy::ServiceMatching => self.get_service_matching_port(target_port),
        }
    }

    /// Select a trusted port, rotating through options to avoid patterns
    fn get_trusted_port(&mut self) -> u16 {
        if self.trusted_ports.is_empty() {
            return 53; // Fallback to DNS
        }

        // Find least used port for rotation
        let port = self
            .trusted_ports
            .iter()
            .min_by_key(|&&port| self.usage_stats.get(&port).unwrap_or(&0))
            .copied()
            .unwrap_or(self.trusted_ports[0]);

        self.increment_usage(port);
        port
    }

    /// Select from high privilege port range
    fn get_high_privilege_port(&mut self) -> u16 {
        let mut rng = rand::rng();

        // 70% chance of using a well-known trusted port
        if rng.random_bool(0.7) {
            self.get_trusted_port()
        } else {
            // 30% chance of using other system ports
            let system_ports = [1, 7, 9, 13, 17, 19, 20, 37, 42, 49, 50, 79, 87, 88];
            let port = system_ports[rng.random_range(0..system_ports.len())];
            self.increment_usage(port);
            port
        }
    }

    /// Mix trusted ports with occasional noise
    fn get_trusted_with_noise(&mut self) -> u16 {
        let mut rng = rand::rng();

        if rng.random::<f32>() < self.config.noise_probability {
            // Generate noise - random port that's not ephemeral
            let port = if self.config.avoid_ephemeral {
                rng.random_range(1024..32768)
            } else {
                rng.random_range(1..65535)
            };
            self.increment_usage(port);
            port
        } else {
            self.get_trusted_port()
        }
    }

    /// Select source port based on target service
    fn get_service_matching_port(&mut self, target_port: u16) -> u16 {
        if let Some(preferred_ports) = self.service_port_map.get(&target_port) {
            // Find least used port from the preferred list
            let port = preferred_ports
                .iter()
                .min_by_key(|&&port| self.usage_stats.get(&port).unwrap_or(&0))
                .copied()
                .unwrap_or(preferred_ports[0]);

            self.increment_usage(port);
            port
        } else {
            // Fallback to trusted port strategy
            self.get_trusted_port()
        }
    }

    /// Track port usage for rotation algorithms
    fn increment_usage(&mut self, port: u16) {
        *self.usage_stats.entry(port).or_insert(0) += 1;
    }

    /// Reset usage statistics (useful for long-running scans)
    pub fn reset_usage_stats(&mut self) {
        self.usage_stats.clear();
    }

    /// Get current configuration
    pub fn get_config(&self) -> &PortSpoofingConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: PortSpoofingConfig) {
        self.config = config;
        self.initialize_trusted_ports();
        self.initialize_service_mappings();
    }

    /// Get statistics about port usage
    pub fn get_usage_stats(&self) -> &HashMap<u16, u32> {
        &self.usage_stats
    }

    /// Get the list of trusted ports being used
    pub fn get_trusted_ports(&self) -> &Vec<u16> {
        &self.trusted_ports
    }

    /// Suggest a source port that would be most effective for the given target
    pub fn suggest_optimal_port(&self, target_port: u16) -> u16 {
        // This provides advice without modifying state
        match target_port {
            80 | 8080 => 80,      // HTTP traffic should come from HTTP port
            443 | 8443 => 443,    // HTTPS traffic should come from HTTPS port
            53 => 53,             // DNS queries from DNS port
            25 | 587 | 465 => 25, // Mail traffic from SMTP port
            22 => 80,             // SSH often blocked, but HTTP might get through
            _ => 53,              // Default to DNS - most universally allowed
        }
    }
}

/// Helper functions for integration with scanner components
impl PortSpoofer {
    /// Check if a port is considered "trusted" by common firewall rules
    pub fn is_trusted_port(port: u16) -> bool {
        matches!(
            port,
            53 | 80 | 443 | 25 | 110 | 143 | 993 | 995 | 22 | 21 | 23 | 123
        )
    }

    /// Get the service name for a port (for logging/debugging)
    pub fn get_service_name(port: u16) -> &'static str {
        match port {
            53 => "DNS",
            80 => "HTTP",
            443 => "HTTPS",
            25 => "SMTP",
            110 => "POP3",
            143 => "IMAP",
            993 => "IMAPS",
            995 => "POP3S",
            22 => "SSH",
            21 => "FTP",
            23 => "Telnet",
            123 => "NTP",
            _ => "Unknown",
        }
    }

    /// Create a spoofing configuration optimized for firewall bypass
    pub fn firewall_bypass_config() -> PortSpoofingConfig {
        PortSpoofingConfig {
            strategy: PortSpoofingStrategy::TrustedPorts,
            noise_probability: 0.05, // Low noise to avoid detection
            prefer_dns: true,        // DNS is almost always allowed
            prefer_http: true,       // HTTP/HTTPS commonly allowed
            avoid_ephemeral: true,   // Avoid suspicious high ports
        }
    }

    /// Create a spoofing configuration optimized for appearing legitimate
    pub fn legitimate_traffic_config() -> PortSpoofingConfig {
        PortSpoofingConfig {
            strategy: PortSpoofingStrategy::ServiceMatching,
            noise_probability: 0.0, // No noise - pure legitimate appearance
            prefer_dns: true,
            prefer_http: true,
            avoid_ephemeral: true,
        }
    }

    /// Create a spoofing configuration optimized for creating scanning noise
    pub fn scanning_noise_config() -> PortSpoofingConfig {
        PortSpoofingConfig {
            strategy: PortSpoofingStrategy::TrustedWithNoise,
            noise_probability: 0.3, // Higher noise for obfuscation
            prefer_dns: false,      // Less predictable
            prefer_http: false,
            avoid_ephemeral: false, // Use full port range
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_spoofer_creation() {
        let config = PortSpoofingConfig::default();
        let spoofer = PortSpoofer::new(config);

        assert!(!spoofer.trusted_ports.is_empty());
        assert!(spoofer.trusted_ports.contains(&53)); // DNS should be included
        assert!(spoofer.trusted_ports.contains(&80)); // HTTP should be included
        assert!(spoofer.trusted_ports.contains(&443)); // HTTPS should be included
    }

    #[test]
    fn test_trusted_port_selection() {
        let mut spoofer = PortSpoofer::default();

        let port1 = spoofer.get_spoofed_source_port(80);
        let port2 = spoofer.get_spoofed_source_port(443);

        assert!(PortSpoofer::is_trusted_port(port1));
        assert!(PortSpoofer::is_trusted_port(port2));
    }

    #[test]
    fn test_service_matching_strategy() {
        let config = PortSpoofingConfig {
            strategy: PortSpoofingStrategy::ServiceMatching,
            ..Default::default()
        };
        let mut spoofer = PortSpoofer::new(config);

        // HTTP target should prefer HTTP-related source ports
        let source_port = spoofer.get_spoofed_source_port(80);
        assert!(matches!(source_port, 80 | 443 | 8080 | 8443));

        // HTTPS target should prefer HTTPS-related source ports
        let source_port = spoofer.get_spoofed_source_port(443);
        assert!(matches!(source_port, 443 | 80 | 8443 | 8080));
    }

    #[test]
    fn test_port_rotation() {
        let mut spoofer = PortSpoofer::default();

        // Generate several ports and ensure we get rotation
        let mut ports_used = std::collections::HashSet::new();
        for _ in 0..20 {
            let port = spoofer.get_spoofed_source_port(80);
            ports_used.insert(port);
        }

        // Should use multiple different ports for rotation
        assert!(ports_used.len() > 1);
    }

    #[test]
    fn test_preset_configurations() {
        let firewall_config = PortSpoofer::firewall_bypass_config();
        assert!(firewall_config.prefer_dns);
        assert!(firewall_config.avoid_ephemeral);
        assert!(firewall_config.noise_probability < 0.1);

        let legitimate_config = PortSpoofer::legitimate_traffic_config();
        assert_eq!(
            legitimate_config.strategy,
            PortSpoofingStrategy::ServiceMatching
        );
        assert_eq!(legitimate_config.noise_probability, 0.0);

        let noise_config = PortSpoofer::scanning_noise_config();
        assert!(noise_config.noise_probability > 0.2);
    }

    #[test]
    fn test_service_name_lookup() {
        assert_eq!(PortSpoofer::get_service_name(53), "DNS");
        assert_eq!(PortSpoofer::get_service_name(80), "HTTP");
        assert_eq!(PortSpoofer::get_service_name(443), "HTTPS");
        assert_eq!(PortSpoofer::get_service_name(9999), "Unknown");
    }

    #[test]
    fn test_optimal_port_suggestions() {
        let spoofer = PortSpoofer::default();

        assert_eq!(spoofer.suggest_optimal_port(80), 80);
        assert_eq!(spoofer.suggest_optimal_port(443), 443);
        assert_eq!(spoofer.suggest_optimal_port(53), 53);
        assert_eq!(spoofer.suggest_optimal_port(22), 80); // SSH -> HTTP bypass
        assert_eq!(spoofer.suggest_optimal_port(9999), 53); // Unknown -> DNS
    }
}
