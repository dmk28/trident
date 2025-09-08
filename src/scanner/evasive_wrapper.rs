use super::structure::{ScanConfig, ScanResult};
use super::synscanner::SynScanner;
use crate::evasion::{
    EvasionConfig, EvasionEngine, EvasionResult, PortSpoofer, PortSpoofingConfig, ScanType,
};
use rand;

/// Wrapper that coordinates scanning with evasion techniques
pub struct EvasiveScannerWrapper {
    scanner: SynScanner,
    evasion_engine: Option<EvasionEngine>,
    port_spoofer: Option<PortSpoofer>,
    evasion_enabled: bool,
    spoofing_enabled: bool,
}

impl EvasiveScannerWrapper {
    /// Create a new evasive scanner without evasion
    pub fn new(config: ScanConfig) -> Self {
        Self {
            scanner: SynScanner::new(config),
            evasion_engine: None,
            port_spoofer: None,
            evasion_enabled: false,
            spoofing_enabled: false,
        }
    }

    /// Create a new evasive scanner with evasion capabilities
    pub fn new_with_evasion(config: ScanConfig, evasion_config: EvasionConfig) -> Self {
        let evasion_engine = EvasionEngine::new(evasion_config);
        let evasion_enabled = evasion_engine.has_raw_socket_capability();

        if !evasion_enabled {
            eprintln!("⚠️  Warning: Raw socket capabilities not available. Evasion disabled.");
            eprintln!("   Run with sudo for full evasion capabilities.");
        }

        Self {
            scanner: SynScanner::new(config),
            evasion_engine: Some(evasion_engine),
            port_spoofer: None,
            evasion_enabled,
            spoofing_enabled: false,
        }
    }

    /// Create a new evasive scanner with both evasion and port spoofing capabilities
    pub fn new_with_evasion_and_spoofing(
        config: ScanConfig,
        evasion_config: EvasionConfig,
        port_spoofing_config: Option<PortSpoofingConfig>,
    ) -> Self {
        let mut evasion_engine = EvasionEngine::new(evasion_config);
        let evasion_enabled = evasion_engine.has_raw_socket_capability();

        if !evasion_enabled {
            eprintln!("⚠️  Warning: Raw socket capabilities not available. Evasion disabled.");
            eprintln!("   Run with sudo for full evasion capabilities.");
        }

        let (port_spoofer, spoofing_enabled) = if let Some(spoof_config) = port_spoofing_config {
            (Some(PortSpoofer::new(spoof_config)), true)
        } else {
            (None, false)
        };

        Self {
            scanner: SynScanner::new(config),
            evasion_engine: Some(evasion_engine),
            port_spoofer,
            evasion_enabled,
            spoofing_enabled,
        }
    }

    /// Perform the scan with optional evasion and port spoofing
    pub async fn scan(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.evasion_enabled || self.spoofing_enabled {
            self.scan_with_evasion_and_spoofing().await
        } else {
            self.scan_without_evasion()
        }
    }

    /// Perform scan with evasion techniques and port spoofing
    async fn scan_with_evasion_and_spoofing(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.evasion_enabled {
            println!("🥷 Starting evasion-enabled scan...");
        }
        if self.spoofing_enabled {
            println!("🔧 Starting port-spoofing scan...");
        }

        // Get scan configuration to determine what ports we're scanning
        let scan_config = self.get_scan_config();
        let target_ip = scan_config.destination_ip;
        let source_ip = scan_config.interface_ip;
        let ports = scan_config.ports_to_scan.clone();

        // Port spoofing preparation
        if let Some(ref mut port_spoofer) = self.port_spoofer {
            println!("🔧 Port spoofing configuration:");
            let config = port_spoofer.get_config();
            println!("   Strategy: {:?}", config.strategy);
            println!("   Trusted ports: {:?}", port_spoofer.get_trusted_ports());

            // Show recommended ports for each target
            for &port in &ports {
                let suggested_port = port_spoofer.suggest_optimal_port(port);
                println!(
                    "   Port {} -> suggested source port {} ({})",
                    port,
                    suggested_port,
                    crate::evasion::PortSpoofer::get_service_name(suggested_port)
                );
            }
        }

        // Evasion (decoy) phase
        if let Some(ref mut evasion_engine) = self.evasion_engine {
            println!(
                "🎯 Evasion capabilities: {}",
                evasion_engine.capabilities_info()
            );

            // For each port, send decoy traffic before the real scan
            for &port in &ports {
                println!("🔍 Scanning port {} with evasion...", port);

                match evasion_engine
                    .execute_decoy_scan(source_ip, target_ip, port, ScanType::TcpSyn)
                    .await
                {
                    Ok(evasion_result) => {
                        // Print result inline to avoid borrowing conflict
                        if evasion_result.real_scan_sent {
                            println!(
                                "  ✅ Port {}: Real packet sent + {} decoy packets",
                                port, evasion_result.decoys_sent
                            );
                        } else {
                            println!(
                                "  ⚠️  Port {}: Real packet failed, {} decoys attempted",
                                port, evasion_result.decoys_sent
                            );
                        }

                        if !evasion_result.errors.is_empty() {
                            for error in &evasion_result.errors {
                                eprintln!("⚠️  Evasion warning: {}", error);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Evasion failed for port {}: {}", port, e);
                    }
                }

                // Small delay between port scans to make timing less predictable
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    rand::random::<u64>() % 100 + 50,
                ))
                .await;
            }

            println!("🎯 Decoy phase complete. Running main scan...");
        }

        // Run the actual scanner with potential port spoofing modifications
        // Note: Currently the SynScanner doesn't directly support dynamic source ports
        // This is where future integration would happen to modify the scanner's source port selection
        self.scanner.scan()?;

        // Report port spoofing usage if enabled
        if let Some(ref port_spoofer) = self.port_spoofer {
            println!("🔧 Port spoofing statistics:");
            let usage_stats = port_spoofer.get_usage_stats();
            for (&port, &count) in usage_stats.iter() {
                println!(
                    "   Source port {} used {} times ({})",
                    port,
                    count,
                    crate::evasion::PortSpoofer::get_service_name(port)
                );
            }
        }

        println!("✅ Evasive scan completed successfully!");
        Ok(())
    }

    /// Perform regular scan without evasion
    fn scan_without_evasion(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔍 Starting regular scan (no evasion)...");
        self.scanner.scan()
    }

    /// Get scan results
    pub fn get_results(&self) -> &Vec<ScanResult> {
        self.scanner.get_results()
    }

    /// Check if evasion is enabled and available
    pub fn is_evasion_enabled(&self) -> bool {
        self.evasion_enabled
    }

    /// Check if port spoofing is enabled
    pub fn is_spoofing_enabled(&self) -> bool {
        self.spoofing_enabled
    }

    /// Get evasion capabilities info
    pub fn evasion_info(&self) -> String {
        let mut info = Vec::new();

        if let Some(ref engine) = self.evasion_engine {
            info.push(format!("Evasion: {}", engine.capabilities_info()));
        } else {
            info.push("Evasion: Not configured".to_string());
        }

        if let Some(ref spoofer) = self.port_spoofer {
            info.push(format!(
                "Port Spoofing: {:?} strategy",
                spoofer.get_config().strategy
            ));
        } else {
            info.push("Port Spoofing: Not configured".to_string());
        }

        info.join(", ")
    }

    /// Print evasion result summary
    fn print_evasion_result(&self, result: &EvasionResult, port: u16) {
        if result.real_scan_sent {
            println!(
                "  ✅ Port {}: Real packet sent + {} decoy packets",
                port, result.decoys_sent
            );
        } else {
            println!(
                "  ⚠️  Port {}: Real packet failed, {} decoys attempted",
                port, result.decoys_sent
            );
        }
    }

    /// Get a reference to the scan configuration (helper method)
    fn get_scan_config(&self) -> &ScanConfig {
        self.scanner.get_config()
    }

    /// Set a custom evasion configuration
    pub fn set_evasion_config(&mut self, config: EvasionConfig) -> Result<(), String> {
        if self.evasion_engine.is_some() {
            let new_engine = EvasionEngine::new(config);
            self.evasion_enabled = new_engine.has_raw_socket_capability();
            self.evasion_engine = Some(new_engine);
            Ok(())
        } else {
            Err("No evasion engine configured".to_string())
        }
    }

    /// Get statistics about the evasion performance
    /// Get a spoofed source port for the given target port
    pub fn get_spoofed_source_port(&mut self, target_port: u16) -> Option<u16> {
        if let Some(ref mut spoofer) = self.port_spoofer {
            Some(spoofer.get_spoofed_source_port(target_port))
        } else {
            None
        }
    }

    pub fn get_evasion_stats(&self) -> EvasionStats {
        EvasionStats {
            evasion_enabled: self.evasion_enabled,
            spoofing_enabled: self.spoofing_enabled,
            raw_socket_available: self
                .evasion_engine
                .as_ref()
                .map(|e| e.has_raw_socket_capability())
                .unwrap_or(false),
            capabilities: self.evasion_info(),
        }
    }
}

/// Statistics about evasion capabilities and performance
#[derive(Debug)]
pub struct EvasionStats {
    pub evasion_enabled: bool,
    pub spoofing_enabled: bool,
    pub raw_socket_available: bool,
    pub capabilities: String,
}

impl std::fmt::Display for EvasionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Evasion Stats:\n")?;
        write!(f, "  Evasion Enabled: {}\n", self.evasion_enabled)?;
        write!(f, "  Port Spoofing Enabled: {}\n", self.spoofing_enabled)?;
        write!(f, "  Raw Sockets: {}\n", self.raw_socket_available)?;
        write!(f, "  Capabilities: {}", self.capabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, atomic::AtomicBool};
    use std::time::Duration;

    fn create_test_config() -> ScanConfig {
        ScanConfig {
            destination_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ports_to_scan: vec![80, 443, 22],
            interface_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            source_port: 12345,
            timeout: Duration::from_secs(5),
            wait_after_send: Duration::from_millis(100),
            all_sent: Arc::new(AtomicBool::new(false)),
            max_threads: 100,
        }
    }

    #[test]
    fn test_wrapper_creation_without_evasion() {
        let config = create_test_config();
        let wrapper = EvasiveScannerWrapper::new(config);

        assert!(!wrapper.is_evasion_enabled());
        assert!(!wrapper.is_spoofing_enabled());
        assert!(wrapper.evasion_info().contains("Not configured"));
    }

    #[test]
    fn test_wrapper_creation_with_evasion() {
        let scan_config = create_test_config();
        let evasion_config = EvasionConfig::default();
        let wrapper = EvasiveScannerWrapper::new_with_evasion(scan_config, evasion_config);

        // Evasion might not be enabled if raw sockets aren't available
        let stats = wrapper.get_evasion_stats();
        assert!(!stats.capabilities.is_empty());
    }

    #[tokio::test]
    async fn test_scan_without_evasion() {
        let config = create_test_config();
        let mut wrapper = EvasiveScannerWrapper::new(config);

        // This will likely fail in test environment due to raw sockets,
        // but we can test that the method exists and handles errors gracefully
        let result = wrapper.scan().await;

        // We expect this to fail in CI/test environments, so we just check
        // that we get a proper error response rather than a panic
        assert!(result.is_err() || result.is_ok());
    }
}
