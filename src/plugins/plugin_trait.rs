use crate::scanner::{PortStatus, ScanResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, time::SystemTime};

/// Plugin execution priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PluginPriority {
    Critical, // Security-critical findings (vulnerabilities)
    High,     // Service identification, major findings
    Medium,   // Additional analysis, enumeration
    Low,      // Nice-to-have information
}

/// Result severity levels for security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Individual plugin finding/result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,       // 0.0 - 1.0
    pub evidence: Vec<String>, // Proof/examples
    pub recommendations: Vec<String>,
    pub references: Vec<String>, // CVEs, URLs, etc.
    pub metadata: HashMap<String, String>,
}

/// Plugin execution result
#[derive(Debug, Clone)]
pub struct PluginResult {
    pub plugin_name: String,
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub execution_time: std::time::Duration,
    pub success: bool,
    pub error_message: Option<String>,
    pub findings: Vec<Finding>,
    pub raw_data: Option<Vec<u8>>, // For debugging/advanced analysis
}

/// Plugin configuration
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub enabled: bool,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub min_cvss: f32,
    pub custom_settings: HashMap<String, String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_seconds: 30,
            max_retries: 1,
            min_cvss: 0.0,
            custom_settings: HashMap::new(),
        }
    }
}

/// Main plugin trait - all plugins must implement this
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Plugin identification
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn priority(&self) -> PluginPriority;

    /// Plugin capabilities
    fn can_analyze(&self, scan_result: &ScanResult) -> bool;
    fn required_port_status(&self) -> Vec<PortStatus> {
        vec![PortStatus::Open] // Most plugins only care about open ports
    }

    /// Main plugin execution
    async fn analyze(
        &self,
        target: IpAddr,
        port: u16,
        scan_result: &ScanResult,
        config: &PluginConfig,
    ) -> PluginResult;

    /// Plugin lifecycle
    async fn initialize(&mut self) -> Result<(), String> {
        Ok(()) // Default: no initialization needed
    }

    async fn cleanup(&mut self) -> Result<(), String> {
        Ok(()) // Default: no cleanup needed
    }

    /// Plugin configuration validation
    fn validate_config(&self, config: &PluginConfig) -> Result<(), String> {
        if config.timeout_seconds == 0 {
            return Err("Timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// Helper trait for plugins that need to create findings
pub trait FindingBuilder {
    fn create_finding(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Finding {
        Finding {
            title: title.into(),
            description: description.into(),
            severity,
            confidence: 1.0,
            evidence: Vec::new(),
            recommendations: Vec::new(),
            references: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn create_service_finding(
        service_name: &str,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Finding {
        let mut finding = Self::create_finding(
            format!("Service Detected: {}", service_name),
            match version {
                Some(v) => format!("{} version {} detected", service_name, v),
                None => format!("{} service detected", service_name),
            },
            Severity::Info,
        );

        if let Some(banner) = banner {
            finding.evidence.push(format!("Banner: {}", banner));
        }

        finding
    }

    fn create_vulnerability_finding(
        vuln_name: &str,
        cve: Option<&str>,
        description: &str,
        severity: Severity,
    ) -> Finding {
        let mut finding = Self::create_finding(
            format!("Vulnerability: {}", vuln_name),
            description,
            severity,
        );

        if let Some(cve) = cve {
            finding.references.push(format!("CVE: {}", cve));
            finding.metadata.insert("cve".to_string(), cve.to_string());
        }

        finding
    }
}
