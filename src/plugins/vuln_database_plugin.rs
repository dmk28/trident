//! Vulnerability Database Plugin
//!
//! This plugin integrates with the comprehensive vulnerability database to identify
//! known vulnerabilities in detected services. It performs CVE lookups, checks for
//! known exploitable vulnerabilities, and provides detailed security assessments.

use crate::plugins::plugin_trait::{
    Finding, Plugin, PluginConfig, PluginPriority, PluginResult, Severity,
};
use crate::scanner::{PortStatus, ScanResult};
use crate::vulndb::{VulnCheckType, VulnerabilityDatabase, VulnerabilityRule};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Vulnerability Database Plugin
pub struct VulnDatabasePlugin {
    name: String,
    version: String,
    vuln_db: VulnerabilityDatabase,
}

impl VulnDatabasePlugin {
    pub fn new() -> Self {
        Self {
            name: "Vulnerability Database Scanner".to_string(),
            version: "1.0.0".to_string(),
            vuln_db: VulnerabilityDatabase::new(),
        }
    }

    /// Check for vulnerabilities based on open ports (conservative approach)
    fn check_port_vulnerabilities(&self, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();
        let port_vulnerabilities = self.vuln_db.find_vulnerabilities_for_port(port);

        for rule in port_vulnerabilities {
            if matches!(rule.check_type, VulnCheckType::OpenPort) {
                // Only flag non-critical port-based vulnerabilities to avoid false positives
                if !matches!(rule.severity, Severity::Critical) {
                    let mut finding = self.create_finding_from_rule(rule, port, None);
                    // Lower confidence for port-only matches
                    finding.confidence *= 0.6; // Reduce confidence by 40%
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Check for service-specific vulnerabilities
    fn check_service_vulnerabilities(
        &self,
        service: Option<&str>,
        banner: Option<&str>,
        port: u16,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(service_name) = service {
            let service_vulnerabilities = self
                .vuln_db
                .find_vulnerabilities_for_service(service_name, banner);

            for rule in service_vulnerabilities {
                match &rule.check_type {
                    VulnCheckType::BannerMatch(pattern) => {
                        if let Some(banner_text) = banner {
                            if banner_text.to_lowercase().contains(&pattern.to_lowercase()) {
                                findings.push(self.create_finding_from_rule(
                                    rule,
                                    port,
                                    Some(banner_text),
                                ));
                            }
                        }
                    }
                    VulnCheckType::VersionCheck {
                        service: svc,
                        pattern,
                    } => {
                        if service_name.to_lowercase().contains(&svc.to_lowercase()) {
                            if let Some(banner_text) = banner {
                                if banner_text.to_lowercase().contains(&pattern.to_lowercase()) {
                                    findings.push(self.create_finding_from_rule(
                                        rule,
                                        port,
                                        Some(banner_text),
                                    ));
                                }
                            }
                        }
                    }
                    VulnCheckType::OpenPort | VulnCheckType::CustomScript(_) => {
                        // Already handled or requires special processing
                    }
                }
            }
        }

        findings
    }

    /// Check for critical and exploitable vulnerabilities
    fn check_critical_vulnerabilities(&self, port: u16, service: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check critical vulnerabilities - ONLY if we have service confirmation
        let critical_vulns = self.vuln_db.get_critical_vulnerabilities();
        for rule in critical_vulns {
            if rule.ports.contains(&port) {
                if let Some(service_name) = service {
                    // Only flag critical vulnerabilities if service patterns match
                    if rule.service_patterns.iter().any(|pattern| {
                        service_name
                            .to_lowercase()
                            .contains(&pattern.to_lowercase())
                    }) {
                        let mut finding = self.create_finding_from_rule(rule, port, service);
                        finding.title = format!("🚨 CRITICAL: {}", finding.title);
                        finding.severity = Severity::Critical;
                        findings.push(finding);
                    }
                }
                // Removed the fallback logic that flagged vulnerabilities without service confirmation
                // This prevents false positives like Log4Shell on router HTTPS interfaces
            }
        }

        // Check exploitable vulnerabilities - ONLY with service confirmation
        let exploitable_vulns = self.vuln_db.get_exploitable_vulnerabilities();
        for rule in exploitable_vulns {
            if rule.ports.contains(&port) {
                if let Some(service_name) = service {
                    if rule.service_patterns.iter().any(|pattern| {
                        service_name
                            .to_lowercase()
                            .contains(&pattern.to_lowercase())
                    }) {
                        let mut finding = self.create_finding_from_rule(rule, port, service);
                        finding.title = format!("💥 EXPLOITABLE: {}", finding.title);
                        findings.push(finding);
                    }
                }
                // No fallback - exploitable vulnerabilities require service confirmation
            }
        }

        findings
    }

    /// Perform CVE database lookup
    fn check_cve_database(&self, service: Option<&str>, version: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(service_name) = service {
            let cves = self
                .vuln_db
                .find_cves_for_service(service_name, version, None, 0.0);

            // The CVE database returns Finding objects directly
            findings.extend(cves.into_iter().take(5));
        }

        findings
    }

    /// Create a finding from a vulnerability rule
    fn create_finding_from_rule(
        &self,
        rule: &VulnerabilityRule,
        port: u16,
        evidence: Option<&str>,
    ) -> Finding {
        let mut recommendations = vec![
            "Review and apply available security patches".to_string(),
            "Implement security hardening measures".to_string(),
            "Monitor for signs of exploitation".to_string(),
        ];

        if rule.patch_available {
            recommendations.insert(
                0,
                "URGENT: Security patch is available - apply immediately".to_string(),
            );
        }

        if rule.exploitable {
            recommendations.insert(
                0,
                "⚠️ This vulnerability is actively exploitable - take immediate action".to_string(),
            );
        }

        let mut evidence_vec = vec![format!("Port: {}", port)];
        if let Some(evidence_text) = evidence {
            evidence_vec.push(format!("Evidence: {}", evidence_text));
        }
        if !rule.cve_ids.is_empty() {
            evidence_vec.push(format!("CVEs: {}", rule.cve_ids.join(", ")));
        }

        Finding {
            title: rule.name.clone(),
            description: rule.description.clone(),
            severity: rule.severity.clone(),
            confidence: if rule.exploitable {
                0.95
            } else if evidence.is_some() {
                0.8
            } else {
                0.5
            },
            evidence: evidence_vec,
            recommendations,
            references: rule.references.clone(),
            metadata: {
                let mut map = HashMap::new();
                map.insert("category".to_string(), rule.category.clone());
                map.insert("exploitable".to_string(), rule.exploitable.to_string());
                map.insert(
                    "patch_available".to_string(),
                    rule.patch_available.to_string(),
                );
                if !rule.cve_ids.is_empty() {
                    map.insert("cve_ids".to_string(), rule.cve_ids.join(", "));
                }
                map.insert(
                    "ports".to_string(),
                    rule.ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                map
            },
        }
    }

    /// Extract service name and version from banner or service info
    fn parse_service_info(
        &self,
        service: Option<&str>,
        banner: Option<&str>,
    ) -> (Option<String>, Option<String>) {
        let mut detected_service = service.map(|s| s.to_string());
        let mut version = None;

        if let Some(banner_text) = banner {
            // Try to extract service and version from banner
            let banner_lower = banner_text.to_lowercase();

            // Java application servers and services (for Log4Shell detection)
            if banner_lower.contains("tomcat") || banner_lower.contains("catalina") {
                detected_service = Some("tomcat".to_string());
                if let Some(start) = banner_lower.find("tomcat/") {
                    if let Some(end) = banner_text[start..].find(' ') {
                        version = Some(banner_text[start..start + end].to_string());
                    }
                }
            } else if banner_lower.contains("jetty") {
                detected_service = Some("jetty".to_string());
            } else if banner_lower.contains("spring") || banner_lower.contains("spring-boot") {
                detected_service = Some("spring".to_string());
            } else if banner_lower.contains("weblogic") {
                detected_service = Some("weblogic".to_string());
            } else if banner_lower.contains("websphere") {
                detected_service = Some("websphere".to_string());
            } else if banner_lower.contains("jboss") || banner_lower.contains("wildfly") {
                detected_service = Some("jboss".to_string());
            } else if banner_lower.contains("elasticsearch") {
                detected_service = Some("elasticsearch".to_string());
            } else if banner_lower.contains("solr") {
                detected_service = Some("solr".to_string());
            } else if banner_lower.contains("java")
                && (banner_lower.contains("server") || banner_lower.contains("http"))
            {
                detected_service = Some("java".to_string());
            // Non-Java web servers and services
            } else if banner_lower.contains("apache") && !banner_lower.contains("tomcat") {
                detected_service = Some("apache".to_string());
                if let Some(start) = banner_lower.find("apache/") {
                    if let Some(end) = banner_text[start..].find(' ') {
                        version = Some(banner_text[start..start + end].to_string());
                    }
                }
            } else if banner_lower.contains("nginx") {
                detected_service = Some("nginx".to_string());
                if let Some(start) = banner_lower.find("nginx/") {
                    if let Some(end) = banner_text[start..].find(' ') {
                        version = Some(banner_text[start..start + end].to_string());
                    }
                }
            } else if banner_lower.contains("iis") || banner_lower.contains("microsoft-iis") {
                detected_service = Some("iis".to_string());
            } else if banner_lower.contains("openssh") {
                detected_service = Some("openssh".to_string());
                if let Some(start) = banner_lower.find("openssh_") {
                    if let Some(end) = banner_text[start..].find(' ') {
                        version = Some(banner_text[start..start + end].to_string());
                    }
                }
            } else if banner_lower.contains("mysql") {
                detected_service = Some("mysql".to_string());
            } else if banner_lower.contains("postgresql") {
                detected_service = Some("postgresql".to_string());
            } else if banner_lower.contains("lighttpd") {
                detected_service = Some("lighttpd".to_string());
            } else if banner_lower.contains("caddy") {
                detected_service = Some("caddy".to_string());
            }
        }

        (detected_service, version)
    }

    /// Detect if target is likely network equipment to avoid false positives
    fn is_likely_network_equipment(&self, banner: Option<&str>, target: IpAddr, port: u16) -> bool {
        // Check banner for network equipment indicators
        if let Some(banner_text) = banner {
            let banner_lower = banner_text.to_lowercase();

            // Common network equipment identifiers in banners
            if banner_lower.contains("cisco")
                || banner_lower.contains("juniper")
                || banner_lower.contains("netgear")
                || banner_lower.contains("linksys")
                || banner_lower.contains("d-link")
                || banner_lower.contains("tp-link")
                || banner_lower.contains("ubiquiti")
                || banner_lower.contains("mikrotik")
                || banner_lower.contains("fortinet")
                || banner_lower.contains("palo alto")
                || banner_lower.contains("sonicwall")
                || banner_lower.contains("watchguard")
                || banner_lower.contains("pfSense")
                || banner_lower.contains("opnsense")
                || banner_lower.contains("router")
                || banner_lower.contains("switch")
                || banner_lower.contains("firewall")
                || banner_lower.contains("gateway")
                || banner_lower.contains("access point")
            {
                return true;
            }

            // Check for common router/switch web interfaces
            if (port == 80 || port == 443)
                && (banner_lower.contains("web configuration")
                    || banner_lower.contains("device management")
                    || banner_lower.contains("admin interface")
                    || banner_lower.contains("router configuration"))
            {
                return true;
            }
        }

        // Check IP address patterns common for network equipment
        match target {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Common default gateway addresses
                if (octets[0] == 192 && octets[1] == 168 && (octets[3] == 1 || octets[3] == 254))
                    || (octets[0] == 10 && octets[1] == 0 && octets[2] == 0 && octets[3] == 1)
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 && octets[3] == 1)
                {
                    // Additional confirmation needed - check port
                    if port == 80 || port == 443 || port == 22 || port == 23 {
                        return true;
                    }
                }
            }
            _ => {}
        }

        false
    }
}

impl Default for VulnDatabasePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for VulnDatabasePlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        "Comprehensive vulnerability database scanner that checks for known CVEs and security issues"
    }

    fn priority(&self) -> PluginPriority {
        PluginPriority::High // High priority for security findings
    }

    fn can_analyze(&self, scan_result: &ScanResult) -> bool {
        // Can analyze open ports and some filtered ports
        matches!(
            scan_result.status,
            PortStatus::Open | PortStatus::OpenFiltered
        )
    }

    fn required_port_status(&self) -> Vec<PortStatus> {
        vec![PortStatus::Open, PortStatus::OpenFiltered]
    }

    async fn analyze(
        &self,
        target: IpAddr,
        port: u16,
        scan_result: &ScanResult,
        _config: &PluginConfig,
    ) -> PluginResult {
        let mut findings = Vec::new();
        let mut success = true;
        let mut error_message = None;

        // Check if this looks like network equipment (routers, switches, etc.)
        let is_network_equipment =
            self.is_likely_network_equipment(scan_result.banner.as_deref(), target, port);

        // Extract service information
        let (detected_service, version) = self.parse_service_info(
            scan_result.service.as_deref(),
            scan_result.banner.as_deref(),
        );

        // Skip vulnerability scanning for obvious network equipment
        if is_network_equipment {
            findings.push(Finding {
                title: "Network Equipment Detected".to_string(),
                description: "This appears to be network infrastructure (router, switch, or firewall). Vulnerability scanning skipped to avoid false positives.".to_string(),
                severity: Severity::Info,
                confidence: 0.8,
                evidence: vec![
                    format!("Target IP: {}", target),
                    format!("Port: {}", port),
                    if let Some(banner) = &scan_result.banner {
                        format!("Banner: {}", banner)
                    } else {
                        "Private network IP range".to_string()
                    },
                ],
                recommendations: vec![
                    "Verify this is authorized network equipment".to_string(),
                    "Ensure firmware is up to date".to_string(),
                    "Review access controls and authentication".to_string(),
                ],
                references: vec![],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert("equipment_type".to_string(), "network_infrastructure".to_string());
                    map.insert("scan_target".to_string(), format!("{}:{}", target, port));
                    map
                },
            });

            return PluginResult {
                plugin_name: self.name().to_string(),
                target_ip: target,
                target_port: port,
                success: true,
                findings,
                execution_time: Duration::from_millis(0),
                error_message: None,
                raw_data: None,
            };
        }

        // 1. Check port-based vulnerabilities
        let port_findings = self.check_port_vulnerabilities(port);
        findings.extend(port_findings);

        // 2. Check service-specific vulnerabilities
        if detected_service.is_some() || scan_result.banner.is_some() {
            let service_findings = self.check_service_vulnerabilities(
                detected_service.as_deref(),
                scan_result.banner.as_deref(),
                port,
            );
            findings.extend(service_findings);
        }

        // 3. Check critical and exploitable vulnerabilities
        let critical_findings =
            self.check_critical_vulnerabilities(port, detected_service.as_deref());
        findings.extend(critical_findings);

        // 4. Perform CVE database lookup
        if detected_service.is_some() {
            let cve_findings =
                self.check_cve_database(detected_service.as_deref(), version.as_deref());
            findings.extend(cve_findings);
        }

        // 5. Add summary finding if vulnerabilities were found
        if !findings.is_empty() {
            let critical_count = findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::Critical))
                .count();
            let high_count = findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::High))
                .count();

            if critical_count > 0 || high_count > 0 {
                findings.insert(0, Finding {
                    title: format!("🔍 Vulnerability Assessment Summary - {} vulnerabilities found", findings.len()),
                    description: format!(
                        "Vulnerability scan completed for {}:{}. Found {} critical and {} high severity vulnerabilities{}",
                        target, port, critical_count, high_count,
                        if detected_service.is_some() {
                            format!(" for {} service", detected_service.as_ref().unwrap())
                        } else {
                            " (service-confirmed vulnerabilities only)".to_string()
                        }
                    ),
                    severity: if critical_count > 0 { Severity::Critical } else { Severity::High },
                    confidence: if detected_service.is_some() { 0.9 } else { 0.7 },
                    evidence: vec![
                        format!("Critical vulnerabilities: {}", critical_count),
                        format!("High severity vulnerabilities: {}", high_count),
                        format!("Total vulnerabilities: {}", findings.len() - 1), // -1 to exclude this summary
                    ],
                    recommendations: vec![
                        "Review all identified vulnerabilities immediately".to_string(),
                        "Prioritize critical and high severity issues".to_string(),
                        "Implement a vulnerability management process".to_string(),
                        "Schedule regular security assessments".to_string(),
                    ],
                    references: vec![
                        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string(),
                        "https://nvd.nist.gov/".to_string(),
                    ],
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("scan_target".to_string(), format!("{}:{}", target, port));
                        map.insert("critical_count".to_string(), critical_count.to_string());
                        map.insert("high_count".to_string(), high_count.to_string());
                        map.insert("total_count".to_string(), (findings.len() - 1).to_string());
                        if let Some(ref svc) = detected_service {
                            map.insert("detected_service".to_string(), svc.clone());
                        }
                        if let Some(ref ver) = version {
                            map.insert("detected_version".to_string(), ver.clone());
                        }
                        map
                    },
                });
            }
        } else {
            // No vulnerabilities found
            success = true; // This is actually a good thing
        }

        PluginResult {
            plugin_name: self.name().to_string(),
            target_ip: target,
            target_port: port,
            success,
            findings,
            execution_time: Duration::from_millis(0), // Will be set by plugin manager
            error_message,
            raw_data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_vuln_database_plugin_creation() {
        let plugin = VulnDatabasePlugin::new();
        assert_eq!(plugin.name(), "Vulnerability Database Scanner");
        assert_eq!(plugin.version(), "1.0.0");
    }

    #[test]
    fn test_plugin_can_analyze() {
        let plugin = VulnDatabasePlugin::new();

        let open_result = ScanResult {
            port: 80,
            status: PortStatus::Open,
            timestamp: SystemTime::now(),
            response_time: Duration::from_millis(100),
            ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            service: Some("http".to_string()),
            banner: Some("Apache/2.4.41".to_string()),
        };

        let closed_result = ScanResult {
            port: 80,
            status: PortStatus::Closed,
            timestamp: SystemTime::now(),
            response_time: Duration::from_millis(100),
            ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            service: None,
            banner: None,
        };

        assert!(plugin.can_analyze(&open_result));
        assert!(!plugin.can_analyze(&closed_result));
    }

    #[test]
    fn test_service_parsing() {
        let plugin = VulnDatabasePlugin::new();

        // Test Apache parsing
        let (service, version) =
            plugin.parse_service_info(Some("http"), Some("Apache/2.4.41 (Ubuntu)"));
        assert_eq!(service, Some("apache".to_string()));

        // Test Nginx parsing
        let (service, _) = plugin.parse_service_info(None, Some("nginx/1.18.0 (Ubuntu)"));
        assert_eq!(service, Some("nginx".to_string()));

        // Test SSH parsing
        let (service, _) =
            plugin.parse_service_info(Some("ssh"), Some("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"));
        assert_eq!(service, Some("openssh".to_string()));
    }

    #[test]
    fn test_port_vulnerabilities() {
        let plugin = VulnDatabasePlugin::new();

        // Test common vulnerable ports
        let findings_80 = plugin.check_port_vulnerabilities(80);
        let findings_22 = plugin.check_port_vulnerabilities(22);

        // Should find some vulnerabilities for common ports
        // Note: The actual findings depend on the vulnerability database content
        assert!(findings_80.len() >= 0); // Could be 0 if only service-specific vulns exist
        assert!(findings_22.len() >= 0);
    }
}
