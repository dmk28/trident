use crate::os_fingerprint::database_probes::DatabaseInfo;
use crate::plugins::plugin_trait::{
    FindingBuilder, Plugin, PluginConfig, PluginPriority, PluginResult, Severity,
};
use crate::plugins::shared_services::get_database_service;
use crate::scanner::{PortStatus, ScanResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

/// Database detection wrapper plugin that integrates with existing service detection
pub struct DatabaseDetectionPlugin {
    name: String,
    version: String,
    enabled: bool,
}

impl DatabaseDetectionPlugin {
    pub fn new() -> Self {
        Self {
            name: "Database Detection".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
        }
    }

    /// Get database service (uses shared service)
    async fn get_db_service(
        &self,
    ) -> tokio::sync::MutexGuard<'static, crate::plugins::shared_services::DatabaseDetectionService>
    {
        get_database_service().await
    }

    /// Detect database service using shared service
    async fn probe_database_service(&self, ip: IpAddr, port: u16) -> Option<DatabaseInfo> {
        let db_service = self.get_db_service().await;
        db_service.detect_database(ip, port).await
    }

    /// Convert DatabaseInfo to appropriate findings
    fn create_database_findings(
        &self,
        db_info: &DatabaseInfo,
    ) -> Vec<crate::plugins::plugin_trait::Finding> {
        let mut findings = Vec::new();

        // Main service detection finding
        let version_str = db_info.version.as_deref().unwrap_or("unknown version");
        let mut service_finding = Self::create_service_finding(
            &db_info.service_type,
            db_info.version.as_deref(),
            db_info.raw_banner.as_deref(),
        );

        // Add database-specific metadata
        service_finding
            .metadata
            .insert("database_type".to_string(), db_info.service_type.clone());
        service_finding.metadata.insert(
            "auth_required".to_string(),
            db_info.authentication_required.to_string(),
        );
        service_finding.metadata.insert(
            "handshake_steps".to_string(),
            db_info.handshake_steps.to_string(),
        );

        if let Some(case_sensitive) = db_info.case_sensitive {
            service_finding
                .metadata
                .insert("case_sensitive".to_string(), case_sensitive.to_string());
        }

        // Add protocol information from additional_info
        for (key, value) in &db_info.additional_info {
            service_finding
                .metadata
                .insert(format!("db_{}", key), value.clone());
        }

        findings.push(service_finding);

        // Security findings based on database configuration
        if db_info.anonymous_access_possible {
            let vuln_finding = Self::create_vulnerability_finding(
                "Database Anonymous Access",
                None,
                &format!(
                    "{} database allows anonymous access without authentication",
                    db_info.service_type
                ),
                Severity::High,
            );
            findings.push(vuln_finding);
        }

        // Check for insecure authentication methods
        if let Some(auth_method) = db_info.additional_info.get("auth_method") {
            match auth_method.as_str() {
                "trust" => {
                    let critical_finding = Self::create_vulnerability_finding(
                        "Trust Authentication Enabled",
                        None,
                        &format!(
                            "{} is configured with 'trust' authentication - no password required for connections",
                            db_info.service_type
                        ),
                        Severity::Critical,
                    );
                    findings.push(critical_finding);
                }
                "cleartext" => {
                    let medium_finding = Self::create_vulnerability_finding(
                        "Cleartext Password Authentication",
                        None,
                        &format!(
                            "{} accepts cleartext passwords which can be intercepted",
                            db_info.service_type
                        ),
                        Severity::Medium,
                    );
                    findings.push(medium_finding);
                }
                _ => {}
            }
        }

        // Information disclosure through version banners
        if db_info.version.is_some() {
            let mut info_finding = Self::create_finding(
                "Database Version Disclosure",
                format!(
                    "{} version information disclosed: {}",
                    db_info.service_type, version_str
                ),
                Severity::Info,
            );
            info_finding.confidence = 0.8;
            info_finding
                .recommendations
                .push("Consider suppressing version information in banners".to_string());
            findings.push(info_finding);
        }

        findings
    }

    fn get_database_type_hint(&self, port: u16) -> &'static str {
        match port {
            3306 => "MySQL",
            5432 => "PostgreSQL",
            1521 => "Oracle",
            1433 => "SQL Server",
            6379 => "Redis",
            27017 => "MongoDB",
            5984 => "CouchDB",
            9042 => "Cassandra",
            7000 | 7001 => "Cassandra",
            8086 => "InfluxDB",
            _ => "Unknown Database",
        }
    }

    fn is_common_database_port(&self, port: u16) -> bool {
        matches!(
            port,
            1433 | 1521 | 3306 | 5432 | 6379 | 27017 | 5984 | 9042 | 7000 | 7001 | 8086
        )
    }
}

impl Default for DatabaseDetectionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingBuilder for DatabaseDetectionPlugin {}

#[async_trait]
impl Plugin for DatabaseDetectionPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        "Detects database services (MySQL, PostgreSQL, MSSQL, Oracle) and analyzes security configurations"
    }

    fn priority(&self) -> PluginPriority {
        PluginPriority::High // Database detection is high priority
    }

    fn can_analyze(&self, scan_result: &ScanResult) -> bool {
        // Only analyze open ports that might be databases
        matches!(scan_result.status, PortStatus::Open)
            && (self.is_common_database_port(scan_result.port) || scan_result.port > 1024)
    }

    fn required_port_status(&self) -> Vec<PortStatus> {
        vec![PortStatus::Open]
    }

    async fn analyze(
        &self,
        target: IpAddr,
        port: u16,
        _scan_result: &ScanResult,
        _config: &PluginConfig,
    ) -> PluginResult {
        let start_time = std::time::Instant::now();
        let mut findings = Vec::new();
        let mut success = true;
        let mut error_message = None;

        println!("🔍 Probing {}:{} for database services...", target, port);

        // Attempt database detection using shared service
        match self.probe_database_service(target, port).await {
            Some(db_info) => {
                println!(
                    "✅ Detected {} database on port {}",
                    db_info.service_type, port
                );
                findings.extend(self.create_database_findings(&db_info));
            }
            None => {
                // If this is a known database port but we couldn't identify the specific database,
                // still create a generic finding
                if self.is_common_database_port(port) {
                    let type_hint = self.get_database_type_hint(port);
                    let generic_finding = Self::create_finding(
                        "Potential Database Service",
                        format!(
                            "Port {} is commonly used for database services (likely {}) but specific database type could not be identified",
                            port, type_hint
                        ),
                        Severity::Info,
                    );
                    findings.push(generic_finding);
                } else {
                    // For non-standard ports, only report if we actually detected something
                    success = false;
                    error_message = Some("No database service detected".to_string());
                }
            }
        }

        PluginResult {
            plugin_name: self.name().to_string(),
            target_ip: target,
            target_port: port,
            execution_time: start_time.elapsed(),
            success,
            error_message,
            findings,
            raw_data: None,
        }
    }

    async fn initialize(&mut self) -> Result<(), String> {
        println!("🚀 Initializing Database Detection Plugin");
        Ok(())
    }

    fn validate_config(&self, config: &PluginConfig) -> Result<(), String> {
        if !config.enabled {
            return Err("Database detection plugin is disabled".to_string());
        }

        if config.timeout_seconds == 0 {
            return Err("Timeout must be greater than 0".to_string());
        }

        if config.timeout_seconds < 5 {
            println!(
                "⚠️  Warning: Database detection timeout less than 5 seconds may cause false negatives"
            );
        }

        Ok(())
    }
}

/// Enhanced integration function for adding database detection to existing service results
pub async fn enhance_service_detection_with_database_probing(
    ip: IpAddr,
    port: u16,
    existing_findings: &mut Vec<String>,
) -> Option<DatabaseInfo> {
    // Use shared database service
    let db_service = get_database_service().await;
    if let Some(db_info) = db_service.detect_database(ip, port).await {
        // Add database findings to existing results
        let service_description = if let Some(version) = &db_info.version {
            format!("{}:{} - {} v{}", ip, port, db_info.service_type, version)
        } else {
            format!("{}:{} - {}", ip, port, db_info.service_type)
        };

        existing_findings.push(service_description);

        // Add security notes if applicable
        if db_info.anonymous_access_possible {
            existing_findings.push(format!(
                "{}:{} - ⚠️ SECURITY: Anonymous access possible",
                ip, port
            ));
        }

        if let Some(auth_method) = db_info.additional_info.get("auth_method") {
            if auth_method == "trust" {
                existing_findings.push(format!(
                    "{}:{} - 🚨 CRITICAL: Trust authentication enabled",
                    ip, port
                ));
            }
        }

        Some(db_info)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanResult;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_database_port_recognition() {
        let plugin = DatabaseDetectionPlugin::new();
        let db_service = plugin.get_db_service().await;

        assert!(db_service.is_database_port(3306)); // MySQL
        assert!(db_service.is_database_port(5432)); // PostgreSQL
        assert!(db_service.is_database_port(1433)); // MSSQL
        assert!(db_service.is_database_port(1521)); // Oracle
        assert!(db_service.is_database_port(27017)); // MongoDB
        assert!(db_service.is_database_port(6379)); // Redis

        assert!(!db_service.is_database_port(80)); // HTTP
        assert!(!db_service.is_database_port(22)); // SSH
    }

    #[test]
    fn test_plugin_can_analyze() {
        let plugin = DatabaseDetectionPlugin::new();

        let open_db_port = ScanResult {
            ip: Some("127.0.0.1".parse().unwrap()),
            port: 3306,
            status: PortStatus::Open,
            service: None,
            banner: None,
            response_time: std::time::Duration::from_millis(10),
            timestamp: SystemTime::now(),
        };

        let closed_port = ScanResult {
            ip: Some("127.0.0.1".parse().unwrap()),
            port: 3306,
            status: PortStatus::Closed,
            service: None,
            banner: None,
            response_time: std::time::Duration::from_millis(1000),
            timestamp: SystemTime::now(),
        };

        assert!(plugin.can_analyze(&open_db_port));
        assert!(!plugin.can_analyze(&closed_port));
    }

    #[tokio::test]
    async fn test_plugin_analyze() {
        let plugin = DatabaseDetectionPlugin::new();
        let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let config = PluginConfig::default();

        let scan_result = ScanResult {
            ip: Some(ip),
            port: 3306,
            status: PortStatus::Open,
            service: None,
            banner: None,
            response_time: std::time::Duration::from_millis(10),
            timestamp: SystemTime::now(),
        };

        let result = plugin.analyze(ip, 3306, &scan_result, &config).await;

        assert_eq!(result.plugin_name, "Database Detection");
        assert_eq!(result.target_ip, ip);
        assert_eq!(result.target_port, 3306);
        // Result success may vary depending on whether MySQL is actually running
    }

    #[test]
    fn test_config_validation() {
        let plugin = DatabaseDetectionPlugin::new();

        let good_config = PluginConfig {
            enabled: true,
            timeout_seconds: 10,
            max_retries: 1,
            min_cvss: 0.0,
            custom_settings: HashMap::new(),
        };

        let bad_config = PluginConfig {
            enabled: true,
            timeout_seconds: 0,
            max_retries: 1,
            min_cvss: 0.0,
            custom_settings: HashMap::new(),
        };

        assert!(plugin.validate_config(&good_config).is_ok());
        assert!(plugin.validate_config(&bad_config).is_err());
    }
}
