use super::plugin_trait::{
    Finding, FindingBuilder, Plugin, PluginConfig, PluginPriority, PluginResult, Severity,
};
use crate::os_fingerprint::database_probes::DatabaseInfo;
use crate::os_fingerprint::{
    ConversationResult, grab_ftp_banner, grab_http_banner, grab_ssh_banner, run_smtp_conversation,
};
use crate::plugins::shared_services::get_database_service;
use crate::scanner::{PortStatus, ScanResult};
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, rustls};

/// Service detection plugin that identifies services running on open ports
pub struct ServiceDetectionPlugin {
    pub name: String,
    pub version: String,
}

impl ServiceDetectionPlugin {
    pub fn new() -> Self {
        Self {
            name: "Service Detection".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    // Simplified TLS detection - just check if connection succeeds

    /// Detect HTTP service and gather information
    async fn detect_http(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        match grab_http_banner(ip, port, None).await {
            Ok(server_header) => {
                if server_header != "No Server Header" {
                    let mut finding =
                        Self::create_service_finding("HTTP", None, Some(&server_header));
                    finding
                        .metadata
                        .insert("server_header".to_string(), server_header.clone());

                    // Try to extract version information
                    if let Some(version) = self.extract_http_version(&server_header) {
                        finding.title = format!("Service Detected: HTTP Server ({})", version);
                        finding.metadata.insert("version".to_string(), version);
                    }

                    findings.push(finding);
                } else {
                    findings.push(Self::create_service_finding("HTTP", None, None));
                }
            }
            Err(_) => {
                // Even if banner grab fails, we know it's HTTP if we're checking common HTTP ports
                if matches!(port, 80 | 8080 | 8000 | 8888) {
                    findings.push(Self::create_service_finding("HTTP", None, None));
                }
            }
        }

        findings
    }

    /// Detect if TLS connection succeeds for HTTPS services
    async fn detect_tls_details(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        match tokio::net::TcpStream::connect((ip, port)).await {
            Ok(stream) => {
                let mut root_store = rustls::RootCertStore::empty();
                // TODO: Add root certificates for proper verification

                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let connector = TlsConnector::from(Arc::new(config));
                let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();

                match connector.connect(server_name, stream).await {
                    Ok(tls_stream) => {
                        let (_, session) = tls_stream.get_ref();
                        let version = format!("{:?}", session.protocol_version());
                        let cipher = format!("{:?}", session.negotiated_cipher_suite());
                        let num_certs = session.peer_certificates().map_or(0, |c| c.len());

                        let finding = Self::create_finding(
                            "TLS Fingerprint",
                            format!(
                                "TLS version: {}, Cipher: {}, Certificates: {}",
                                version, cipher, num_certs
                            ),
                            Severity::Info,
                        );
                        findings.push(finding);

                        // Check for vulnerable TLS versions
                        if version.contains("TLSv1_0") || version.contains("TLSv1_1") {
                            findings.push(Self::create_vulnerability_finding(
                                "Deprecated TLS Version",
                                Some(&version),
                                "TLS 1.0 and 1.1 are deprecated and vulnerable to attacks like POODLE",
                                Severity::High,
                            ));
                        }

                        // Check for weak cipher suites
                        if cipher.contains("RC4")
                            || cipher.contains("DES")
                            || cipher.contains("3DES")
                        {
                            findings.push(Self::create_vulnerability_finding(
                                "Weak Cipher Suite",
                                Some(&cipher),
                                "Weak cipher suites are vulnerable to attacks",
                                Severity::Medium,
                            ));
                        }

                        // Check for missing certificates
                        if num_certs == 0 {
                            findings.push(Self::create_vulnerability_finding(
                                "No Server Certificate",
                                None,
                                "Server did not present any certificates during TLS handshake",
                                Severity::High,
                            ));
                        }
                    }
                    Err(e) => {
                        findings.push(Self::create_finding(
                            "TLS Handshake Failed",
                            format!("TLS handshake failed: {}", e),
                            Severity::Info,
                        ));
                    }
                }
            }
            Err(e) => {
                findings.push(Self::create_finding(
                    "TCP Connection Failed",
                    format!("Failed to connect to {}:{} - {}", ip, port, e),
                    Severity::Info,
                ));
            }
        }

        findings
    }

    /// Detect SSH service using banner grabbing
    async fn detect_ssh(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        match grab_ssh_banner(ip, port).await {
            Ok(banner) => {
                let version = self.extract_ssh_version(&banner);
                let mut finding =
                    Self::create_service_finding("SSH", version.as_deref(), Some(&banner));
                finding
                    .metadata
                    .insert("banner".to_string(), banner.clone());

                // Security analysis
                if banner.contains("SSH-1.") {
                    findings.push(Self::create_vulnerability_finding(
                        "Insecure SSH Version",
                        None,
                        "SSH version 1.x is deprecated and insecure. Upgrade to SSH-2.0.",
                        Severity::Medium,
                    ));
                }

                findings.push(finding);
            }
            Err(_) => {
                if port == 22 {
                    findings.push(Self::create_service_finding("SSH", None, None));
                }
            }
        }

        findings
    }

    /// Detect FTP service
    async fn detect_ftp(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        match grab_ftp_banner(ip, port).await {
            Ok(banner) => {
                let version = self.extract_ftp_version(&banner);
                let mut finding =
                    Self::create_service_finding("FTP", version.as_deref(), Some(&banner));
                finding
                    .metadata
                    .insert("banner".to_string(), banner.clone());

                // Security analysis - check for anonymous FTP
                if banner.to_lowercase().contains("anonymous") {
                    findings.push(Self::create_vulnerability_finding(
                        "Anonymous FTP Access",
                        None,
                        "FTP server allows anonymous access. This may expose sensitive data.",
                        Severity::Medium,
                    ));
                }

                findings.push(finding);
            }
            Err(_) => {
                if port == 21 {
                    findings.push(Self::create_service_finding("FTP", None, None));
                }
            }
        }

        findings
    }

    /// Detect SMTP service using your conversation system
    async fn detect_smtp(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        match run_smtp_conversation(ip, port).await {
            Ok(conversation_result) => {
                let mut finding = Self::create_service_finding("SMTP", None, None);
                finding.metadata.insert(
                    "capabilities".to_string(),
                    conversation_result.discovered_capabilities.join(", "),
                );

                // Analyze SMTP capabilities for security issues
                for capability in &conversation_result.discovered_capabilities {
                    if capability.contains("AUTH") {
                        finding
                            .metadata
                            .insert("auth_methods".to_string(), capability.clone());
                    }
                    if capability.contains("STARTTLS") {
                        finding
                            .metadata
                            .insert("tls_support".to_string(), "true".to_string());
                    }
                }

                // Security check: SMTP without TLS
                if !conversation_result
                    .discovered_capabilities
                    .iter()
                    .any(|cap| cap.contains("STARTTLS"))
                {
                    findings.push(Self::create_vulnerability_finding(
                        "SMTP Without TLS",
                        None,
                        "SMTP server does not advertise STARTTLS support. Communications may be unencrypted.",
                        Severity::Low,
                    ));
                }

                findings.push(finding);
            }
            Err(_) => {
                if matches!(port, 25 | 587 | 465) {
                    findings.push(Self::create_service_finding("SMTP", None, None));
                }
            }
        }

        findings
    }

    /// Extract version from HTTP server header
    fn extract_http_version(&self, header: &str) -> Option<String> {
        // Simple version extraction - could be enhanced with regex
        if let Some(start) = header.find('/') {
            if let Some(end) = header[start + 1..].find(' ') {
                return Some(header[start + 1..start + 1 + end].to_string());
            }
            // If no space found, take everything after the /
            return Some(header[start + 1..].to_string());
        }
        None
    }

    /// Extract version from SSH banner
    fn extract_ssh_version(&self, banner: &str) -> Option<String> {
        // SSH banner format: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        if let Some(parts) = banner.split_whitespace().next() {
            if let Some(version_part) = parts.strip_prefix("SSH-") {
                return Some(format!("SSH-{}", version_part));
            }
        }
        None
    }

    /// Extract version from FTP banner
    fn extract_ftp_version(&self, banner: &str) -> Option<String> {
        // FTP banners vary widely, try to extract meaningful version info
        let words: Vec<&str> = banner.split_whitespace().collect();
        if words.len() > 2 {
            return Some(words[1..3].join(" "));
        }
        None
    }

    /// Detect database services using shared database service
    async fn detect_database(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();
        let db_service = get_database_service().await;

        match db_service.detect_database(ip, port).await {
            Some(db_info) => {
                let version = db_info.version.as_deref();
                let mut finding = Self::create_service_finding(
                    &db_info.service_type,
                    version,
                    db_info.raw_banner.as_deref(),
                );

                // Add database-specific metadata
                finding
                    .metadata
                    .insert("database_type".to_string(), db_info.service_type.clone());
                finding.metadata.insert(
                    "authentication_required".to_string(),
                    db_info.authentication_required.to_string(),
                );
                finding.metadata.insert(
                    "handshake_steps".to_string(),
                    db_info.handshake_steps.to_string(),
                );

                if let Some(case_sensitive) = db_info.case_sensitive {
                    finding
                        .metadata
                        .insert("case_sensitive".to_string(), case_sensitive.to_string());
                }

                // Add protocol information
                for (key, value) in &db_info.additional_info {
                    finding
                        .metadata
                        .insert(format!("db_{}", key), value.clone());
                }

                // Security findings
                if db_info.anonymous_access_possible {
                    findings.push(Self::create_vulnerability_finding(
                        "Database Anonymous Access",
                        None,
                        &format!(
                            "{} allows anonymous access - potential security risk",
                            db_info.service_type
                        ),
                        Severity::High,
                    ));
                }

                // Check for insecure authentication methods
                if let Some(auth_method) = db_info.additional_info.get("auth_method") {
                    match auth_method.as_str() {
                        "trust" => {
                            findings.push(Self::create_vulnerability_finding(
                                "Insecure Database Authentication",
                                None,
                                &format!("{} configured with 'trust' authentication - no password required", db_info.service_type),
                                Severity::Critical,
                            ));
                        }
                        "cleartext" => {
                            findings.push(Self::create_vulnerability_finding(
                                "Cleartext Database Authentication",
                                None,
                                &format!(
                                    "{} uses cleartext password authentication",
                                    db_info.service_type
                                ),
                                Severity::Medium,
                            ));
                        }
                        _ => {}
                    }
                }

                findings.push(finding);
            }
            None => {
                // If we can't identify the specific database, but we're on a common database port,
                // still note that something is listening with type hint
                if db_service.is_database_port(port) {
                    let type_hint = db_service
                        .get_database_type_hint(port)
                        .unwrap_or("Unknown Database");
                    findings.push(Self::create_service_finding(
                        &format!("Database ({}?)", type_hint),
                        None,
                        None,
                    ));
                }
            }
        }

        findings
    }

    /// Detect RDP (Remote Desktop Protocol) service
    async fn detect_rdp(&self, ip: IpAddr, port: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Try to connect to the RDP port and analyze the response
        match tokio::net::TcpStream::connect((ip, port)).await {
            Ok(mut stream) => {
                // RDP connection request (simplified - just check if service responds)
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Send a basic RDP connection request
                let rdp_request = vec![
                    0x03, 0x00, 0x00, 0x13, // TPKT header
                    0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00,
                    0x00, 0x00,
                ];

                let mut response = vec![0u8; 1024];
                let connection_result = tokio::time::timeout(Duration::from_secs(5), async {
                    stream.write_all(&rdp_request).await?;
                    let bytes_read = stream.read(&mut response).await?;
                    Ok::<usize, std::io::Error>(bytes_read)
                })
                .await;

                match connection_result {
                    Ok(Ok(bytes_read)) if bytes_read > 0 => {
                        // Check if response looks like RDP
                        if response[0] == 0x03 && response[1] == 0x00 {
                            let mut finding = Self::create_service_finding("RDP", None, None);
                            finding.title =
                                "Service Detected: RDP (Remote Desktop Protocol)".to_string();
                            finding.description =
                                "Microsoft Remote Desktop Protocol service detected".to_string();
                            finding
                                .metadata
                                .insert("protocol".to_string(), "RDP".to_string());
                            finding
                                .metadata
                                .insert("standard_port".to_string(), "3389".to_string());

                            // Add security warning
                            if port == 3389 {
                                finding.metadata.insert("security_note".to_string(),
                                    "RDP exposed to network - ensure strong authentication and consider VPN".to_string());
                            }

                            findings.push(finding);
                        } else {
                            // Port is open but doesn't respond like RDP
                            findings.push(Self::create_service_finding(
                                "Unknown Service",
                                None,
                                None,
                            ));
                        }
                    }
                    _ => {
                        // Connection failed or no response - but port is open (from scan results)
                        findings.push(Self::create_service_finding("Filtered Service", None, None));
                    }
                }
            }
            Err(_) => {
                // Connection refused - this shouldn't happen if port scan showed it as open
                findings.push(Self::create_service_finding(
                    "Connection Failed",
                    None,
                    None,
                ));
            }
        }

        findings
    }
}

impl FindingBuilder for ServiceDetectionPlugin {}

#[async_trait]
impl Plugin for ServiceDetectionPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        "Identifies services running on open ports using banner grabbing and protocol analysis"
    }

    fn priority(&self) -> PluginPriority {
        PluginPriority::High // Service identification is high priority
    }

    fn can_analyze(&self, scan_result: &ScanResult) -> bool {
        // Only analyze open ports
        matches!(scan_result.status, PortStatus::Open)
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
        let mut all_findings = Vec::new();

        println!("🔍 Analyzing {}:{} for services...", target, port);

        // Determine service type based on port and run appropriate detection
        match port {
            22 => all_findings.extend(self.detect_ssh(target, port).await),
            21 => all_findings.extend(self.detect_ftp(target, port).await),
            25 | 587 | 465 => all_findings.extend(self.detect_smtp(target, port).await),
            80 | 8080 | 8000 | 8888 => all_findings.extend(self.detect_http(target, port).await),
            443 | 8443 => {
                all_findings.extend(self.detect_http(target, port).await);
                all_findings.extend(self.detect_tls_details(target, port).await);
            }
            // RDP port - Remote Desktop Protocol
            3389 => all_findings.extend(self.detect_rdp(target, port).await),
            // Database ports - use comprehensive database detection
            3306 | 3307 => all_findings.extend(self.detect_database(target, port).await),
            5432 | 5433 => all_findings.extend(self.detect_database(target, port).await),
            1433 | 1434 => all_findings.extend(self.detect_database(target, port).await),
            1521 | 1522 => all_findings.extend(self.detect_database(target, port).await),
            _ => {
                // For unknown ports, try multiple detection methods
                // Start with HTTP as it's most common
                let http_findings = self.detect_http(target, port).await;
                if !http_findings.is_empty() {
                    all_findings.extend(http_findings);
                } else {
                    // Try database detection as fallback - many databases run on custom ports
                    let db_findings = self.detect_database(target, port).await;
                    if !db_findings.is_empty() {
                        all_findings.extend(db_findings);
                    } else {
                        // Could add more generic detection here
                        all_findings.push(Self::create_service_finding("Unknown", None, None));
                    }
                }
            }
        }

        PluginResult {
            plugin_name: self.name().to_string(),
            target_ip: target,
            target_port: port,
            execution_time: start_time.elapsed(),
            success: true,
            error_message: None,
            findings: all_findings,
            raw_data: None,
        }
    }
}
