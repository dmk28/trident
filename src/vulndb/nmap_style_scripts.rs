use crate::plugins::plugin_trait::{Finding, Severity};

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseScript {
    pub name: String,
    pub description: String,
    pub author: String,
    pub categories: Vec<String>,
    pub ports: Vec<u16>,
    pub cves: Vec<String>,
    pub probes: Vec<VulnProbe>,
    pub severity: Severity,
    pub confidence_threshold: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnProbe {
    pub name: String,
    pub probe_type: ProbeType,
    pub payload: Option<String>,
    pub expected_response: Vec<String>,
    pub version_patterns: Vec<String>,
    pub confidence_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeType {
    BannerGrab,
    HttpRequest { method: String, path: String },
    CustomTcp { data: Vec<u8> },
    VersionCheck { service: String },
    AuthBypass,
    ExploitProbe,
}

pub struct NmapStyleEngine {
    scripts: HashMap<String, NseScript>,
    compiled_patterns: HashMap<String, Regex>,
}

impl NmapStyleEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            scripts: HashMap::new(),
            compiled_patterns: HashMap::new(),
        };
        engine.load_builtin_scripts();
        engine.compile_patterns();
        engine
    }

    fn load_builtin_scripts(&mut self) {
        // SSH Version Detection Scripts
        self.scripts.insert(
            "ssh-vuln-cve2016-0777".to_string(),
            NseScript {
                name: "ssh-vuln-cve2016-0777".to_string(),
                description: "Checks for OpenSSH client information leak vulnerability".to_string(),
                author: "Project Trident".to_string(),
                categories: vec!["vuln".to_string(), "safe".to_string()],
                ports: vec![22],
                cves: vec!["CVE-2016-0777".to_string()],
                probes: vec![VulnProbe {
                    name: "ssh_version_check".to_string(),
                    probe_type: ProbeType::BannerGrab,
                    payload: None,
                    expected_response: vec!["SSH-2.0-OpenSSH".to_string()],
                    version_patterns: vec![
                        r"OpenSSH_([5-7]\.[0-9]+)".to_string(),
                        r"OpenSSH_5\.[4-9]".to_string(),
                        r"OpenSSH_6\.".to_string(),
                        r"OpenSSH_7\.[0-1]".to_string(),
                    ],
                    confidence_score: 0.9,
                }],
                severity: Severity::Medium,
                confidence_threshold: 0.8,
            },
        );

        // Log4Shell Detection
        self.scripts.insert(
            "http-vuln-log4shell".to_string(),
            NseScript {
                name: "http-vuln-log4shell".to_string(),
                description: "Detects Log4j RCE vulnerability (Log4Shell)".to_string(),
                author: "Project Trident".to_string(),
                categories: vec!["vuln".to_string(), "intrusive".to_string()],
                ports: vec![80, 443, 8080, 8443],
                cves: vec!["CVE-2021-44228".to_string(), "CVE-2021-45046".to_string()],
                probes: vec![
                    VulnProbe {
                        name: "java_service_detection".to_string(),
                        probe_type: ProbeType::HttpRequest {
                            method: "GET".to_string(),
                            path: "/".to_string(),
                        },
                        payload: None,
                        expected_response: vec![
                            "Tomcat".to_string(),
                            "Jetty".to_string(),
                            "Spring".to_string(),
                        ],
                        version_patterns: vec![
                            r"Apache-Coyote".to_string(),
                            r"Tomcat/[0-9]".to_string(),
                            r"Jetty\([0-9]".to_string(),
                            r"Spring".to_string(),
                        ],
                        confidence_score: 0.8,
                    },
                    VulnProbe {
                        name: "log4j_header_test".to_string(),
                        probe_type: ProbeType::HttpRequest {
                            method: "GET".to_string(),
                            path: "/".to_string(),
                        },
                        payload: Some(
                            "X-Api-Version: ${jndi:ldap://detect.log4shell.com/test}".to_string(),
                        ),
                        expected_response: vec!["java".to_string(), "log4j".to_string()],
                        version_patterns: vec![],
                        confidence_score: 0.95,
                    },
                ],
                severity: Severity::Critical,
                confidence_threshold: 0.7,
            },
        );

        // SMB EternalBlue
        self.scripts.insert(
            "smb-vuln-ms17-010".to_string(),
            NseScript {
                name: "smb-vuln-ms17-010".to_string(),
                description: "Checks for EternalBlue SMB vulnerability".to_string(),
                author: "Project Trident".to_string(),
                categories: vec!["vuln".to_string(), "safe".to_string()],
                ports: vec![445, 139],
                cves: vec!["CVE-2017-0144".to_string()],
                probes: vec![VulnProbe {
                    name: "smb_dialect_check".to_string(),
                    probe_type: ProbeType::CustomTcp {
                        data: vec![
                            0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00,
                            0x00, 0x18, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
                            0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31,
                            0x2e, 0x30, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
                            0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66,
                            0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
                            0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e,
                            0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41,
                            0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20,
                            0x30, 0x2e, 0x31, 0x32, 0x00,
                        ],
                    },
                    payload: None,
                    expected_response: vec!["SMB".to_string(), "Windows".to_string()],
                    version_patterns: vec![
                        r"Windows.*Server.*2008".to_string(),
                        r"Windows.*Server.*2012".to_string(),
                        r"Windows.*7".to_string(),
                        r"Windows.*Vista".to_string(),
                    ],
                    confidence_score: 0.85,
                }],
                severity: Severity::Critical,
                confidence_threshold: 0.8,
            },
        );

        // Redis Unauthorized Access
        self.scripts.insert(
            "redis-info-unauth".to_string(),
            NseScript {
                name: "redis-info-unauth".to_string(),
                description: "Checks for Redis unauthorized access".to_string(),
                author: "Project Trident".to_string(),
                categories: vec!["vuln".to_string(), "auth".to_string()],
                ports: vec![6379],
                cves: vec!["CVE-2022-0543".to_string()],
                probes: vec![VulnProbe {
                    name: "redis_info_command".to_string(),
                    probe_type: ProbeType::CustomTcp {
                        data: b"INFO\r\n".to_vec(),
                    },
                    payload: None,
                    expected_response: vec!["redis_version".to_string(), "redis_mode".to_string()],
                    version_patterns: vec![r"redis_version:([5-6]\.[0-9]+\.[0-9]+)".to_string()],
                    confidence_score: 0.95,
                }],
                severity: Severity::High,
                confidence_threshold: 0.9,
            },
        );

        // HTTP Server Information Disclosure
        self.scripts.insert(
            "http-server-header".to_string(),
            NseScript {
                name: "http-server-header".to_string(),
                description: "Detects HTTP server information disclosure".to_string(),
                author: "Project Trident".to_string(),
                categories: vec!["discovery".to_string(), "safe".to_string()],
                ports: vec![80, 443, 8080, 8443],
                cves: vec![],
                probes: vec![VulnProbe {
                    name: "http_server_header".to_string(),
                    probe_type: ProbeType::HttpRequest {
                        method: "HEAD".to_string(),
                        path: "/".to_string(),
                    },
                    payload: None,
                    expected_response: vec!["Server:".to_string()],
                    version_patterns: vec![
                        r"Apache/([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
                        r"nginx/([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
                        r"Microsoft-IIS/([0-9]+\.[0-9]+)".to_string(),
                    ],
                    confidence_score: 0.8,
                }],
                severity: Severity::Low,
                confidence_threshold: 0.7,
            },
        );

        // FTP Anonymous Access
        self.scripts.insert(
            "ftp-anon".to_string(),
            NseScript {
                name: "ftp-anon".to_string(),
                description: "Checks for FTP anonymous login".to_string(),
                author: "Project Trident".to_string(),
                categories: vec!["auth".to_string(), "safe".to_string()],
                ports: vec![21],
                cves: vec![],
                probes: vec![VulnProbe {
                    name: "ftp_anonymous_login".to_string(),
                    probe_type: ProbeType::AuthBypass,
                    payload: Some("USER anonymous\r\nPASS anonymous@\r\n".to_string()),
                    expected_response: vec!["230".to_string(), "Login successful".to_string()],
                    version_patterns: vec![],
                    confidence_score: 0.9,
                }],
                severity: Severity::Medium,
                confidence_threshold: 0.85,
            },
        );
    }

    fn compile_patterns(&mut self) {
        for script in self.scripts.values() {
            for probe in &script.probes {
                for pattern in &probe.version_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        self.compiled_patterns.insert(pattern.clone(), regex);
                    }
                }
            }
        }
    }

    pub async fn run_script(
        &self,
        script_name: &str,
        target_ip: std::net::IpAddr,
        target_port: u16,
        banner: Option<&str>,
    ) -> Option<Finding> {
        if let Some(script) = self.scripts.get(script_name) {
            if script.ports.contains(&target_port) || script.ports.is_empty() {
                return self
                    .execute_script(script, target_ip, target_port, banner)
                    .await;
            }
        }
        None
    }

    pub async fn run_category_scripts(
        &self,
        category: &str,
        target_ip: std::net::IpAddr,
        target_port: u16,
        banner: Option<&str>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for script in self.scripts.values() {
            if script.categories.contains(&category.to_string())
                && (script.ports.contains(&target_port) || script.ports.is_empty())
            {
                if let Some(finding) = self
                    .execute_script(script, target_ip, target_port, banner)
                    .await
                {
                    findings.push(finding);
                }
            }
        }

        findings
    }

    async fn execute_script(
        &self,
        script: &NseScript,
        target_ip: std::net::IpAddr,
        target_port: u16,
        banner: Option<&str>,
    ) -> Option<Finding> {
        let mut total_confidence = 0.0f32;
        let mut evidence = Vec::new();
        let mut vulnerability_confirmed = false;

        for probe in &script.probes {
            if let Some(result) = self
                .execute_probe(probe, target_ip, target_port, banner)
                .await
            {
                total_confidence += result.confidence;
                evidence.extend(result.evidence);
                if result.vulnerability_detected {
                    vulnerability_confirmed = true;
                }
            }
        }

        let average_confidence = if script.probes.is_empty() {
            0.0
        } else {
            total_confidence / script.probes.len() as f32
        };

        if vulnerability_confirmed && average_confidence >= script.confidence_threshold {
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("script_name".to_string(), script.name.clone());
            metadata.insert("categories".to_string(), script.categories.join(","));
            if !script.cves.is_empty() {
                metadata.insert("cve_ids".to_string(), script.cves.join(","));
            }

            Some(Finding {
                title: script.name.clone(),
                description: script.description.clone(),
                severity: script.severity.clone(),
                confidence: average_confidence,
                evidence,
                recommendations: self.get_recommendations_for_script(script),
                references: script
                    .cves
                    .iter()
                    .map(|cve| format!("https://nvd.nist.gov/vuln/detail/{}", cve))
                    .collect(),
                metadata,
            })
        } else {
            None
        }
    }

    async fn execute_probe(
        &self,
        probe: &VulnProbe,
        target_ip: std::net::IpAddr,
        target_port: u16,
        banner: Option<&str>,
    ) -> Option<ProbeResult> {
        match &probe.probe_type {
            ProbeType::BannerGrab => {
                if let Some(banner_text) = banner {
                    return Some(self.analyze_banner(probe, banner_text));
                }
            }
            ProbeType::HttpRequest { method, path } => {
                return self
                    .execute_http_probe(probe, target_ip, target_port, method, path)
                    .await;
            }
            ProbeType::CustomTcp { data } => {
                return self
                    .execute_tcp_probe(probe, target_ip, target_port, data)
                    .await;
            }
            ProbeType::VersionCheck { service: _ } => {
                if let Some(banner_text) = banner {
                    return Some(self.analyze_version_patterns(probe, banner_text));
                }
            }
            ProbeType::AuthBypass => {
                return self
                    .execute_auth_bypass(probe, target_ip, target_port)
                    .await;
            }
            ProbeType::ExploitProbe => {
                // Implement exploit probes with extreme caution
                return None; // Disabled for safety
            }
        }
        None
    }

    fn analyze_banner(&self, probe: &VulnProbe, banner: &str) -> ProbeResult {
        let mut confidence = 0.0f32;
        let mut evidence = Vec::new();
        let mut vulnerability_detected = false;

        // Check expected responses
        for expected in &probe.expected_response {
            if banner.contains(expected) {
                confidence += 0.3f32;
                evidence.push(format!("Banner contains expected pattern: {}", expected));
                vulnerability_detected = true;
            }
        }

        // Check version patterns
        for pattern in &probe.version_patterns {
            if let Some(regex) = self.compiled_patterns.get(pattern) {
                if regex.is_match(banner) {
                    confidence += 0.4;
                    evidence.push(format!("Version pattern matched: {}", pattern));
                    vulnerability_detected = true;
                }
            }
        }

        ProbeResult {
            confidence: confidence.min(probe.confidence_score),
            evidence,
            vulnerability_detected,
        }
    }

    fn analyze_version_patterns(&self, probe: &VulnProbe, banner: &str) -> ProbeResult {
        let mut confidence = 0.0f32;
        let mut evidence = Vec::new();

        for pattern in &probe.version_patterns {
            if let Some(regex) = self.compiled_patterns.get(pattern) {
                if let Some(captures) = regex.captures(banner) {
                    confidence = probe.confidence_score;
                    evidence.push(format!(
                        "Vulnerable version detected: {}",
                        captures.get(0).unwrap().as_str()
                    ));
                    return ProbeResult {
                        confidence,
                        evidence,
                        vulnerability_detected: true,
                    };
                }
            }
        }

        ProbeResult {
            confidence: 0.0,
            evidence,
            vulnerability_detected: false,
        }
    }

    async fn execute_http_probe(
        &self,
        probe: &VulnProbe,
        target_ip: std::net::IpAddr,
        target_port: u16,
        method: &str,
        path: &str,
    ) -> Option<ProbeResult> {
        if let Ok(Ok(mut stream)) = timeout(
            Duration::from_secs(5),
            TcpStream::connect((target_ip, target_port)),
        )
        .await
        {
            let request = if let Some(payload) = &probe.payload {
                format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\n{}\r\nConnection: close\r\n\r\n",
                    method, path, target_ip, payload
                )
            } else {
                format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    method, path, target_ip
                )
            };

            if stream.write_all(request.as_bytes()).await.is_ok() {
                let mut buffer = vec![0; 4096];
                if let Ok(bytes_read) = stream.read(&mut buffer).await {
                    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                    return Some(self.analyze_http_response(probe, &response));
                }
            }
        }
        None
    }

    fn analyze_http_response(&self, probe: &VulnProbe, response: &str) -> ProbeResult {
        let mut confidence = 0.0f32;
        let mut evidence = Vec::new();
        let mut vulnerability_detected = false;

        for expected in &probe.expected_response {
            if response.to_lowercase().contains(&expected.to_lowercase()) {
                confidence += 0.4f32;
                evidence.push(format!("HTTP response contains: {}", expected));
                vulnerability_detected = true;
            }
        }

        // Check for version patterns in headers
        for pattern in &probe.version_patterns {
            if let Some(regex) = self.compiled_patterns.get(pattern) {
                if regex.is_match(response) {
                    confidence += 0.5;
                    evidence.push(format!(
                        "Version pattern found in HTTP response: {}",
                        pattern
                    ));
                    vulnerability_detected = true;
                }
            }
        }

        ProbeResult {
            confidence: confidence.min(probe.confidence_score),
            evidence,
            vulnerability_detected,
        }
    }

    async fn execute_tcp_probe(
        &self,
        probe: &VulnProbe,
        target_ip: std::net::IpAddr,
        target_port: u16,
        data: &[u8],
    ) -> Option<ProbeResult> {
        if let Ok(Ok(mut stream)) = timeout(
            Duration::from_secs(5),
            TcpStream::connect((target_ip, target_port)),
        )
        .await
        {
            if stream.write_all(data).await.is_ok() {
                let mut buffer = vec![0; 4096];
                if let Ok(bytes_read) = stream.read(&mut buffer).await {
                    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                    return Some(self.analyze_tcp_response(probe, &response));
                }
            }
        }
        None
    }

    fn analyze_tcp_response(&self, probe: &VulnProbe, response: &str) -> ProbeResult {
        let mut confidence = 0.0f32;
        let mut evidence = Vec::new();
        let mut vulnerability_detected = false;

        for expected in &probe.expected_response {
            if response.contains(expected) {
                confidence += 0.5f32;
                evidence.push(format!("TCP response contains expected data: {}", expected));
                vulnerability_detected = true;
            }
        }

        ProbeResult {
            confidence: confidence.min(probe.confidence_score),
            evidence,
            vulnerability_detected,
        }
    }

    async fn execute_auth_bypass(
        &self,
        probe: &VulnProbe,
        target_ip: std::net::IpAddr,
        target_port: u16,
    ) -> Option<ProbeResult> {
        if let Some(payload) = &probe.payload {
            if let Ok(Ok(mut stream)) = timeout(
                Duration::from_secs(10),
                TcpStream::connect((target_ip, target_port)),
            )
            .await
            {
                if stream.write_all(payload.as_bytes()).await.is_ok() {
                    let mut buffer = vec![0; 2048];
                    if let Ok(bytes_read) = stream.read(&mut buffer).await {
                        let response = String::from_utf8_lossy(&buffer[..bytes_read]);

                        for expected in &probe.expected_response {
                            if response.contains(expected) {
                                return Some(ProbeResult {
                                    confidence: probe.confidence_score,
                                    evidence: vec![format!(
                                        "Authentication bypass successful: {}",
                                        expected
                                    )],
                                    vulnerability_detected: true,
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn get_recommendations_for_script(&self, script: &NseScript) -> Vec<String> {
        match script.name.as_str() {
            "ssh-vuln-cve2016-0777" => vec![
                "Update OpenSSH to version 7.1p2 or later".to_string(),
                "Configure SSH client settings to prevent information leaks".to_string(),
            ],
            "http-vuln-log4shell" => vec![
                "IMMEDIATELY update Log4j to version 2.17.1 or later".to_string(),
                "Implement WAF rules to block JNDI lookup attempts".to_string(),
                "Monitor logs for exploitation attempts".to_string(),
            ],
            "smb-vuln-ms17-010" => vec![
                "Apply Microsoft security update MS17-010".to_string(),
                "Disable SMBv1 protocol".to_string(),
                "Enable network segmentation".to_string(),
            ],
            "redis-info-unauth" => vec![
                "Configure Redis authentication with requirepass".to_string(),
                "Bind Redis to localhost only".to_string(),
                "Use firewall to restrict access".to_string(),
            ],
            _ => vec![
                "Review service configuration".to_string(),
                "Apply security updates".to_string(),
                "Follow security best practices".to_string(),
            ],
        }
    }

    pub fn get_script_names_by_category(&self, category: &str) -> Vec<String> {
        self.scripts
            .values()
            .filter(|script| script.categories.contains(&category.to_string()))
            .map(|script| script.name.clone())
            .collect()
    }

    pub fn get_all_categories(&self) -> Vec<String> {
        let mut categories = std::collections::HashSet::new();
        for script in self.scripts.values() {
            for category in &script.categories {
                categories.insert(category.clone());
            }
        }
        categories.into_iter().collect()
    }
}

#[derive(Debug)]
struct ProbeResult {
    confidence: f32,
    evidence: Vec<String>,
    vulnerability_detected: bool,
}

impl Default for NmapStyleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_script_loading() {
        let engine = NmapStyleEngine::new();
        assert!(!engine.scripts.is_empty());
        assert!(engine.scripts.contains_key("ssh-vuln-cve2016-0777"));
    }

    #[test]
    fn test_version_pattern_matching() {
        let engine = NmapStyleEngine::new();
        let script = engine.scripts.get("ssh-vuln-cve2016-0777").unwrap();
        let probe = &script.probes[0];

        let banner = "SSH-2.0-OpenSSH_6.6";
        let result = engine.analyze_banner(probe, banner);

        assert!(result.vulnerability_detected);
        assert!(result.confidence > 0.0);
    }
}
