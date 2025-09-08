use crate::plugins::plugin_trait::Severity;
use regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

use tokio::time::{Duration, timeout};
extern crate flate2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub cve_id: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub affected_services: Vec<String>,
    pub affected_versions: Vec<String>,
    pub ports: Vec<u16>,
    pub references: Vec<String>,
    pub exploitable: bool,
    pub patch_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceVulnerability {
    pub service_name: String,
    pub version_pattern: String,
    pub cves: Vec<Cve>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMatch {
    pub cve_id: String,
    pub summary: String,
    pub explanation: String, // 140 characters max
    pub reference_url: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub matched_service: String,
    pub matched_version: String,
    pub confidence: f32,
}

#[derive(Debug, Deserialize)]
pub struct GitHubCveEntry {
    #[serde(rename = "cveMetadata")]
    pub cve_metadata: CveMetadata,
    pub containers: CveContainers,
}

#[derive(Debug, Deserialize)]
pub struct CveMetadata {
    #[serde(rename = "cveId")]
    pub cve_id: String,
    #[serde(rename = "assignerShortName")]
    pub assigner: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CveContainers {
    pub cna: Option<CnaContainer>,
}

#[derive(Debug, Deserialize)]
pub struct CnaContainer {
    pub descriptions: Option<Vec<CveDescription>>,
    pub metrics: Option<Vec<CveMetric>>,
    pub affected: Option<Vec<AffectedProduct>>,
    pub references: Option<Vec<CveReference>>,
}

#[derive(Debug, Deserialize)]
pub struct CveDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct CveMetric {
    #[serde(rename = "cvssV3_1")]
    pub cvss_v3_1: Option<CvssV31>,
}

#[derive(Debug, Deserialize)]
pub struct CvssV31 {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

#[derive(Debug, Deserialize)]
pub struct AffectedProduct {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub versions: Option<Vec<ProductVersion>>,
}

#[derive(Debug, Deserialize)]
pub struct ProductVersion {
    pub version: String,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CveReference {
    pub url: String,
}

/// Compressed CVE database format for storage efficiency
#[derive(Serialize, Deserialize)]
pub struct CompactCveDatabase {
    pub cves: Vec<CompactCveEntry>,
    pub service_patterns: std::collections::HashMap<String, Vec<String>>,
    pub last_updated: u64,
}

#[derive(Serialize, Deserialize)]
pub struct CompactCveEntry {
    pub id: String,
    pub score: f32,
    pub severity: u8, // 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    pub services: Vec<String>,
    pub versions: Vec<String>,
    pub ports: Vec<u16>,
    pub exploitable: bool,
}

pub struct CveDatabase {
    pub cves: HashMap<String, Cve>,
    pub service_vulns: HashMap<String, Vec<ServiceVulnerability>>,
    pub client: Client,
    pub cache_dir: String,
}
impl CveDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            cves: HashMap::new(),
            service_vulns: HashMap::new(),
            client: Client::new(),
            cache_dir: "cve_cache".to_string(),
        };
        db.load_known_cves();
        db
    }

    pub async fn fetch_cve_from_github(
        &self,
        cve_id: &str,
    ) -> Result<Option<Cve>, Box<dyn std::error::Error>> {
        let year = &cve_id[4..8]; // Extract year from CVE-YYYY-NNNNN
        let url = format!(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{}/{}/{}.json",
            year,
            &cve_id[9..12], // First 3 digits of CVE number for directory structure
            cve_id
        );

        let response = timeout(Duration::from_secs(10), self.client.get(&url).send()).await??;

        if response.status().is_success() {
            let github_cve: GitHubCveEntry = response.json().await?;
            Ok(Some(self.convert_github_cve_to_entry(github_cve)))
        } else {
            Ok(None)
        }
    }

    pub async fn fetch_critical_cves_batch(
        &mut self,
        cve_ids: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "🔄 Fetching {} CVEs from GitHub repository...",
            cve_ids.len()
        );

        let mut successful = 0;
        let mut failed = 0;

        for cve_id in cve_ids {
            match self.fetch_cve_from_github(cve_id).await {
                Ok(Some(cve_entry)) => {
                    self.cves.insert(cve_id.to_string(), cve_entry);
                    successful += 1;
                }
                Ok(None) => {
                    println!("⚠️  CVE not found: {}", cve_id);
                    failed += 1;
                }
                Err(e) => {
                    println!("❌ Failed to fetch {}: {}", cve_id, e);
                    failed += 1;
                }
            }
        }

        println!(
            "✅ Successfully fetched {} CVEs, {} failed",
            successful, failed
        );
        Ok(())
    }

    fn convert_github_cve_to_entry(&self, github_entry: GitHubCveEntry) -> Cve {
        let description = github_entry
            .containers
            .cna
            .as_ref()
            .and_then(|cna| cna.descriptions.as_ref())
            .and_then(|descs| descs.iter().find(|d| d.lang == "en"))
            .map(|d| d.value.clone())
            .unwrap_or_else(|| "No description available".to_string());

        let (cvss_score, severity) = github_entry
            .containers
            .cna
            .as_ref()
            .and_then(|cna| cna.metrics.as_ref())
            .and_then(|metrics| metrics.first())
            .and_then(|metric| metric.cvss_v3_1.as_ref())
            .map(|cvss| {
                let score = cvss.base_score;
                let severity = match cvss.base_severity.as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MEDIUM" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Info,
                };
                (score, severity)
            })
            .unwrap_or((0.0, Severity::Info));

        let affected_services: Vec<String> = github_entry
            .containers
            .cna
            .as_ref()
            .and_then(|cna| cna.affected.as_ref())
            .map(|affected| {
                affected
                    .iter()
                    .filter_map(|product| product.product.clone())
                    .collect()
            })
            .unwrap_or_default();

        let affected_versions: Vec<String> = github_entry
            .containers
            .cna
            .as_ref()
            .and_then(|cna| cna.affected.as_ref())
            .map(|affected| {
                affected
                    .iter()
                    .filter_map(|product| product.versions.as_ref())
                    .flatten()
                    .map(|v| v.version.clone())
                    .collect()
            })
            .unwrap_or_default();

        let references: Vec<String> = github_entry
            .containers
            .cna
            .as_ref()
            .and_then(|cna| cna.references.as_ref())
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default();

        let ports = self.guess_ports_from_services(&affected_services);

        Cve {
            cve_id: github_entry.cve_metadata.cve_id,
            description,
            severity,
            cvss_score,
            affected_services,
            affected_versions,
            ports,
            references,
            exploitable: cvss_score >= 7.0, // Heuristic: High/Critical scores are likely exploitable
            patch_available: true,          // Assume patches are available for published CVEs
        }
    }

    fn guess_ports_from_services(&self, services: &[String]) -> Vec<u16> {
        let mut ports = Vec::new();

        for service in services {
            let service_lower = service.to_lowercase();
            match service_lower.as_str() {
                s if s.contains("apache") || s.contains("httpd") => {
                    ports.extend(&[80, 443, 8080, 8443]);
                }
                s if s.contains("nginx") => {
                    ports.extend(&[80, 443, 8080, 8443]);
                }
                s if s.contains("mysql") => {
                    ports.push(3306);
                }
                s if s.contains("postgresql") || s.contains("postgres") => {
                    ports.push(5432);
                }
                s if s.contains("redis") => {
                    ports.push(6379);
                }
                s if s.contains("ssh") || s.contains("openssh") => {
                    ports.push(22);
                }
                s if s.contains("ftp") => {
                    ports.push(21);
                }
                s if s.contains("telnet") => {
                    ports.push(23);
                }
                s if s.contains("smtp") => {
                    ports.push(25);
                }
                s if s.contains("dns") => {
                    ports.push(53);
                }
                s if s.contains("snmp") => {
                    ports.extend(&[161, 162]);
                }
                s if s.contains("smb") || s.contains("samba") => {
                    ports.extend(&[139, 445]);
                }
                _ => {} // Unknown service, no port mapping
            }
        }

        ports.sort();
        ports.dedup();
        ports
    }

    pub async fn update_with_latest_cves(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Fetch some of the most critical CVEs from recent years
        let critical_cves = [
            "CVE-2021-44228", // Log4Shell
            "CVE-2021-45046", // Log4Shell follow-up
            "CVE-2017-0144",  // EternalBlue
            "CVE-2020-1472",  // Zerologon
            "CVE-2021-34527", // PrintNightmare
            "CVE-2019-0708",  // BlueKeep
            "CVE-2022-0543",  // Redis Lua injection
            "CVE-2021-26855", // Exchange ProxyLogon
            "CVE-2020-14882", // Oracle WebLogic
            "CVE-2021-40444", // MSHTML RCE
        ];

        self.fetch_critical_cves_batch(&critical_cves).await?;
        Ok(())
    }

    /// Compressed CVE storage for efficiency - stores only essential data
    pub fn compress_cve_database(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        println!("🗜️ Compressing CVE database...");

        // Create a compact representation
        let compact_data = self.create_compact_cve_data();
        let serialized = serde_json::to_vec(&compact_data)?;

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&serialized)?;
        let compressed = encoder.finish()?;

        println!(
            "✅ Compression: {} bytes → {} bytes ({:.1}% reduction)",
            serialized.len(),
            compressed.len(),
            (1.0 - compressed.len() as f64 / serialized.len() as f64) * 100.0
        );

        Ok(compressed)
    }

    fn create_compact_cve_data(&self) -> CompactCveDatabase {
        let mut compact_cves = Vec::new();

        for (_id, cve) in &self.cves {
            // Only include network-relevant CVEs with high impact
            if self.is_network_relevant(cve) && cve.cvss_score >= 7.0 {
                compact_cves.push(CompactCveEntry {
                    id: cve.cve_id.clone(),
                    score: cve.cvss_score,
                    severity: match cve.severity {
                        Severity::Critical => 4,
                        Severity::High => 3,
                        Severity::Medium => 2,
                        Severity::Low => 1,
                        Severity::Info => 0,
                    },
                    services: cve.affected_services.clone(),
                    versions: cve.affected_versions.clone(),
                    ports: cve.ports.clone(),
                    exploitable: cve.exploitable,
                });
            }
        }

        CompactCveDatabase {
            cves: compact_cves,
            service_patterns: self.create_service_patterns(),
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn is_network_relevant(&self, cve: &Cve) -> bool {
        // Filter for network services only
        let network_services = [
            "http",
            "https",
            "ssh",
            "ftp",
            "telnet",
            "smtp",
            "dns",
            "snmp",
            "mysql",
            "postgresql",
            "redis",
            "apache",
            "nginx",
            "tomcat",
            "iis",
            "exchange",
            "smb",
            "rdp",
            "vnc",
            "ldap",
        ];

        cve.affected_services.iter().any(|service| {
            let service_lower = service.to_lowercase();
            network_services.iter().any(|ns| service_lower.contains(ns))
        }) || !cve.ports.is_empty()
    }

    fn create_service_patterns(&self) -> std::collections::HashMap<String, Vec<String>> {
        let mut patterns = std::collections::HashMap::new();

        // Common service detection patterns
        patterns.insert(
            "apache".to_string(),
            vec!["Apache/".to_string(), "httpd".to_string()],
        );

        patterns.insert(
            "nginx".to_string(),
            vec!["nginx/".to_string(), "nginx".to_string()],
        );

        patterns.insert(
            "ssh".to_string(),
            vec!["OpenSSH".to_string(), "SSH-".to_string()],
        );

        patterns.insert(
            "mysql".to_string(),
            vec!["MySQL".to_string(), "mysql".to_string()],
        );

        patterns.insert(
            "redis".to_string(),
            vec!["Redis".to_string(), "redis_version".to_string()],
        );

        patterns
    }

    /// Load compressed CVE database
    pub fn load_compressed_database(
        &mut self,
        compressed_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        println!("📂 Loading compressed CVE database...");

        // Decompress
        let mut decoder = GzDecoder::new(compressed_data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        // Deserialize
        let compact_db: CompactCveDatabase = serde_json::from_slice(&decompressed)?;

        // Convert back to full format
        self.cves.clear();
        for compact_cve in compact_db.cves {
            let full_cve = Cve {
                cve_id: compact_cve.id.clone(),
                description: format!("CVE {} (Score: {:.1})", compact_cve.id, compact_cve.score),
                severity: match compact_cve.severity {
                    4 => Severity::Critical,
                    3 => Severity::High,
                    2 => Severity::Medium,
                    1 => Severity::Low,
                    _ => Severity::Info,
                },
                cvss_score: compact_cve.score,
                affected_services: compact_cve.services,
                affected_versions: compact_cve.versions,
                ports: compact_cve.ports,
                references: vec![format!(
                    "https://nvd.nist.gov/vuln/detail/{}",
                    compact_cve.id
                )],
                exploitable: compact_cve.exploitable,
                patch_available: true,
            };

            self.cves.insert(compact_cve.id, full_cve);
        }

        println!(
            "✅ Loaded {} CVEs from compressed database",
            self.cves.len()
        );
        Ok(())
    }

    /// Nmap-style version matching for enhanced accuracy
    pub fn match_service_version(
        &self,
        service: &str,
        version: &str,
        banner: Option<&str>,
    ) -> Vec<&Cve> {
        let mut matches = Vec::new();

        for (_id, cve) in &self.cves {
            if self.service_version_matches(cve, service, version, banner) {
                matches.push(cve);
            }
        }

        // Sort by CVSS score (highest first)
        matches.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }

    fn service_version_matches(
        &self,
        cve: &Cve,
        service: &str,
        version: &str,
        banner: Option<&str>,
    ) -> bool {
        // Service name matching
        let service_match = cve.affected_services.iter().any(|cve_service| {
            let cve_service_lower = cve_service.to_lowercase();
            let service_lower = service.to_lowercase();
            cve_service_lower.contains(&service_lower) || service_lower.contains(&cve_service_lower)
        });

        if !service_match {
            return false;
        }

        // Version matching - simplified semantic version comparison
        if !cve.affected_versions.is_empty() {
            let version_match = cve
                .affected_versions
                .iter()
                .any(|cve_version| self.version_is_vulnerable(version, cve_version));

            if !version_match {
                return false;
            }
        }

        // Banner matching for additional confidence
        if let Some(banner_text) = banner {
            let banner_lower = banner_text.to_lowercase();
            let service_in_banner = cve
                .affected_services
                .iter()
                .any(|svc| banner_lower.contains(&svc.to_lowercase()));

            return service_in_banner;
        }

        true
    }

    fn version_is_vulnerable(&self, detected_version: &str, vulnerable_version: &str) -> bool {
        // Simple version matching - in production, use proper semver comparison
        if detected_version.contains(vulnerable_version) {
            return true;
        }

        // Extract version numbers for comparison
        let detected_nums = self.extract_version_numbers(detected_version);
        let vulnerable_nums = self.extract_version_numbers(vulnerable_version);

        if detected_nums.is_empty() || vulnerable_nums.is_empty() {
            return false;
        }

        // Simple major.minor comparison
        detected_nums[0] == vulnerable_nums[0]
            && (detected_nums.len() == 1
                || vulnerable_nums.len() == 1
                || detected_nums[1] <= vulnerable_nums.get(1).copied().unwrap_or(999))
    }

    fn extract_version_numbers(&self, version_str: &str) -> Vec<u32> {
        version_str
            .split(&['.', '-', '_', ' '][..])
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    fn load_known_cves(&mut self) {
        // SSH Vulnerabilities
        let ssh_cves = vec![
            Cve {
                cve_id: "CVE-2016-0777".to_string(),
                description: "OpenSSH client information leak vulnerability".to_string(),
                severity: Severity::Medium,
                cvss_score: 5.3,
                affected_services: vec!["openssh".to_string()],
                affected_versions: vec!["5.4".to_string(), "7.1".to_string()],
                ports: vec![22],
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2016-0777".to_string(),
                    "https://www.openssh.com/txt/release-7.1p2".to_string(),
                ],
                exploitable: true,
                patch_available: true,
            },
            Cve {
                cve_id: "CVE-2020-14145".to_string(),
                description: "OpenSSH observable discrepancy leading to an information leak"
                    .to_string(),
                severity: Severity::Medium,
                cvss_score: 5.9,
                affected_services: vec!["openssh".to_string()],
                affected_versions: vec!["6.2".to_string(), "8.2".to_string()],
                ports: vec![22],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-14145".to_string()],
                exploitable: false,
                patch_available: true,
            },
        ];

        // Apache HTTP Server Vulnerabilities
        let apache_cves = vec![
            Cve {
                cve_id: "CVE-2021-44228".to_string(),
                description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell)".to_string(),
                severity: Severity::Critical,
                cvss_score: 10.0,
                affected_services: vec!["apache".to_string(), "tomcat".to_string(), "java".to_string()],
                affected_versions: vec!["2.0-beta9".to_string(), "2.15.0".to_string()],
                ports: vec![80, 443, 8080, 8443],
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string(),
                    "https://logging.apache.org/log4j/2.x/security.html".to_string(),
                ],
                exploitable: true,
                patch_available: true,
            },
            Cve {
                cve_id: "CVE-2022-22963".to_string(),
                description: "Spring Cloud Function SpEL Code Injection".to_string(),
                severity: Severity::Critical,
                cvss_score: 9.8,
                affected_services: vec!["spring".to_string(), "java".to_string()],
                affected_versions: vec!["3.1.6".to_string(), "3.2.2".to_string()],
                ports: vec![80, 443, 8080, 8443],
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22963".to_string(),
                ],
                exploitable: true,
                patch_available: true,
            },
        ];

        // MySQL Vulnerabilities
        let mysql_cves = vec![Cve {
            cve_id: "CVE-2021-2154".to_string(),
            description: "MySQL Server DML unspecified vulnerability".to_string(),
            severity: Severity::Medium,
            cvss_score: 4.9,
            affected_services: vec!["mysql".to_string()],
            affected_versions: vec!["5.7.33".to_string(), "8.0.23".to_string()],
            ports: vec![3306],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-2154".to_string()],
            exploitable: false,
            patch_available: true,
        }];

        // SMB/Windows Vulnerabilities
        let smb_cves = vec![Cve {
            cve_id: "CVE-2017-0144".to_string(),
            description: "Microsoft SMBv1 Server remote code execution vulnerability (EternalBlue)"
                .to_string(),
            severity: Severity::Critical,
            cvss_score: 9.3,
            affected_services: vec!["smb".to_string(), "microsoft-ds".to_string()],
            affected_versions: vec!["Windows Vista".to_string(), "Windows 10".to_string()],
            ports: vec![445, 139],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144".to_string(),
                "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
                    .to_string(),
            ],
            exploitable: true,
            patch_available: true,
        }];

        // Redis Vulnerabilities
        let redis_cves = vec![Cve {
            cve_id: "CVE-2022-0543".to_string(),
            description: "Redis Lua library command injection vulnerability".to_string(),
            severity: Severity::Critical,
            cvss_score: 10.0,
            affected_services: vec!["redis".to_string()],
            affected_versions: vec!["5.0.0".to_string(), "6.2.6".to_string()],
            ports: vec![6379],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-0543".to_string()],
            exploitable: true,
            patch_available: true,
        }];

        // FTP Vulnerabilities
        let ftp_cves = vec![Cve {
            cve_id: "CVE-2020-8277".to_string(),
            description:
                "Pure-FTPd before 1.0.50 allows remote attackers to cause a denial of service"
                    .to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            affected_services: vec!["pure-ftpd".to_string(), "ftp".to_string()],
            affected_versions: vec!["1.0.49".to_string()],
            ports: vec![21],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-8277".to_string()],
            exploitable: true,
            patch_available: true,
        }];

        // Store CVEs by ID
        for cve_list in [
            &ssh_cves,
            &apache_cves,
            &mysql_cves,
            &smb_cves,
            &redis_cves,
            &ftp_cves,
        ] {
            for cve in cve_list {
                self.cves.insert(cve.cve_id.clone(), cve.clone());
            }
        }

        // Create service vulnerability mappings
        self.service_vulns.insert(
            "ssh".to_string(),
            vec![ServiceVulnerability {
                service_name: "openssh".to_string(),
                version_pattern: r"OpenSSH_([5-7]\.[0-9]+)".to_string(),
                cves: ssh_cves,
            }],
        );

        self.service_vulns.insert(
            "http".to_string(),
            vec![
                ServiceVulnerability {
                    service_name: "apache".to_string(),
                    version_pattern: r"Apache/([0-9]+\.[0-9]+\.[0-9]+)".to_string(),
                    cves: apache_cves.clone(),
                },
                ServiceVulnerability {
                    service_name: "spring".to_string(),
                    version_pattern: r"Spring.*([3]\.[0-9]+\.[0-9]+)".to_string(),
                    cves: apache_cves,
                },
            ],
        );

        self.service_vulns.insert(
            "mysql".to_string(),
            vec![ServiceVulnerability {
                service_name: "mysql".to_string(),
                version_pattern: r"MySQL.*([5-8]\.[0-9]+\.[0-9]+)".to_string(),
                cves: mysql_cves,
            }],
        );

        self.service_vulns.insert(
            "smb".to_string(),
            vec![ServiceVulnerability {
                service_name: "microsoft-ds".to_string(),
                version_pattern: r"Microsoft Windows.*".to_string(),
                cves: smb_cves,
            }],
        );

        self.service_vulns.insert(
            "redis".to_string(),
            vec![ServiceVulnerability {
                service_name: "redis".to_string(),
                version_pattern: r"Redis.*([5-6]\.[0-9]+\.[0-9]+)".to_string(),
                cves: redis_cves,
            }],
        );

        self.service_vulns.insert(
            "ftp".to_string(),
            vec![ServiceVulnerability {
                service_name: "pure-ftpd".to_string(),
                version_pattern: r"Pure-FTPd.*([1]\.[0]\.[0-9]+)".to_string(),
                cves: ftp_cves,
            }],
        );
    }

    pub fn get_cve(&self, cve_id: &str) -> Option<&Cve> {
        self.cves.get(cve_id)
    }

    pub fn get_service_vulnerabilities(&self, service: &str) -> Option<&Vec<ServiceVulnerability>> {
        self.service_vulns.get(service)
    }

    pub fn search_by_service_and_version(&self, service: &str, version: &str) -> Vec<&Cve> {
        let mut results = Vec::new();

        if let Some(service_vulns) = self.get_service_vulnerabilities(service) {
            for service_vuln in service_vulns {
                // Simple version matching - in production you'd want more sophisticated version comparison
                for cve in &service_vuln.cves {
                    if cve.affected_versions.iter().any(|v| version.contains(v)) {
                        results.push(cve);
                    }
                }
            }
        }

        results
    }

    pub fn get_critical_cves(&self) -> Vec<&Cve> {
        self.cves
            .values()
            .filter(|cve| matches!(cve.severity, Severity::Critical))
            .collect()
    }

    pub fn get_exploitable_cves(&self) -> Vec<&Cve> {
        self.cves.values().filter(|cve| cve.exploitable).collect()
    }

    pub async fn initialize_with_github_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🌐 Initializing CVE database with GitHub data...");
        self.update_with_latest_cves().await?;
        println!(
            "🎯 CVE database initialized with {} entries",
            self.cves.len()
        );
        Ok(())
    }

    pub async fn batch_process_github_cves(
        &mut self,
        year_range: std::ops::Range<u16>,
        severity_filter: Option<Severity>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "🔄 Processing GitHub CVE database for years {:?}...",
            year_range
        );

        let mut total_processed = 0;
        let mut total_added = 0;

        for year in year_range {
            let year_cves = self
                .fetch_cves_for_year(year, severity_filter.clone())
                .await?;
            total_processed += year_cves.len();

            for cve in year_cves {
                if self.is_relevant_cve(&cve) {
                    self.cves.insert(cve.cve_id.clone(), cve);
                    total_added += 1;
                }
            }

            println!("✅ Processed {} CVEs for year {}", total_processed, year);
        }

        println!(
            "🎯 Batch processing complete: {} CVEs processed, {} relevant CVEs added",
            total_processed, total_added
        );
        Ok(())
    }

    async fn fetch_cves_for_year(
        &self,
        year: u16,
        severity_filter: Option<Severity>,
    ) -> Result<Vec<Cve>, Box<dyn std::error::Error>> {
        let mut cves = Vec::new();

        // Fetch directory listing for the year
        let dir_url = format!(
            "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves/{}",
            year
        );

        let response = timeout(Duration::from_secs(30), self.client.get(&dir_url).send()).await??;

        if response.status().is_success() {
            // Parse directory structure and fetch relevant CVEs
            // This is a simplified version - in practice you'd paginate through all CVEs
            let sample_cve_ids = self.get_high_impact_cves_for_year(year);

            for cve_id in sample_cve_ids {
                if let Ok(Some(cve)) = self.fetch_cve_from_github(&cve_id).await {
                    if severity_filter.is_none() || Some(cve.severity.clone()) == severity_filter {
                        cves.push(cve);
                    }
                }
            }
        }

        Ok(cves)
    }

    fn get_high_impact_cves_for_year(&self, year: u16) -> Vec<String> {
        match year {
            2021 => vec![
                "CVE-2021-44228".to_string(), // Log4Shell
                "CVE-2021-45046".to_string(), // Log4Shell follow-up
                "CVE-2021-34527".to_string(), // PrintNightmare
                "CVE-2021-26855".to_string(), // Exchange ProxyLogon
                "CVE-2021-40444".to_string(), // MSHTML RCE
            ],
            2020 => vec![
                "CVE-2020-1472".to_string(),  // Zerologon
                "CVE-2020-14882".to_string(), // Oracle WebLogic
                "CVE-2020-8277".to_string(),  // Pure-FTPd
            ],
            2019 => vec![
                "CVE-2019-0708".to_string(),  // BlueKeep
                "CVE-2019-11510".to_string(), // Pulse Secure
            ],
            2017 => vec![
                "CVE-2017-0144".to_string(), // EternalBlue
                "CVE-2017-5638".to_string(), // Apache Struts
            ],
            _ => vec![], // Add more years as needed
        }
    }

    fn is_relevant_cve(&self, cve: &Cve) -> bool {
        // Filter for network services and common attack vectors
        let has_network_ports = !cve.ports.is_empty();
        let has_high_severity = matches!(cve.severity, Severity::High | Severity::Critical);
        let is_exploitable = cve.exploitable;

        has_network_ports && (has_high_severity || is_exploitable)
    }

    pub async fn update_service_cve_mappings(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔄 Updating service-to-CVE mappings...");

        // Enhanced service mappings based on CVE database
        self.service_vulns.clear();

        let mut service_map: HashMap<String, Vec<ServiceVulnerability>> = HashMap::new();

        for (_cve_id, cve) in &self.cves {
            for service in &cve.affected_services {
                let service_lower = service.to_lowercase();

                // Map CVEs to services more intelligently
                let service_key = self.normalize_service_name(&service_lower);

                if let Some(service_name) = service_key {
                    let service_vuln = ServiceVulnerability {
                        service_name: service_name.clone(),
                        version_pattern: self.create_version_pattern(&cve.affected_versions),
                        cves: vec![cve.clone()],
                    };

                    service_map
                        .entry(service_name)
                        .or_insert_with(Vec::new)
                        .push(service_vuln);
                }
            }
        }

        self.service_vulns = service_map;

        println!(
            "✅ Updated mappings for {} services with {} CVEs",
            self.service_vulns.len(),
            self.cves.len()
        );
        Ok(())
    }

    fn normalize_service_name(&self, service: &str) -> Option<String> {
        match service {
            s if s.contains("apache") && s.contains("http") => Some("apache".to_string()),
            s if s.contains("tomcat") => Some("tomcat".to_string()),
            s if s.contains("nginx") => Some("nginx".to_string()),
            s if s.contains("openssh") => Some("ssh".to_string()),
            s if s.contains("mysql") => Some("mysql".to_string()),
            s if s.contains("postgresql") => Some("postgresql".to_string()),
            s if s.contains("redis") => Some("redis".to_string()),
            s if s.contains("elasticsearch") => Some("elasticsearch".to_string()),
            s if s.contains("microsoft") && s.contains("iis") => Some("iis".to_string()),
            _ => None,
        }
    }

    fn create_version_pattern(&self, versions: &[String]) -> String {
        if versions.is_empty() {
            return r".*".to_string();
        }

        // Create a regex pattern that matches any of the vulnerable versions
        let patterns: Vec<String> = versions
            .iter()
            .map(|v| format!(r"{}(\.|$)", regex::escape(v)))
            .collect();

        format!(r"({})", patterns.join("|"))
    }

    /// Search for vulnerabilities and return formatted results with 140-char explanations
    pub fn search_vulnerabilities(&self, service: &str, version: &str) -> Vec<VulnerabilityMatch> {
        let mut results = Vec::new();

        if let Some(service_vulns) = self.get_service_vulnerabilities(service) {
            for service_vuln in service_vulns {
                for cve in &service_vuln.cves {
                    if cve.affected_versions.iter().any(|v| version.contains(v)) {
                        let vulnerability_match = self.create_vulnerability_match(
                            cve, service, version,
                            0.85, // Default confidence for direct version match
                        );
                        results.push(vulnerability_match);
                    }
                }
            }
        }

        results
    }

    /// Create a VulnerabilityMatch from a CVE with 140-character explanation
    fn create_vulnerability_match(
        &self,
        cve: &Cve,
        matched_service: &str,
        matched_version: &str,
        confidence: f32,
    ) -> VulnerabilityMatch {
        // Create 140-char explanation from CVE title/description
        let explanation = self.create_short_explanation(cve);

        // Use first reference or construct one
        let reference_url = cve
            .references
            .first()
            .cloned()
            .unwrap_or_else(|| format!("https://nvd.nist.gov/vuln/detail/{}", cve.cve_id));

        VulnerabilityMatch {
            cve_id: cve.cve_id.clone(),
            summary: cve.description.chars().take(100).collect::<String>() + "...",
            explanation,
            reference_url,
            severity: cve.severity.clone(),
            cvss_score: cve.cvss_score,
            matched_service: matched_service.to_string(),
            matched_version: matched_version.to_string(),
            confidence,
        }
    }

    /// Generate a 140-character vulnerability explanation
    fn create_short_explanation(&self, cve: &Cve) -> String {
        // Try to extract key information and create a concise explanation
        let desc = &cve.description;

        // Look for common vulnerability patterns
        let explanation = if desc.to_lowercase().contains("remote code execution") {
            format!(
                "RCE vulnerability in {} - patch immediately!",
                cve.affected_services
                    .first()
                    .unwrap_or(&"service".to_string())
            )
        } else if desc.to_lowercase().contains("sql injection") {
            "SQL injection allows data theft - update or disable service.".to_string()
        } else if desc.to_lowercase().contains("buffer overflow") {
            format!(
                "Buffer overflow in {} - remote exploitation possible.",
                cve.affected_services
                    .first()
                    .unwrap_or(&"service".to_string())
            )
        } else if desc.to_lowercase().contains("denial of service") {
            "DoS vulnerability - service disruption possible.".to_string()
        } else {
            // Fallback: truncate description intelligently
            let words: Vec<&str> = desc.split_whitespace().collect();
            let mut result = String::new();
            for word in words {
                if result.len() + word.len() + 1 <= 140 {
                    if !result.is_empty() {
                        result.push(' ');
                    }
                    result.push_str(word);
                } else {
                    break;
                }
            }
            result
        };

        // Ensure it's within 140 characters
        if explanation.len() > 140 {
            format!("{}...", &explanation[..137])
        } else {
            explanation.to_string()
        }
    }
}
