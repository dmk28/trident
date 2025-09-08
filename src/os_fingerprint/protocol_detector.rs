use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Protocol version detection results
#[derive(Debug, Clone)]
pub struct ProtocolVersion {
    pub protocol: String,
    pub version: String,
    pub confidence: f32,
    pub detected_features: Vec<String>,
}

/// TLS/SSL fingerprinting data
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub version: String,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<String>,
    pub ja3_hash: Option<String>,
    pub certificate_info: Option<String>,
}

/// Protocol behavior analysis
#[derive(Debug, Clone)]
pub struct ProtocolBehavior {
    pub response_timing: Duration,
    pub error_patterns: Vec<String>,
    pub edge_case_handling: HashMap<String, String>,
    pub connection_behavior: String,
}

/// Deep packet inspection classification
#[derive(Debug, Clone)]
pub struct ProtocolClassification {
    pub protocol_family: String,
    pub likely_protocol: String,
    pub confidence: f32,
    pub identifying_patterns: Vec<String>,
    pub packet_structure: String,
}

/// Combined protocol detection result
#[derive(Debug, Clone)]
pub struct ProtocolDetectionResult {
    pub version_info: Option<ProtocolVersion>,
    pub tls_info: Option<TlsFingerprint>,
    pub behavior_info: Option<ProtocolBehavior>,
    pub classification: Option<ProtocolClassification>,
}

// ==================== PROTOCOL VERSION DETECTION ====================

pub fn detect_http_version(response: &str) -> Option<ProtocolVersion> {
    let version_patterns = [
        (r"HTTP/3\.", "HTTP/3", vec!["QUIC", "UDP-based"]),
        (
            r"HTTP/2\.",
            "HTTP/2",
            vec!["Binary framing", "Multiplexing"],
        ),
        (
            r"HTTP/1\.1",
            "HTTP/1.1",
            vec!["Persistent connections", "Chunked encoding"],
        ),
        (r"HTTP/1\.0", "HTTP/1.0", vec!["Simple request-response"]),
    ];

    for (pattern, version, features) in &version_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(response) {
                return Some(ProtocolVersion {
                    protocol: "HTTP".to_string(),
                    version: version.to_string(),
                    confidence: 0.95,
                    detected_features: features.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
    }
    None
}

pub fn detect_ssh_version(banner: &str) -> Option<ProtocolVersion> {
    let ssh_patterns = [
        (r"SSH-2\.0", "SSH-2.0", vec!["Modern SSH", "Key exchange"]),
        (r"SSH-1\.99", "SSH-1.99", vec!["Backward compatible"]),
        (r"SSH-1\.5", "SSH-1.5", vec!["Legacy SSH"]),
        (r"SSH-1\.0", "SSH-1.0", vec!["Original SSH"]),
    ];

    for (pattern, version, features) in &ssh_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(banner) {
                let mut detected_features =
                    features.iter().map(|s| s.to_string()).collect::<Vec<_>>();

                // Extract additional SSH implementation details
                if banner.contains("OpenSSH") {
                    detected_features.push("OpenSSH".to_string());
                } else if banner.contains("libssh") {
                    detected_features.push("libssh".to_string());
                } else if banner.contains("Cisco") {
                    detected_features.push("Cisco SSH".to_string());
                }

                return Some(ProtocolVersion {
                    protocol: "SSH".to_string(),
                    version: version.to_string(),
                    confidence: 0.9,
                    detected_features,
                });
            }
        }
    }
    None
}

pub fn detect_ftp_version(response: &str) -> Option<ProtocolVersion> {
    let features = if response.contains("EPSV") || response.contains("EPRT") {
        vec!["Extended Passive Mode", "IPv6 Support"]
    } else if response.contains("PASV") {
        vec!["Passive Mode"]
    } else {
        vec!["Active Mode Only"]
    };

    Some(ProtocolVersion {
        protocol: "FTP".to_string(),
        version: "RFC 959".to_string(),
        confidence: 0.8,
        detected_features: features.iter().map(|s| s.to_string()).collect(),
    })
}

// ==================== ENCRYPTED PROTOCOL ANALYSIS ====================

pub async fn analyze_tls_connection(ip: IpAddr, port: u16) -> Option<TlsFingerprint> {
    let _stream = match TcpStream::connect((ip, port)).await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // This is a simplified TLS analysis - in practice you'd need full TLS parsing
    // For demonstration, we'll simulate what real TLS fingerprinting does

    let mut fingerprint = TlsFingerprint {
        version: "Unknown".to_string(),
        cipher_suites: Vec::new(),
        extensions: Vec::new(),
        ja3_hash: None,
        certificate_info: None,
    };

    // In a real implementation, you'd:
    // 1. Send a TLS ClientHello
    // 2. Parse the ServerHello response
    // 3. Extract cipher suites, extensions, and certificate data
    // 4. Calculate JA3/JA4 hash from the handshake

    // Simulated analysis based on common patterns
    match port {
        443 | 8443 => {
            fingerprint.version = "TLS 1.2/1.3".to_string();
            fingerprint.cipher_suites = vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ];
            fingerprint.extensions = vec![
                "server_name".to_string(),
                "supported_versions".to_string(),
                "key_share".to_string(),
            ];
        }
        _ => {
            fingerprint.version = "No TLS".to_string();
        }
    }

    Some(fingerprint)
}

fn calculate_ja3_hash(_client_hello: &[u8]) -> String {
    // JA3 is calculated from: TLS Version, Cipher Suites, Extensions,
    // Elliptic Curves, and Elliptic Curve Point Formats
    // This is a placeholder - real implementation would parse TLS handshake
    "placeholder_ja3_hash".to_string()
}

// ==================== PROTOCOL BEHAVIOR ANALYSIS ====================

pub async fn analyze_protocol_behavior(ip: IpAddr, port: u16) -> Option<ProtocolBehavior> {
    let start_time = Instant::now();

    let mut behavior = ProtocolBehavior {
        response_timing: Duration::from_secs(0),
        error_patterns: Vec::new(),
        edge_case_handling: HashMap::new(),
        connection_behavior: "Unknown".to_string(),
    };

    // Test 1: Connection timing
    let connection_result = timeout(Duration::from_secs(5), TcpStream::connect((ip, port))).await;
    behavior.response_timing = start_time.elapsed();

    let mut stream = match connection_result {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            behavior.connection_behavior = "Connection refused".to_string();
            return Some(behavior);
        }
        Err(_) => {
            behavior.connection_behavior = "Connection timeout".to_string();
            return Some(behavior);
        }
    };

    behavior.connection_behavior = "Connection established".to_string();

    // Test 2: Malformed request handling
    let oversized_data = vec![b'A'; 8192];
    let malformed_tests: &[(&str, &[u8])] = &[
        ("Invalid HTTP", b"GET /invalid HTTP/9.9\r\n\r\n"),
        ("Binary junk", b"\x00\x01\x02\x03\x04\x05"),
        ("Oversized request", &oversized_data),
        ("NULL bytes", b"GET /test\x00\x00 HTTP/1.1\r\n\r\n"),
    ];

    for (test_name, payload) in malformed_tests {
        if let Ok(_) = stream.write_all(payload).await {
            let mut buffer = vec![0u8; 1024];
            match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    behavior
                        .edge_case_handling
                        .insert(test_name.to_string(), response.to_string());

                    // Classify error patterns
                    if response.contains("400") {
                        behavior
                            .error_patterns
                            .push("HTTP 400 Bad Request".to_string());
                    } else if response.contains("500") {
                        behavior
                            .error_patterns
                            .push("HTTP 500 Internal Error".to_string());
                    } else if response.contains("refused") {
                        behavior
                            .error_patterns
                            .push("Connection refused pattern".to_string());
                    }
                }
                _ => {
                    behavior.edge_case_handling.insert(
                        test_name.to_string(),
                        "No response / Connection dropped".to_string(),
                    );
                }
            }
        }
    }

    Some(behavior)
}

// ==================== DEEP PACKET INSPECTION ====================

pub fn classify_unknown_protocol(packet_data: &[u8]) -> Option<ProtocolClassification> {
    let mut classification = ProtocolClassification {
        protocol_family: "Unknown".to_string(),
        likely_protocol: "Unknown".to_string(),
        confidence: 0.0,
        identifying_patterns: Vec::new(),
        packet_structure: "Binary".to_string(),
    };

    // Text-based protocol detection
    if let Ok(text_data) = std::str::from_utf8(packet_data) {
        classification.packet_structure = "Text-based".to_string();

        let text_patterns = [
            (
                "HTTP",
                vec!["GET ", "POST ", "HTTP/", "Host:", "User-Agent:"],
            ),
            (
                "SMTP",
                vec!["HELO ", "MAIL FROM:", "RCPT TO:", "DATA", "220 "],
            ),
            ("POP3", vec!["USER ", "PASS ", "+OK", "-ERR", "RETR "]),
            ("IMAP", vec!["LOGIN ", "SELECT ", "FETCH ", "* OK", "A001 "]),
            ("FTP", vec!["USER ", "PASS ", "PWD", "LIST", "220 ", "221 "]),
            (
                "Telnet",
                vec!["login:", "Password:", "Username:", "Welcome"],
            ),
            ("IRC", vec!["NICK ", "JOIN ", "PRIVMSG ", "PING ", "PONG "]),
        ];

        for (protocol, patterns) in &text_patterns {
            let matches = patterns
                .iter()
                .filter(|pattern| text_data.contains(*pattern))
                .count();

            if matches > 0 {
                let confidence = (matches as f32 / patterns.len() as f32) * 0.9;
                if confidence > classification.confidence {
                    classification.protocol_family = "Text-based Application".to_string();
                    classification.likely_protocol = protocol.to_string();
                    classification.confidence = confidence;
                    classification.identifying_patterns = patterns
                        .iter()
                        .filter(|pattern| text_data.contains(*pattern))
                        .map(|s| s.to_string())
                        .collect();
                }
            }
        }
    }

    // Binary protocol detection
    if classification.confidence < 0.3 {
        let binary_patterns = [
            ("TLS/SSL", vec![0x16, 0x03], "TLS Handshake"),
            ("SSH", vec![b'S', b'S', b'H'], "SSH Protocol"),
            ("DNS", vec![0x00, 0x00, 0x01, 0x00], "DNS Query"),
            ("DHCP", vec![0x01, 0x01, 0x06, 0x00], "DHCP Discover"),
            ("RDP", vec![0x03, 0x00, 0x00], "RDP Connection"),
            ("SMB", vec![0xff, b'S', b'M', b'B'], "SMB Protocol"),
        ];

        for (protocol, pattern, description) in &binary_patterns {
            if packet_data.len() >= pattern.len() {
                let matches = pattern
                    .iter()
                    .zip(packet_data.iter())
                    .filter(|(a, b)| a == b)
                    .count();

                if matches == pattern.len() {
                    classification.protocol_family = "Binary Protocol".to_string();
                    classification.likely_protocol = protocol.to_string();
                    classification.confidence = 0.8;
                    classification.identifying_patterns = vec![description.to_string()];
                    break;
                }
            }
        }
    }

    // Protocol structure analysis
    if packet_data.len() >= 4 {
        let length_field = u32::from_be_bytes([
            packet_data[0],
            packet_data[1],
            packet_data[2],
            packet_data[3],
        ]);

        if length_field as usize + 4 == packet_data.len() {
            classification
                .identifying_patterns
                .push("Length-prefixed protocol".to_string());
        }
    }

    if classification.confidence > 0.2 {
        Some(classification)
    } else {
        None
    }
}

// ==================== MAIN DETECTION INTERFACE ====================

pub async fn comprehensive_protocol_detection(
    ip: IpAddr,
    port: u16,
    initial_data: Option<&[u8]>,
) -> ProtocolDetectionResult {
    let mut result = ProtocolDetectionResult {
        version_info: None,
        tls_info: None,
        behavior_info: None,
        classification: None,
    };

    // Attempt to grab some initial data if not provided
    let sample_data = match initial_data {
        Some(data) => data.to_vec(),
        None => match grab_sample_data(ip, port).await {
            Ok(data) => data,
            Err(_) => Vec::new(),
        },
    };

    // Protocol version detection
    if !sample_data.is_empty() {
        let data_str = String::from_utf8_lossy(&sample_data);

        if let Some(version) = detect_http_version(&data_str) {
            result.version_info = Some(version);
        } else if let Some(version) = detect_ssh_version(&data_str) {
            result.version_info = Some(version);
        } else if let Some(version) = detect_ftp_version(&data_str) {
            result.version_info = Some(version);
        }
    }

    // TLS analysis for secure ports
    if matches!(port, 443 | 993 | 995 | 8443) {
        result.tls_info = analyze_tls_connection(ip, port).await;
    }

    // Behavior analysis
    result.behavior_info = analyze_protocol_behavior(ip, port).await;

    // Deep packet inspection
    if !sample_data.is_empty() {
        result.classification = classify_unknown_protocol(&sample_data);
    }

    result
}

async fn grab_sample_data(ip: IpAddr, port: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect((ip, port))).await??;
    let mut buffer = vec![0u8; 4096];

    // Try to read initial banner
    match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => Ok(buffer[..n].to_vec()),
        _ => {
            // Send a generic probe and read response
            let _ = stream
                .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                .await;
            match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
                Ok(Ok(n)) => Ok(buffer[..n].to_vec()),
                _ => Ok(Vec::new()),
            }
        }
    }
}

// ==================== UTILITY FUNCTIONS ====================

pub fn generate_protocol_report(result: &ProtocolDetectionResult) -> String {
    let mut report = String::new();

    report.push_str("=== Protocol Detection Report ===\n");

    if let Some(version) = &result.version_info {
        report.push_str(&format!(
            "Protocol: {} {}\n",
            version.protocol, version.version
        ));
        report.push_str(&format!("Confidence: {:.1}%\n", version.confidence * 100.0));
        report.push_str(&format!(
            "Features: {}\n",
            version.detected_features.join(", ")
        ));
    }

    if let Some(tls) = &result.tls_info {
        report.push_str(&format!("TLS Version: {}\n", tls.version));
        if !tls.cipher_suites.is_empty() {
            report.push_str(&format!(
                "Cipher Suites: {}\n",
                tls.cipher_suites.join(", ")
            ));
        }
    }

    if let Some(behavior) = &result.behavior_info {
        report.push_str(&format!("Response Time: {:?}\n", behavior.response_timing));
        report.push_str(&format!("Connection: {}\n", behavior.connection_behavior));
        if !behavior.error_patterns.is_empty() {
            report.push_str(&format!(
                "Error Patterns: {}\n",
                behavior.error_patterns.join(", ")
            ));
        }
    }

    if let Some(classification) = &result.classification {
        report.push_str(&format!(
            "Classification: {} ({}%)\n",
            classification.likely_protocol,
            classification.confidence * 100.0
        ));
        report.push_str(&format!("Structure: {}\n", classification.packet_structure));
    }

    report
}
