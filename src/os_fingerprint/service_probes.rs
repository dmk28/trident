use super::banner_grabber::ServiceProbe;
use regex::Regex;

/// Creates a comprehensive database of service probes based on nmap's service-probes
pub fn create_service_probes() -> Result<Vec<ServiceProbe>, Box<dyn std::error::Error>> {
    let mut probes = Vec::new();

    // === BANNER-BASED SERVICES (No probe data needed) ===

    // SSH - Secure Shell
    probes.push(ServiceProbe {
        name: "SSH".to_string(),
        probe_data: vec![], // SSH sends banner immediately
        match_pattern: Regex::new(r"SSH-(\d+\.\d+)[-_]([^\r\n\s]+)")?,
        default_ports: vec![22, 2222],
    });

    // FTP - File Transfer Protocol
    probes.push(ServiceProbe {
        name: "FTP".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r"220.*(?:FTP|File Transfer Protocol).*?([^\r\n]+)")?,
        default_ports: vec![21, 2121],
    });

    // SMTP - Simple Mail Transfer Protocol
    probes.push(ServiceProbe {
        name: "SMTP".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r"220.*?SMTP.*?([^\r\n]+)")?,
        default_ports: vec![25, 465, 587],
    });

    // POP3 - Post Office Protocol v3
    probes.push(ServiceProbe {
        name: "POP3".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r"\+OK.*?POP3.*?([^\r\n]+)")?,
        default_ports: vec![110, 995],
    });

    // IMAP - Internet Message Access Protocol
    probes.push(ServiceProbe {
        name: "IMAP".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r"\* OK.*?IMAP.*?([^\r\n]+)")?,
        default_ports: vec![143, 993],
    });

    // Telnet
    probes.push(ServiceProbe {
        name: "Telnet".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r".*(?:login|Username|Password).*")?,
        default_ports: vec![23],
    });

    // === REQUEST-RESPONSE SERVICES ===

    // HTTP - Hypertext Transfer Protocol
    probes.push(ServiceProbe {
        name: "HTTP".to_string(),
        probe_data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        match_pattern: Regex::new(r"HTTP/1\.[01] \d{3}.*?Server:\s*([^\r\n]+)")?,
        default_ports: vec![80, 8080, 8081, 8000, 3000, 5000],
    });

    // HTTPS (same probe, different ports)
    probes.push(ServiceProbe {
        name: "HTTPS".to_string(),
        probe_data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        match_pattern: Regex::new(r"HTTP/1\.[01] \d{3}.*?Server:\s*([^\r\n]+)")?,
        default_ports: vec![443, 8443, 9443],
    });

    // MySQL Database
    probes.push(ServiceProbe {
        name: "MySQL".to_string(),
        probe_data: vec![], // MySQL sends handshake immediately
        match_pattern: Regex::new(r".*mysql.*version.*?(\d+\.\d+\.\d+)")?,
        default_ports: vec![3306],
    });

    // PostgreSQL Database
    probes.push(ServiceProbe {
        name: "PostgreSQL".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r".*PostgreSQL.*?(\d+\.\d+)")?,
        default_ports: vec![5432],
    });

    // === BINARY/SPECIALIZED PROTOCOLS ===

    // SMB/NetBIOS - Windows File Sharing
    probes.push(ServiceProbe {
        name: "SMB".to_string(),
        probe_data: vec![
            0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, // SMB negotiation
            0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
        ],
        match_pattern: Regex::new(r".*SMB.*")?,
        default_ports: vec![139, 445],
    });

    // DNS - Domain Name System (TCP)
    probes.push(ServiceProbe {
        name: "DNS".to_string(),
        probe_data: vec![
            0x00, 0x1d, // Length
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Counts
            0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
            0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
            0x00, 0x00, 0x10, 0x00, 0x03, // Query type TXT, class CH
        ],
        match_pattern: Regex::new(r".*version.*BIND.*?(\d+\.\d+\.\d+)")?,
        default_ports: vec![53],
    });

    // SNMP - Simple Network Management Protocol
    probes.push(ServiceProbe {
        name: "SNMP".to_string(),
        probe_data: vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, // SNMP v1 GetRequest
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
        ],
        match_pattern: Regex::new(r".*SNMP.*")?,
        default_ports: vec![161, 1161],
    });

    // VNC - Virtual Network Computing
    probes.push(ServiceProbe {
        name: "VNC".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r"RFB (\d{3}\.\d{3})")?,
        default_ports: vec![5900, 5901, 5902],
    });

    // === ADDITIONAL COMMON SERVICES ===

    // Redis Database
    probes.push(ServiceProbe {
        name: "Redis".to_string(),
        probe_data: b"*1\r\n$4\r\nINFO\r\n".to_vec(),
        match_pattern: Regex::new(r"redis_version:(\d+\.\d+\.\d+)")?,
        default_ports: vec![6379],
    });

    // MongoDB
    probes.push(ServiceProbe {
        name: "MongoDB".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r".*MongoDB.*version.*?(\d+\.\d+\.\d+)")?,
        default_ports: vec![27017],
    });

    // Elasticsearch
    probes.push(ServiceProbe {
        name: "Elasticsearch".to_string(),
        probe_data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        match_pattern: Regex::new(r".*elasticsearch.*version.*?(\d+\.\d+\.\d+)")?,
        default_ports: vec![9200, 9300],
    });

    // Apache Kafka
    probes.push(ServiceProbe {
        name: "Kafka".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r".*kafka.*")?,
        default_ports: vec![9092],
    });

    // LDAP - Lightweight Directory Access Protocol
    probes.push(ServiceProbe {
        name: "LDAP".to_string(),
        probe_data: vec![],
        match_pattern: Regex::new(r".*LDAP.*")?,
        default_ports: vec![389, 636],
    });

    // SIP - Session Initiation Protocol
    probes.push(ServiceProbe {
        name: "SIP".to_string(),
        probe_data: b"OPTIONS sip:user@domain SIP/2.0\r\n\r\n".to_vec(),
        match_pattern: Regex::new(r"SIP/2\.0.*Server:\s*([^\r\n]+)")?,
        default_ports: vec![5060, 5061],
    });

    // Memcached
    probes.push(ServiceProbe {
        name: "Memcached".to_string(),
        probe_data: b"stats\r\n".to_vec(),
        match_pattern: Regex::new(r"STAT version (\d+\.\d+\.\d+)")?,
        default_ports: vec![11211],
    });

    // Docker API
    probes.push(ServiceProbe {
        name: "Docker".to_string(),
        probe_data: b"GET /version HTTP/1.0\r\n\r\n".to_vec(),
        match_pattern: Regex::new(r".*Docker.*Version.*?(\d+\.\d+\.\d+)")?,
        default_ports: vec![2375, 2376],
    });

    Ok(probes)
}

/// Get probes filtered by service category
pub fn get_probes_by_category(
    category: &str,
) -> Result<Vec<ServiceProbe>, Box<dyn std::error::Error>> {
    let all_probes = create_service_probes()?;

    let filtered = match category.to_lowercase().as_str() {
        "web" => all_probes
            .into_iter()
            .filter(|p| matches!(p.name.as_str(), "HTTP" | "HTTPS"))
            .collect(),
        "database" => all_probes
            .into_iter()
            .filter(|p| {
                matches!(
                    p.name.as_str(),
                    "MySQL" | "PostgreSQL" | "Redis" | "MongoDB"
                )
            })
            .collect(),
        "mail" => all_probes
            .into_iter()
            .filter(|p| matches!(p.name.as_str(), "SMTP" | "POP3" | "IMAP"))
            .collect(),
        "file_sharing" => all_probes
            .into_iter()
            .filter(|p| matches!(p.name.as_str(), "SMB" | "FTP"))
            .collect(),
        _ => all_probes, // Return all if category not recognized
    };

    Ok(filtered)
}

/// Get the most common/essential probes for quick scanning
pub fn get_essential_probes() -> Result<Vec<ServiceProbe>, Box<dyn std::error::Error>> {
    let all_probes = create_service_probes()?;

    let essential = all_probes
        .into_iter()
        .filter(|p| {
            matches!(
                p.name.as_str(),
                "SSH" | "HTTP" | "HTTPS" | "FTP" | "SMTP" | "MySQL" | "PostgreSQL" | "SMB"
            )
        })
        .collect();

    Ok(essential)
}
