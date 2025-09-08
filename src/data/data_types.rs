pub struct ScanResult {
    target: IpAddr,
    port: u16,
    status: PortStatus,
    timestamp: SystemTime,
}

pub struct DomainScanResult {
    domain: String,
    subdomains: Vec<SubdomainResult>,
}
