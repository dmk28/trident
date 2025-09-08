use rand::Rng;
use std::{
    net::IpAddr,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub port: u16,
    pub status: PortStatus,
    pub timestamp: SystemTime,
    pub response_time: Duration,
    pub ip: Option<IpAddr>,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub interface_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub ports_to_scan: Vec<u16>,
    pub wait_after_send: Duration,
    pub timeout: Duration,
    pub all_sent: Arc<AtomicBool>,
    pub max_threads: usize,
}

impl ScanConfig {
    pub fn new(
        destination_ip: IpAddr,
        ports_to_scan: Vec<u16>,
        interface_ip: IpAddr,
        timeout: u64,
    ) -> Self {
        let source_port: u16 = generate_random_port(10024, 65535) as u16;
        Self {
            interface_ip,
            source_port,
            destination_ip,
            wait_after_send: Duration::from_millis(500 * ports_to_scan.len() as u64),
            ports_to_scan,
            timeout: Duration::from_secs(timeout),
            all_sent: Arc::new(AtomicBool::new(false)),
            max_threads: 100,
        }
    }
}

pub fn generate_random_port(min: u32, max: u32) -> u32 {
    let mut rng = rand::rng();
    rng.random_range(min..max)
}

pub fn parse_port_range(port_range: &str) -> Vec<u16> {
    if port_range.contains('-') {
        let parts: Vec<&str> = port_range.split('-').collect();
        if parts.len() != 2 {
            panic!("Invalid port range format. Use: start-end (e.g., 1-1024)");
        }

        let start: u16 = parts[0].parse().expect("Invalid start port number");
        let end: u16 = parts[1].parse().expect("Invalid end port number");

        if start > end {
            panic!("Start port must be less than or equal to end port");
        }

        (start..=end).collect()
    } else if port_range.contains(',') {
        port_range
            .split(',')
            .map(|s| s.trim().parse::<u16>().expect("Invalid port number"))
            .collect()
    } else {
        vec![port_range.parse().expect("Invalid port number")]
    }
}
