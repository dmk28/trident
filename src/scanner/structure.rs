use rand::Rng;
use std::{
    collections::HashSet,
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
    pub source_port: u16, // Kept for backward compatibility, but will be overridden dynamically
    pub destination_ip: IpAddr,
    pub ports_to_scan: Vec<u16>,
    pub wait_after_send: Duration,
    pub timeout: Duration,
    pub all_sent: Arc<AtomicBool>,
    pub max_threads: usize,
    pub use_dynamic_source_ports: bool,
    pub source_port_pool: Arc<std::sync::Mutex<HashSet<u16>>>,
}

impl ScanConfig {
    pub fn new(
        destination_ip: IpAddr,
        ports_to_scan: Vec<u16>,
        interface_ip: IpAddr,
        timeout: u64,
    ) -> Self {
        let source_port: u16 = generate_random_port(10024, 65535) as u16;

        // Calculate intelligent timeout based on scan size and user preference
        let calculated_timeout = Self::calculate_intelligent_timeout(&ports_to_scan, timeout);

        Self {
            interface_ip,
            source_port,
            destination_ip,
            wait_after_send: Duration::from_millis(500 * ports_to_scan.len() as u64),
            ports_to_scan,
            timeout: calculated_timeout,
            all_sent: Arc::new(AtomicBool::new(false)),
            max_threads: 100,
            use_dynamic_source_ports: true,
            source_port_pool: Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Create a new scan config with custom source port behavior
    pub fn new_with_source_port_config(
        destination_ip: IpAddr,
        ports_to_scan: Vec<u16>,
        interface_ip: IpAddr,
        timeout: u64,
        use_dynamic_source_ports: bool,
        fixed_source_port: Option<u16>,
    ) -> Self {
        let source_port: u16 =
            fixed_source_port.unwrap_or(generate_random_port(10024, 65535) as u16);

        // Calculate intelligent timeout based on scan size and user preference
        let calculated_timeout = Self::calculate_intelligent_timeout(&ports_to_scan, timeout);

        Self {
            interface_ip,
            source_port,
            destination_ip,
            wait_after_send: Duration::from_millis(500 * ports_to_scan.len() as u64),
            ports_to_scan,
            timeout: calculated_timeout,
            all_sent: Arc::new(AtomicBool::new(false)),
            max_threads: 100,
            use_dynamic_source_ports,
            source_port_pool: Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Calculate intelligent timeout based on scan size and user preference
    fn calculate_intelligent_timeout(ports_to_scan: &[u16], user_timeout: u64) -> Duration {
        let num_ports = ports_to_scan.len();

        // Calculate minimum required timeout based on scan size
        let min_timeout_secs = if num_ports <= 100 {
            15 // Small scans: 15 seconds minimum
        } else if num_ports <= 1000 {
            30 // Medium scans: 30 seconds minimum
        } else if num_ports <= 10000 {
            60 // Large scans: 1 minute minimum
        } else {
            120 // Huge scans (like 1-65535): 2 minutes minimum
        };

        // Use the larger of user timeout or calculated minimum
        let final_timeout = std::cmp::max(user_timeout, min_timeout_secs);

        if final_timeout > user_timeout {
            println!(
                "⏰ Adjusting timeout from {}s to {}s for {} ports (scan size requires more time)",
                user_timeout, final_timeout, num_ports
            );
        }

        Duration::from_secs(final_timeout)
    }

    /// Generate a unique source port for each destination port to avoid reuse
    pub fn get_unique_source_port(&self, dest_port: u16) -> u16 {
        if !self.use_dynamic_source_ports {
            return self.source_port;
        }

        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 100;

        loop {
            let source_port = generate_random_port(10024, 65535) as u16;

            // Avoid using the same port as destination (would be confusing)
            if source_port == dest_port {
                attempts += 1;
                if attempts >= MAX_ATTEMPTS {
                    break source_port; // Give up after too many attempts
                }
                continue;
            }

            // Try to ensure uniqueness by checking our used port pool
            if let Ok(mut pool) = self.source_port_pool.try_lock() {
                if !pool.contains(&source_port) {
                    pool.insert(source_port);
                    // Keep pool size reasonable to avoid memory growth
                    if pool.len() > 1000 {
                        pool.clear();
                    }
                    break source_port;
                }
            } else {
                // If we can't lock, just use the generated port
                break source_port;
            }

            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                break source_port;
            }
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
