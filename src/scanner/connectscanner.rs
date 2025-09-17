use super::structure::{PortStatus, ScanConfig, ScanResult};
use pnet::datalink::NetworkInterface;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
#[derive(Debug)]
pub struct ConnectScanner {
    pub(crate) config: ScanConfig,
    results: Arc<Mutex<Vec<ScanResult>>>,
    rate_limiter: Arc<Semaphore>,
    verbose: bool,
}

impl ConnectScanner {
    pub fn new(config: ScanConfig, verbose: bool) -> Self {
        // Use max_threads from config as concurrency limit
        let max_concurrent = config.max_threads;
        if verbose {
            println!(
                "🔗 Initializing connect scanner with {} max concurrent connections",
                max_concurrent
            );
        }

        Self {
            config,
            results: Arc::new(Mutex::new(Vec::new())),
            rate_limiter: Arc::new(Semaphore::new(max_concurrent)),
            verbose,
        }
    }
    pub fn get_interface(&self) -> Result<NetworkInterface, Box<dyn ::std::error::Error>> {
        use pnet::datalink;

        let interfaces = datalink::interfaces();

        for interface in interfaces {
            for ip_network in &interface.ips {
                if ip_network.ip() == self.config.interface_ip {
                    return Ok(interface);
                }
            }
        }
        Err("No matching interface".into())
    }

    pub async fn scan_tcp(
        self,
        ip: IpAddr,
        ports: Vec<u16>,
    ) -> Result<(Vec<ScanResult>, Self), Box<dyn std::error::Error>> {
        let timeout_duration = self.config.timeout;
        let total_ports = ports.len();

        if self.verbose {
            println!(
                "🚀 Starting TCP connect scan of {} ports with max {} concurrent connections",
                total_ports,
                self.rate_limiter.available_permits()
            );
        }

        let self_arc = Arc::new(self);
        let mut set = JoinSet::new();

        let progress_counter = Arc::new(AtomicUsize::new(0));

        for port in ports {
            let ip = ip.clone();
            let timeout_duration = timeout_duration.clone();
            let self_arc_clone = Arc::clone(&self_arc);
            let rate_limiter_clone = Arc::clone(&self_arc_clone.rate_limiter);
            let progress_counter_clone = Arc::clone(&progress_counter);

            set.spawn(async move {
                // Acquire permit - this blocks if we're at max concurrency
                let _permit = rate_limiter_clone
                    .acquire()
                    .await
                    .map_err(|_| Error::new(ErrorKind::Other, "Rate limiter closed"))?;

                let result = self_arc_clone
                    .scan_single_port_with_retry(ip, port, timeout_duration)
                    .await;

                // Store all results for comprehensive reporting
                {
                    let mut results = self_arc_clone.results.lock().await;
                    results.push(result);
                }

                // Progress indication for large scans using atomic counter (only if verbose)
                let completed = progress_counter_clone.fetch_add(1, Ordering::Relaxed) + 1;
                if self_arc_clone.verbose && total_ports > 100 && completed % 100 == 0 {
                    println!("📊 Progress: {}/{} ports scanned", completed, total_ports);
                }

                Ok::<(), Error>(())
            });
        }

        // Wait for all tasks to complete
        while let Some(task_result) = set.join_next().await {
            if let Err(e) = task_result {
                if self_arc.verbose {
                    eprintln!("⚠️ Task join error: {}", e);
                }
            }
        }

        let all_results = self_arc.results.lock().await.clone();
        let open_count = all_results
            .iter()
            .filter(|r| matches!(r.status, PortStatus::Open))
            .count();

        let verbose = self_arc.verbose;
        let scanner = Arc::try_unwrap(self_arc).unwrap();

        if verbose {
            println!(
                "✅ Connect scan completed: {}/{} ports open",
                open_count, total_ports
            );
        }
        Ok((all_results, scanner))
    }

    async fn scan_single_port_with_retry(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> ScanResult {
        const DEFAULT_MAX_RETRIES: u32 = 2;
        let max_retries = DEFAULT_MAX_RETRIES; // You can make this configurable later

        for attempt in 0..=max_retries {
            let result = self.scan_single_port(ip, port, timeout_duration).await;

            // If we get an open port or it's our last attempt, return the result
            if matches!(result.status, PortStatus::Open) || attempt == max_retries {
                return result;
            }

            // For closed/filtered ports, retry might help with transient network issues
            if attempt < max_retries {
                // Small delay between retries to avoid hammering
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        // This shouldn't be reached, but just in case
        self.scan_single_port(ip, port, timeout_duration).await
    }

    async fn scan_single_port(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> ScanResult {
        let start_time = std::time::Instant::now();
        let socket_addr = std::net::SocketAddr::new(ip, port);

        let connection_result = timeout(timeout_duration, TcpStream::connect(&socket_addr)).await;

        let status = match connection_result {
            Ok(Ok(_stream)) => {
                // Successfully connected
                PortStatus::Open
            }
            Ok(Err(e)) => {
                // Connection attempt completed but failed
                match e.kind() {
                    ErrorKind::ConnectionRefused => PortStatus::Closed,
                    ErrorKind::TimedOut => PortStatus::Filtered,
                    ErrorKind::PermissionDenied => PortStatus::Filtered,
                    _ => PortStatus::Filtered,
                }
            }
            Err(_) => {
                // Timeout occurred
                PortStatus::Filtered
            }
        };

        ScanResult {
            ip: Some(ip),
            port,
            status,
            service: None,
            banner: None,
            response_time: start_time.elapsed(),
            timestamp: SystemTime::now(),
        }
    }

    pub async fn get_results(&self) -> Vec<ScanResult> {
        let results_guard = self.results.lock().await;
        results_guard.clone()
    }

    pub async fn scan_port_range(
        self,
        ip: IpAddr,
        start_port: u16,
        end_port: u16,
    ) -> Result<(Vec<ScanResult>, Self), Box<dyn std::error::Error>> {
        let ports: Vec<u16> = (start_port..=end_port).collect();
        let (result, scanner) = self.scan_tcp(ip, ports).await?;
        Ok((result, scanner))
    }

    pub async fn scan_common_ports(
        self,
        ip: IpAddr,
    ) -> Result<(Vec<ScanResult>, Self), Box<dyn std::error::Error>> {
        // Common ports similar to the Black Hat Rust book
        let common_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432,
            5900, 8080, 1433, 1521, 27017, 6379,
        ];
        let (result, scanner) = self.scan_tcp(ip, common_ports).await?;
        Ok((result, scanner))
    }
}
