use super::structure::{PortStatus, ScanConfig, ScanResult};
use pnet::datalink::NetworkInterface;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
#[derive(Debug)]
pub struct ConnectScanner {
    pub(crate) config: ScanConfig,
    results: Arc<Mutex<Vec<ScanResult>>>,
}

impl ConnectScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            results: Arc::new(Mutex::new(Vec::new())),
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

        let self_arc = Arc::new(self);
        let mut set = JoinSet::new();
        for port in ports {
            let ip = ip.clone();
            let timeout_duration = timeout_duration.clone();
            let self_arc_clone = Arc::clone(&self_arc);
            set.spawn(async move {
                let result = self_arc_clone
                    .scan_single_port(ip, port, timeout_duration)
                    .await;
                if matches!(result.status, PortStatus::Open) {
                    let mut results = self_arc_clone.results.lock().await;
                    results.push(result);
                }
            });
        }

        while let Some(_) = set.join_next().await {}

        let open_ports = self_arc.results.lock().await.clone();
        let scanner = Arc::try_unwrap(self_arc).unwrap();

        Ok((open_ports, scanner))
    }

    async fn scan_single_port(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> ScanResult {
        let start_time = std::time::Instant::now();

        let socket_addr = std::net::SocketAddr::new(ip, port);
        let is_open = matches!(
            timeout(timeout_duration, TcpStream::connect(&socket_addr)).await,
            Ok(Ok(_))
        );

        let status = if is_open {
            PortStatus::Open
        } else {
            PortStatus::Closed
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
