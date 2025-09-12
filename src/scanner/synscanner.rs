use super::structure::{PortStatus, ScanConfig, ScanResult};
use pnet::{
    datalink::{Channel, DataLinkReceiver, NetworkInterface},
    packet::{
        Packet,
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket, ipv4_checksum, ipv6_checksum},
    },
    transport::{self, TransportChannelType, TransportProtocol, TransportSender},
};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ETHERNET_HEADER_LEN: usize = 14;

pub struct SynScanner {
    pub(crate) config: ScanConfig,
    results: Vec<ScanResult>,
}

impl SynScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
        }
    }

    pub fn scan(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let interface = self.get_interface()?;
        let syn_sender = self.get_socket(self.config.destination_ip)?;
        let rst_sender = self.get_socket(self.config.destination_ip)?;

        let rx = match pnet::datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => rx,
            Ok(_) => return Err("Unknown channel type".into()),
            Err(e) => return Err(format!("Error creating channel: {}", e).into()),
        };

        let config_clone = self.config.clone();
        let results_arc = Arc::new(std::sync::Mutex::new(Vec::new()));

        let config_rx = config_clone.clone();
        let results_rx = results_arc.clone();
        let rx_handle =
            thread::spawn(move || Self::receive_packets(config_rx, rst_sender, rx, results_rx));

        let config_tx = config_clone;
        let tx_handle = thread::spawn(move || Self::send_packets(config_tx, syn_sender));

        let _ = rx_handle.join();
        let _ = tx_handle.join();

        // Collect results
        let results = results_arc.lock().unwrap();
        self.results = results.clone();

        Ok(())
    }

    pub fn get_results(&self) -> &Vec<ScanResult> {
        &self.results
    }

    pub fn get_config(&self) -> &ScanConfig {
        &self.config
    }

    fn get_interface(&self) -> Result<NetworkInterface, Box<dyn std::error::Error>> {
        use pnet::datalink;
        let interfaces = datalink::interfaces();

        // Find interface with matching IP
        for interface in interfaces {
            for ip_network in &interface.ips {
                if ip_network.ip() == self.config.interface_ip {
                    return Ok(interface);
                }
            }
        }

        Err("No matching interface found".into())
    }

    fn get_socket(
        &self,
        destination: IpAddr,
    ) -> Result<TransportSender, Box<dyn std::error::Error>> {
        match destination {
            IpAddr::V4(_) => {
                match transport::transport_channel(
                    4096,
                    TransportChannelType::Layer4(TransportProtocol::Ipv4(
                        IpNextHeaderProtocols::Tcp,
                    )),
                ) {
                    Ok((ts, _)) => Ok(ts),
                    Err(e) => Err(format!("{}", e).into()),
                }
            }
            IpAddr::V6(_) => {
                match transport::transport_channel(
                    4096,
                    TransportChannelType::Layer4(TransportProtocol::Ipv6(
                        IpNextHeaderProtocols::Tcp,
                    )),
                ) {
                    Ok((ts, _)) => Ok(ts),
                    Err(e) => Err(format!("{}", e).into()),
                }
            }
        }
    }

    fn build_packet(
        tcp_packet: &mut MutableTcpPacket,
        source_ip: IpAddr,
        dest_ip: IpAddr,
        source_port: u16,
        dest_port: u16,
        syn: bool,
    ) {
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(dest_port);
        tcp_packet.set_sequence(0);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(8);

        if syn {
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_options(&[
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ]);
            tcp_packet.set_urgent_ptr(0);
        } else {
            tcp_packet.set_flags(TcpFlags::RST);
        }

        let checksum = match (source_ip, dest_ip) {
            (IpAddr::V4(src), IpAddr::V4(dest)) => {
                ipv4_checksum(&tcp_packet.to_immutable(), &src, &dest)
            }
            (IpAddr::V6(src), IpAddr::V6(dest)) => {
                ipv6_checksum(&tcp_packet.to_immutable(), &src, &dest)
            }
            _ => panic!("IP version mismatch between source and destination"),
        };

        tcp_packet.set_checksum(checksum);
    }

    fn get_buffer(config: &ScanConfig) -> Vec<u8> {
        let header_length = match config.destination_ip {
            IpAddr::V4(_) => IPV4_HEADER_LEN,
            IpAddr::V6(_) => IPV6_HEADER_LEN,
        };
        vec![0; ETHERNET_HEADER_LEN + header_length + 86]
    }

    fn handle_tcp<'a>(
        ip_payload: &[u8],
        config: &ScanConfig,
        ip_addr: IpAddr,
        buffer: &'a mut [u8],
        results: Arc<std::sync::Mutex<Vec<ScanResult>>>,
    ) -> Result<Option<MutableTcpPacket<'a>>, String> {
        let tcp_packet =
            TcpPacket::new(ip_payload).ok_or_else(|| "Failed to create TCP Packet".to_string())?;

        let mut rst_packet = MutableTcpPacket::new(buffer)
            .ok_or_else(|| "Failed to create mutable TCP Packet".to_string())?;

        let port = tcp_packet.get_source();
        let flags = tcp_packet.get_flags();
        let status = if flags == (TcpFlags::SYN | TcpFlags::ACK) {
            println!("port {} open on host {}", port, ip_addr);
            PortStatus::Open
        } else if flags == TcpFlags::RST || flags == (TcpFlags::RST | TcpFlags::ACK) {
            println!("port {} closed on host {}", port, ip_addr);
            PortStatus::Closed
        } else {
            println!(
                "port {} - unknown response (flags: 0x{:02x}) on host {}",
                port, flags, ip_addr
            );
            PortStatus::Filtered
        };

        // Record the result
        let result = ScanResult {
            port,
            status,
            timestamp: SystemTime::now(),
            response_time: Duration::from_millis(0),
            ip: Some(ip_addr),
            service: None,
            banner: None,
        };

        results.lock().unwrap().push(result);

        if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
            // For RST response, we need to use the destination port from the incoming packet
            // as our source port (since it was the source port we originally used)
            Self::build_packet(
                &mut rst_packet,
                config.interface_ip,
                config.destination_ip,
                tcp_packet.get_destination(), // Use the destination port from the SYN-ACK as our source
                tcp_packet.get_source(),
                false,
            );
            Ok(Some(rst_packet))
        } else {
            Ok(None)
        }
    }

    fn send_packets(config: ScanConfig, mut sender: TransportSender) {
        println!(
            "Scanning {} ports on {}...",
            config.ports_to_scan.len(),
            config.destination_ip
        );

        if config.use_dynamic_source_ports {
            println!("🔧 Using dynamic source ports to avoid port reuse and improve stealth");
        }

        for destination_port in config.ports_to_scan.iter() {
            // Generate a unique source port for each destination port
            let source_port = config.get_unique_source_port(*destination_port);

            let mut vec = Self::get_buffer(&config);
            let mut tcp_packet =
                MutableTcpPacket::new(&mut vec[..]).expect("Failed to create mutable TCP packet");

            Self::build_packet(
                &mut tcp_packet,
                config.interface_ip,
                config.destination_ip,
                source_port, // Use unique source port instead of config.source_port
                *destination_port,
                true,
            );

            if let Err(e) = sender.send_to(tcp_packet.to_immutable(), config.destination_ip) {
                eprintln!("Error sending packet: {}", e);
            }

            thread::sleep(Duration::from_millis(10));
        }

        thread::sleep(config.wait_after_send);
        config.all_sent.store(true, Ordering::SeqCst);
    }

    fn receive_packets(
        config: ScanConfig,
        mut sender: TransportSender,
        mut rx: Box<dyn DataLinkReceiver>,
        results: Arc<std::sync::Mutex<Vec<ScanResult>>>,
    ) {
        let start = Instant::now();
        let mut all_sent_time: Option<Instant> = None;
        let response_timeout = Duration::from_secs(3); // Wait 3 seconds after all packets sent

        loop {
            match rx.next() {
                Ok(packet) => {
                    let eth_packet = EthernetPacket::new(packet).unwrap();

                    match eth_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();

                            if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp
                                && ipv4_packet.get_source()
                                    == match config.destination_ip {
                                        IpAddr::V4(ip) => ip,
                                        _ => continue,
                                    }
                            {
                                let mut buffer = Self::get_buffer(&config);
                                let rst_packet = Self::handle_tcp(
                                    ipv4_packet.payload(),
                                    &config,
                                    ipv4_packet.get_source().into(),
                                    &mut buffer,
                                    results.clone(),
                                );

                                if let Ok(Some(rst_packet)) = rst_packet {
                                    let _ = sender.send_to(rst_packet, config.destination_ip);
                                }
                            }
                        }

                        EtherTypes::Ipv6 => {
                            let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();

                            if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Tcp
                                && ipv6_packet.get_source()
                                    == match config.destination_ip {
                                        IpAddr::V6(ip) => ip,
                                        _ => continue,
                                    }
                            {
                                let mut buffer = Self::get_buffer(&config);
                                let rst_packet = Self::handle_tcp(
                                    ipv6_packet.payload(),
                                    &config,
                                    ipv6_packet.get_source().into(),
                                    &mut buffer,
                                    results.clone(),
                                );

                                if let Ok(Some(rst_packet)) = rst_packet {
                                    let _ = sender.send_to(rst_packet, config.destination_ip);
                                }
                            }
                        }

                        _ => {}
                    }
                }
                Err(e) => {
                    println!("Error while receiving a packet: {:?}", e);
                }
            }

            // Check if all packets have been sent
            let all_packets_sent = config.all_sent.load(Ordering::SeqCst);

            // Record when all packets were sent for the first time
            if all_packets_sent && all_sent_time.is_none() {
                all_sent_time = Some(Instant::now());
                println!(
                    "🕒 All SYN packets sent, waiting {} seconds for remaining responses...",
                    response_timeout.as_secs()
                );
            }

            // Determine if we should stop receiving
            let should_stop = if let Some(sent_time) = all_sent_time {
                // If all packets were sent, wait only for response_timeout duration
                Instant::now().duration_since(sent_time) > response_timeout
            } else {
                // If still sending packets, use the original timeout
                Instant::now().duration_since(start) > config.timeout
            };

            if should_stop {
                if all_packets_sent {
                    println!("🏁 Response timeout reached, finalizing scan results");
                } else {
                    println!("⏰ Overall scan timeout reached");
                }
                break;
            }
        }
    }
}
