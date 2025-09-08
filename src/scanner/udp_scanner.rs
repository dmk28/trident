use super::structure::{PortStatus, ScanConfig, ScanResult};
use pnet::{
    datalink::{Channel, NetworkInterface},
    packet::{
        Packet,
        icmp::{IcmpPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        udp::{MutableUdpPacket, UdpPacket},
    },
    transport::{self, TransportChannelType, TransportProtocol, TransportSender},
};
use std::{
    net::IpAddr,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime},
};

pub struct UdpScanner {
    pub(crate) config: ScanConfig,
}

impl UdpScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub fn scan(&mut self) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
        let interface = self.get_interface()?;
        let udp_sender = self.get_socket(self.config.destination_ip)?;

        let rx = match pnet::datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => rx,
            Ok(_) => return Err("Unknown channel type".into()),
            Err(e) => return Err(format!("Error creating channel: {}", e).into()),
        };

        let mut results = Vec::new();
        let sent_ports = Arc::new(std::sync::Mutex::new(Vec::new()));

        let config_clone = self.config.clone();
        let sent_ports_clone = Arc::clone(&sent_ports);
        let tx_handle =
            thread::spawn(move || Self::send_packets(config_clone, udp_sender, sent_ports_clone));

        let config_rx = self.config.clone();
        let rx_handle = thread::spawn(move || Self::receive_packets(config_rx, rx));

        let _ = tx_handle.join();
        let icmp_results = rx_handle.join().unwrap();

        // Mark sent ports as open if no ICMP received, closed if ICMP received
        if let Ok(sent) = sent_ports.lock() {
            for &port in &*sent {
                let status = if icmp_results.contains(&port) {
                    PortStatus::Closed
                } else {
                    PortStatus::Open
                };
                results.push(ScanResult {
                    ip: Some(self.config.destination_ip),
                    port,
                    status,
                    service: None,
                    banner: None,
                    response_time: Duration::from_millis(0),
                    timestamp: SystemTime::now(),
                });
            }
        }

        Ok(results)
    }

    fn get_interface(&self) -> Result<NetworkInterface, Box<dyn std::error::Error>> {
        use pnet::datalink;
        let interfaces = datalink::interfaces();

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
                        IpNextHeaderProtocols::Udp,
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
                        IpNextHeaderProtocols::Udp,
                    )),
                ) {
                    Ok((ts, _)) => Ok(ts),
                    Err(e) => Err(format!("{}", e).into()),
                }
            }
        }
    }

    fn send_packets(
        config: ScanConfig,
        mut sender: TransportSender,
        sent_ports: Arc<std::sync::Mutex<Vec<u16>>>,
    ) {
        println!(
            "Sending UDP packets to {} ports on {}...",
            config.ports_to_scan.len(),
            config.destination_ip
        );

        for &destination_port in &config.ports_to_scan {
            let mut vec = vec![0; 64]; // Small UDP packet
            if let Some(mut udp_packet) = MutableUdpPacket::new(&mut vec) {
                udp_packet.set_source(config.source_port);
                udp_packet.set_destination(destination_port);
                udp_packet.set_length(64);
                udp_packet.set_checksum(0); // Let kernel calculate

                if let Err(e) = sender.send_to(udp_packet.to_immutable(), config.destination_ip) {
                    eprintln!("Error sending UDP packet: {}", e);
                } else {
                    if let Ok(mut ports) = sent_ports.lock() {
                        ports.push(destination_port);
                    }
                }
            } else {
                eprintln!("Failed to create UDP packet for port {}", destination_port);
            }

            thread::sleep(Duration::from_millis(10));
        }
    }

    fn receive_packets(
        config: ScanConfig,
        mut rx: Box<dyn pnet::datalink::DataLinkReceiver>,
    ) -> Vec<u16> {
        let mut icmp_ports = Vec::new();
        let start = Instant::now();

        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(eth_packet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                        match eth_packet.get_ethertype() {
                            pnet::packet::ethernet::EtherTypes::Ipv4 => {
                                if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                                    if ipv4_packet.get_next_level_protocol()
                                        == IpNextHeaderProtocols::Icmp
                                        && ipv4_packet.get_source()
                                            == match config.destination_ip {
                                                IpAddr::V4(ip) => ip,
                                                _ => continue,
                                            }
                                    {
                                        if let Some(icmp_packet) =
                                            IcmpPacket::new(ipv4_packet.payload())
                                        {
                                            if icmp_packet.get_icmp_type()
                                                == IcmpTypes::DestinationUnreachable
                                                && icmp_packet.get_icmp_code().0 == 3
                                            // Port unreachable
                                            {
                                                // Extract original UDP port from ICMP payload
                                                // ICMP payload structure: 4 bytes unused + original IP header (20 bytes) + original UDP header
                                                let payload = icmp_packet.payload();
                                                if payload.len() >= 28 {
                                                    // 4 (unused) + 20 (IP header) + 8 (UDP header minimum)
                                                    // Skip 4 bytes unused + 20 bytes IP header = 24 bytes offset
                                                    if let Some(udp_packet) =
                                                        UdpPacket::new(&payload[24..])
                                                    {
                                                        icmp_ports
                                                            .push(udp_packet.get_destination());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {:?}", e);
                }
            }

            if Instant::now().duration_since(start) > config.timeout {
                break;
            }
        }

        icmp_ports
    }
}
