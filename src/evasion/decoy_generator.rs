use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::util;
use pnet_transport::{TransportChannelType, TransportSender, transport_channel};
use rand::Rng;
use rayon::prelude::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

/// Raw packet data for decoy transmission
#[derive(Debug, Clone)]
pub struct DecoyPacket {
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub scan_type: ScanType,
    pub payload: Vec<u8>,
}

/// Types of scans that can be used for decoys
#[derive(Debug, Clone, Copy)]
pub enum ScanType {
    TcpSyn,
    TcpAck,
    TcpFin,
    TcpNull,
    TcpXmas,
}

/// Decoy generator that creates and sends spoofed packets
pub struct DecoyGenerator {
    ipv4_sender: Arc<Mutex<Option<TransportSender>>>,
    ipv6_sender: Arc<Mutex<Option<TransportSender>>>,
    verbose: bool,
}

impl DecoyGenerator {
    /// Create a new decoy generator with raw socket capabilities
    pub fn new() -> Self {
        Self::new_with_verbose(false)
    }

    /// Create a new decoy generator with verbose output control
    pub fn new_with_verbose(verbose: bool) -> Self {
        // Try to create raw socket channels
        let ipv4_sender = Self::create_ipv4_sender(verbose);
        let ipv6_sender = Self::create_ipv6_sender(verbose);

        if ipv4_sender.is_none() && ipv6_sender.is_none() && verbose {
            eprintln!(
                "⚠️  Warning: Could not create raw sockets. Decoy generation may require elevated privileges."
            );
        }

        Self {
            ipv4_sender: Arc::new(Mutex::new(ipv4_sender)),
            ipv6_sender: Arc::new(Mutex::new(ipv6_sender)),
            verbose,
        }
    }

    /// Create IPv4 raw socket sender
    fn create_ipv4_sender(verbose: bool) -> Option<TransportSender> {
        match transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv4),
        ) {
            Ok((sender, _)) => {
                if verbose {
                    println!("✅ IPv4 raw socket created successfully");
                }
                Some(sender)
            }
            Err(e) => {
                if verbose {
                    eprintln!("❌ Failed to create IPv4 raw socket: {}", e);
                }
                None
            }
        }
    }

    /// Create IPv6 raw socket sender
    fn create_ipv6_sender(verbose: bool) -> Option<TransportSender> {
        match transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv6),
        ) {
            Ok((sender, _)) => {
                if verbose {
                    println!("✅ IPv6 raw socket created successfully");
                }
                Some(sender)
            }
            Err(e) => {
                if verbose {
                    eprintln!("❌ Failed to create IPv6 raw socket: {}", e);
                }
                None
            }
        }
    }

    /// Generate and send decoy packets along with the real scan using rayon for parallelization
    pub async fn send_decoy_scan(
        &mut self,
        real_source: IpAddr,
        target: IpAddr,
        target_port: u16,
        decoy_ips: Vec<IpAddr>,
        scan_type: ScanType,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut rng = rand::rng();

        // Create all packets (decoys + real)
        let mut all_packets = Vec::new();

        // Add decoy packets
        for decoy_ip in decoy_ips {
            let source_port = Self::generate_random_port();
            let packet = DecoyPacket {
                source_ip: decoy_ip,
                dest_ip: target,
                source_port,
                dest_port: target_port,
                scan_type,
                payload: Vec::new(),
            };
            all_packets.push((packet, false)); // false = decoy
        }

        // Add real packet
        let real_source_port = Self::generate_random_port();
        let real_packet = DecoyPacket {
            source_ip: real_source,
            dest_ip: target,
            source_port: real_source_port,
            dest_port: target_port,
            scan_type,
            payload: Vec::new(),
        };
        all_packets.push((real_packet, true)); // true = real

        // Randomize order to hide the real scan
        use rand::seq::SliceRandom;
        all_packets.shuffle(&mut rng);

        // Use rayon for parallel packet sending
        let packets_sent = Arc::new(AtomicUsize::new(0));
        let verbose = self.verbose;
        let ipv4_sender_arc = self.ipv4_sender.clone();
        let ipv6_sender_arc = self.ipv6_sender.clone();

        // Use rayon's parallel iterator for CPU-bound work
        all_packets.par_iter().for_each(|(packet, is_real)| {
            let packet_clone = packet.clone();

            // Add some random delay to each packet
            let delay = rand::rng().random_range(10..=100);
            std::thread::sleep(Duration::from_millis(delay));

            let send_result =
                Self::send_packet_sync(&ipv4_sender_arc, &ipv6_sender_arc, &packet_clone);

            match send_result {
                Ok(_) => {
                    packets_sent.fetch_add(1, Ordering::Relaxed);
                    if verbose {
                        if *is_real {
                            println!(
                                "🎯 Real scan packet sent from {} to {}:{}",
                                packet.source_ip, packet.dest_ip, packet.dest_port
                            );
                        } else {
                            println!(
                                "🥷 Decoy packet sent from {} to {}:{}",
                                packet.source_ip, packet.dest_ip, packet.dest_port
                            );
                        }
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!("❌ Failed to send packet from {}: {}", packet.source_ip, e);
                    }
                }
            }
        });

        let final_count = packets_sent.load(Ordering::Relaxed);
        Ok(final_count)
    }

    /// Synchronous packet sending for use with rayon
    fn send_packet_sync(
        ipv4_sender: &Arc<Mutex<Option<TransportSender>>>,
        ipv6_sender: &Arc<Mutex<Option<TransportSender>>>,
        packet: &DecoyPacket,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match packet.source_ip {
            IpAddr::V4(src_ipv4) => {
                let mut sender_guard = ipv4_sender.lock().unwrap();
                if let Some(ref mut sender) = *sender_guard {
                    let dest_ipv4 = match packet.dest_ip {
                        IpAddr::V4(ip) => ip,
                        _ => return Err("IPv4 sender cannot send to IPv6 destination".into()),
                    };
                    Self::send_ipv4_packet(sender, src_ipv4, dest_ipv4, packet)
                } else {
                    Err("IPv4 raw socket not available".into())
                }
            }
            IpAddr::V6(src_ipv6) => {
                let mut sender_guard = ipv6_sender.lock().unwrap();
                if let Some(ref mut sender) = *sender_guard {
                    let dest_ipv6 = match packet.dest_ip {
                        IpAddr::V6(ip) => ip,
                        _ => return Err("IPv6 sender cannot send to IPv4 destination".into()),
                    };
                    Self::send_ipv6_packet(sender, src_ipv6, dest_ipv6, packet)
                } else {
                    Err("IPv6 raw socket not available".into())
                }
            }
        }
    }

    /// Send a single packet using raw sockets (for compatibility)
    async fn send_packet(
        &mut self,
        packet: &DecoyPacket,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Self::send_packet_sync(&self.ipv4_sender, &self.ipv6_sender, packet)
    }

    /// Send IPv4 packet with TCP header
    fn send_ipv4_packet(
        sender: &mut TransportSender,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        packet: &DecoyPacket,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create buffer for IP + TCP headers
        let mut buffer = vec![0u8; 40]; // 20 bytes IP + 20 bytes TCP

        // Build IPv4 header
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer[..20]).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(40);
            ipv4_packet.set_identification(rand::rng().random::<u16>());
            ipv4_packet.set_flags(Ipv4Flags::DontFragment);
            ipv4_packet.set_fragment_offset(0);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ipv4_packet.set_source(src_ip);
            ipv4_packet.set_destination(dest_ip);

            let checksum = util::checksum(ipv4_packet.packet(), 5);
            ipv4_packet.set_checksum(checksum);
        }

        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[20..]).unwrap();
            tcp_packet.set_source(packet.source_port);
            tcp_packet.set_destination(packet.dest_port);
            tcp_packet.set_sequence(rand::rng().random::<u32>());
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_reserved(0);

            // Set TCP flags based on scan type
            let flags = match packet.scan_type {
                ScanType::TcpSyn => TcpFlags::SYN,
                ScanType::TcpAck => TcpFlags::ACK,
                ScanType::TcpFin => TcpFlags::FIN,
                ScanType::TcpNull => 0,
                ScanType::TcpXmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            };
            tcp_packet.set_flags(flags);

            tcp_packet.set_window(1024);
            tcp_packet.set_urgent_ptr(0);

            // Calculate TCP checksum
            let checksum = util::ipv4_checksum(
                tcp_packet.packet(),
                8, // TCP header length in bytes / 2
                &[],
                &src_ip,
                &dest_ip,
                pnet::packet::ip::IpNextHeaderProtocols::Tcp,
            );
            tcp_packet.set_checksum(checksum);
        }

        // Send the packet
        sender.send_to(
            MutableIpv4Packet::new(&mut buffer).unwrap(),
            IpAddr::V4(dest_ip),
        )?;

        Ok(())
    }

    /// Send IPv6 packet with TCP header
    fn send_ipv6_packet(
        sender: &mut TransportSender,
        src_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        packet: &DecoyPacket,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create buffer for IPv6 + TCP headers
        let mut buffer = vec![0u8; 60]; // 40 bytes IPv6 + 20 bytes TCP

        // Build IPv6 header
        {
            let mut ipv6_packet = MutableIpv6Packet::new(&mut buffer[..40]).unwrap();
            ipv6_packet.set_version(6);
            ipv6_packet.set_traffic_class(0);
            ipv6_packet.set_flow_label(0);
            ipv6_packet.set_payload_length(20); // TCP header length
            ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_source(src_ip);
            ipv6_packet.set_destination(dest_ip);
        }

        // Build TCP header (same as IPv4)
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[40..]).unwrap();
            tcp_packet.set_source(packet.source_port);
            tcp_packet.set_destination(packet.dest_port);
            tcp_packet.set_sequence(rand::rng().random::<u32>());
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_reserved(0);

            let flags = match packet.scan_type {
                ScanType::TcpSyn => TcpFlags::SYN,
                ScanType::TcpAck => TcpFlags::ACK,
                ScanType::TcpFin => TcpFlags::FIN,
                ScanType::TcpNull => 0,
                ScanType::TcpXmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            };
            tcp_packet.set_flags(flags);

            tcp_packet.set_window(1024);
            tcp_packet.set_urgent_ptr(0);

            // Calculate TCP checksum for IPv6
            let checksum = util::ipv6_checksum(
                tcp_packet.packet(),
                8, // TCP header length in bytes / 2
                &[],
                &src_ip,
                &dest_ip,
                pnet::packet::ip::IpNextHeaderProtocols::Tcp,
            );
            tcp_packet.set_checksum(checksum);
        }

        // Send the packet
        sender.send_to(
            MutableIpv6Packet::new(&mut buffer).unwrap(),
            IpAddr::V6(dest_ip),
        )?;

        Ok(())
    }

    /// Generate a random source port
    fn generate_random_port() -> u16 {
        let mut rng = rand::rng();
        rng.random_range(32768..=65535)
    }

    /// Check if raw sockets are available
    pub fn is_available(&self) -> bool {
        let ipv4_available = self.ipv4_sender.lock().unwrap().is_some();
        let ipv6_available = self.ipv6_sender.lock().unwrap().is_some();
        ipv4_available || ipv6_available
    }

    /// Get capabilities as a string for debugging
    pub fn capabilities(&self) -> String {
        let mut caps = Vec::new();
        if self.ipv4_sender.lock().unwrap().is_some() {
            caps.push("IPv4");
        }
        if self.ipv6_sender.lock().unwrap().is_some() {
            caps.push("IPv6");
        }
        if caps.is_empty() {
            "No raw socket capabilities".to_string()
        } else {
            format!("Raw sockets: {}", caps.join(", "))
        }
    }
}

impl Drop for DecoyGenerator {
    fn drop(&mut self) {
        let ipv4_available = self.ipv4_sender.lock().unwrap().is_some();
        let ipv6_available = self.ipv6_sender.lock().unwrap().is_some();
        if (ipv4_available || ipv6_available) && self.verbose {
            println!("🔒 Raw socket resources cleaned up");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_packet_creation() {
        let packet = DecoyPacket {
            source_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            source_port: 12345,
            dest_port: 80,
            scan_type: ScanType::TcpSyn,
            payload: Vec::new(),
        };

        assert_eq!(packet.source_port, 12345);
        assert_eq!(packet.dest_port, 80);
        matches!(packet.scan_type, ScanType::TcpSyn);
    }

    #[test]
    fn test_port_generation() {
        // Test that generated ports are in ephemeral range
        for _ in 0..100 {
            let port = DecoyGenerator::generate_random_port();
            assert!(port >= 32768);
            assert!(port <= 65535);
        }
    }

    #[tokio::test]
    async fn test_decoy_generator_creation() {
        let generator = DecoyGenerator::new();
        // Just verify it doesn't panic and provides some status
        let caps = generator.capabilities();
        assert!(!caps.is_empty());
    }
}
