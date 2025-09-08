use crate::os_fingerprint::fingerprint_db::initialize_signature_database;
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::*};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct OsSignature {
    pub name: String,
    pub version: Option<String>,
    pub ttl_values: Vec<u8>,
    pub window_sizes: Vec<u16>,
    pub tcp_options: Vec<String>,
    pub confidence_weight: f32,
}

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub ttl: u8,
    pub window_size: u16,
    pub tcp_options: Option<Vec<String>>,
    pub source_ip: String,
    pub timestamp: u64,
}

pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

pub fn determine_tcp_options(tcp_packet: &TcpPacket) -> Vec<String> {
    tcp_packet
        .get_options()
        .iter()
        .map(|option| format!("{:?}", option.number))
        .collect()
}

pub fn extract_fingerprint(ip_packet: IpPacket, tcp_packet: &TcpPacket) -> CapturedPacket {
    let ttl = match ip_packet {
        IpPacket::V4(ref ipv4) => ipv4.get_ttl(),
        IpPacket::V6(ref ipv6) => ipv6.get_hop_limit(),
    };

    CapturedPacket {
        ttl,
        window_size: tcp_packet.get_window(),
        source_ip: match ip_packet {
            IpPacket::V4(ref ipv4) => ipv4.get_source().to_string(),
            IpPacket::V6(ref ipv6) => ipv6.get_source().to_string(),
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        tcp_options: Some(determine_tcp_options(tcp_packet)),
    }
}

#[derive(Debug, Clone)]
pub struct OsDetectionResult {
    pub os_name: String,
    pub version: Option<String>,
    pub confidence: f32,
    pub ttl_match: bool,
    pub window_match: bool,
    pub options_match: bool,
}

fn calculate_ttl_match(captured_ttl: u8, signature_ttls: &[u8]) -> bool {
    signature_ttls.iter().any(|&sig_ttl| {
        // Account for hop decrementation (TTL can be reduced by up to 10 hops)
        captured_ttl <= sig_ttl && captured_ttl >= sig_ttl.saturating_sub(10)
    })
}

fn calculate_window_match(captured_window: u16, signature_windows: &[u16]) -> bool {
    signature_windows.contains(&captured_window)
}

fn calculate_options_match(
    captured_options: &Option<Vec<String>>,
    signature_options: &[String],
) -> f32 {
    let Some(cap_opts) = captured_options else {
        return 0.0;
    };

    if signature_options.is_empty() && cap_opts.is_empty() {
        return 1.0;
    }

    let matches = signature_options
        .iter()
        .filter(|opt| cap_opts.contains(opt))
        .count();

    if signature_options.is_empty() {
        0.5 // Partial match if we have options but signature doesn't specify
    } else {
        matches as f32 / signature_options.len() as f32
    }
}

pub fn score_packet_against_signature(packet: &CapturedPacket, signature: &OsSignature) -> f32 {
    let ttl_match = calculate_ttl_match(packet.ttl, &signature.ttl_values);
    let window_match = calculate_window_match(packet.window_size, &signature.window_sizes);
    let options_score = calculate_options_match(&packet.tcp_options, &signature.tcp_options);

    let mut score = 0.0;
    let mut total_weight = 0.0;

    // TTL matching is most important (weight: 0.5)
    if ttl_match {
        score += 0.5;
    }
    total_weight += 0.5;

    // Window size matching (weight: 0.3)
    if window_match {
        score += 0.3;
    }
    total_weight += 0.3;

    // TCP options matching (weight: 0.2)
    score += options_score * 0.2;
    total_weight += 0.2;

    // Apply signature confidence weight
    (score / total_weight) * signature.confidence_weight
}

pub fn detect_os(packet: &CapturedPacket) -> Option<OsDetectionResult> {
    let db = initialize_signature_database();
    let mut best_match: Option<(OsDetectionResult, f32)> = None;

    for (_os_family, signatures) in &db {
        for signature in signatures {
            let score = score_packet_against_signature(packet, signature);

            if score > 0.3 {
                // Minimum confidence threshold
                let result = OsDetectionResult {
                    os_name: signature.name.clone(),
                    version: signature.version.clone(),
                    confidence: score,
                    ttl_match: calculate_ttl_match(packet.ttl, &signature.ttl_values),
                    window_match: calculate_window_match(
                        packet.window_size,
                        &signature.window_sizes,
                    ),
                    options_match: calculate_options_match(
                        &packet.tcp_options,
                        &signature.tcp_options,
                    ) > 0.5,
                };

                match &best_match {
                    None => best_match = Some((result, score)),
                    Some((_, best_score)) if score > *best_score => {
                        best_match = Some((result, score));
                    }
                    _ => {}
                }
            }
        }
    }

    best_match.map(|(result, _)| result)
}
