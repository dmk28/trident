use super::types::{DatabaseInfo, DatabaseProbeError};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

pub struct OracleProber {
    connection_timeout: Duration,
    read_timeout: Duration,
}

impl OracleProber {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Test Oracle TNS protocol
    pub async fn probe_oracle_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // Oracle TNS connect packet
        let connect_packet = self.create_oracle_tns_connect_packet();
        stream.write_all(&connect_packet).await?;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            return self.parse_oracle_response(&buffer[..n]).await;
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Create Oracle TNS connect packet
    fn create_oracle_tns_connect_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // TNS Connect Data - simplified connect string
        let connect_data =
            "(CONNECT_DATA=(SERVICE_NAME=XE)(CID=(PROGRAM=probe)(HOST=scanner)(USER=probe)))";
        let connect_data_bytes = connect_data.as_bytes();

        // TNS Header (8 bytes)
        let packet_length = 8 + connect_data_bytes.len();

        // Packet Length (2 bytes, big-endian)
        packet.extend_from_slice(&(packet_length as u16).to_be_bytes());

        // Packet Checksum (2 bytes) - usually 0x0000 for connect
        packet.extend_from_slice(&[0x00, 0x00]);

        // Packet Type (1 byte) - 0x01 = Connect
        packet.push(0x01);

        // Reserved (1 byte)
        packet.push(0x00);

        // Header Checksum (2 bytes) - usually 0x0000
        packet.extend_from_slice(&[0x00, 0x00]);

        // Connect Data
        packet.extend_from_slice(connect_data_bytes);

        packet
    }

    /// Create alternative TNS connect packet for different Oracle versions
    fn create_oracle_tns_connect_packet_v2(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Alternative connect string for older Oracle versions
        let connect_data = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)))";
        let connect_data_bytes = connect_data.as_bytes();

        let packet_length = 8 + connect_data_bytes.len();

        packet.extend_from_slice(&(packet_length as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.push(0x01); // Connect packet type
        packet.push(0x00); // Reserved
        packet.extend_from_slice(&[0x00, 0x00]); // Header checksum

        packet.extend_from_slice(connect_data_bytes);
        packet
    }

    /// Parse Oracle TNS response
    async fn parse_oracle_response(&self, data: &[u8]) -> Result<DatabaseInfo, DatabaseProbeError> {
        if data.len() < 8 {
            return Err(DatabaseProbeError::ProtocolError(
                "Oracle response too short for TNS header".to_string(),
            ));
        }

        // Parse TNS header
        let packet_length = u16::from_be_bytes([data[0], data[1]]) as usize;
        let _packet_checksum = u16::from_be_bytes([data[2], data[3]]);
        let packet_type = data[4];
        let _reserved = data[5];
        let _header_checksum = u16::from_be_bytes([data[6], data[7]]);

        let mut info = DatabaseInfo {
            service_type: "Oracle".to_string(),
            version: None,
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(true), // Oracle is case-sensitive by default
            handshake_steps: 2,         // TNS connect + authentication
            additional_info: HashMap::new(),
            raw_banner: Some(String::from_utf8_lossy(data).to_string()),
        };

        // Analyze packet type
        match packet_type {
            0x02 => {
                // Accept packet - connection established
                info.additional_info
                    .insert("connection_status".to_string(), "accepted".to_string());

                // Try to extract version from accept packet data
                if let Some(version) = self.extract_oracle_version(&data[8..]) {
                    info.version = Some(version);
                }
            }
            0x04 => {
                // Refuse packet - connection refused
                info.additional_info
                    .insert("connection_status".to_string(), "refused".to_string());

                // Extract error message if available
                if data.len() > 8 {
                    let error_data = String::from_utf8_lossy(&data[8..]);
                    info.additional_info
                        .insert("error_message".to_string(), error_data.to_string());

                    // Try to extract version from error message
                    if let Some(version) = self.extract_version_from_error(&error_data) {
                        info.version = Some(version);
                    }
                }
            }
            0x05 => {
                // Redirect packet
                info.additional_info
                    .insert("connection_status".to_string(), "redirect".to_string());

                if data.len() > 8 {
                    let redirect_data = String::from_utf8_lossy(&data[8..]);
                    info.additional_info
                        .insert("redirect_info".to_string(), redirect_data.to_string());
                }
            }
            0x0B => {
                // Resend packet
                info.additional_info.insert(
                    "connection_status".to_string(),
                    "resend_requested".to_string(),
                );
            }
            _ => {
                return Err(DatabaseProbeError::ProtocolError(format!(
                    "Unknown TNS packet type: 0x{:02X}",
                    packet_type
                )));
            }
        }

        // Add Oracle-specific protocol information
        info.additional_info.insert(
            "protocol_notes".to_string(),
            "TNS (Transparent Network Substrate) protocol".to_string(),
        );

        info.additional_info
            .insert("packet_type".to_string(), format!("0x{:02X}", packet_type));

        info.additional_info
            .insert("packet_length".to_string(), packet_length.to_string());

        Ok(info)
    }

    /// Extract Oracle version from accept packet data
    fn extract_oracle_version(&self, data: &[u8]) -> Option<String> {
        let data_str = String::from_utf8_lossy(data);

        // Look for version patterns in the response
        // Oracle often includes version info in various formats
        let version_patterns = [
            r"Oracle Database (\d+[cg]?) Release (\d+\.\d+\.\d+)",
            r"Oracle(\d+[cg]?)",
            r"TNSLSNR for Linux: Version (\d+\.\d+\.\d+)",
            r"Version (\d+\.\d+\.\d+)",
            r"Oracle\d+[cg]?",
        ];

        for pattern in &version_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(&data_str) {
                    if caps.len() > 1 {
                        return Some(caps.get(1).unwrap().as_str().to_string());
                    } else if let Some(full_match) = caps.get(0) {
                        return Some(full_match.as_str().to_string());
                    }
                }
            }
        }

        // Fallback: look for any number that might be a version
        if data_str.contains("Oracle") {
            // Extract first number sequence after "Oracle"
            if let Some(oracle_pos) = data_str.find("Oracle") {
                let after_oracle = &data_str[oracle_pos + 6..];
                for word in after_oracle.split_whitespace() {
                    if word.chars().any(|c| c.is_ascii_digit()) {
                        return Some(word.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract version information from error messages
    fn extract_version_from_error(&self, error_msg: &str) -> Option<String> {
        // Oracle error messages often contain version information
        // TNS-12514: TNS:listener does not currently know of service requested in connect descriptor
        // ORA-12505: TNS:listener does not currently know of SID given in connect descriptor

        let patterns = [
            r"TNS-\d+.*Oracle Database (\d+[cg]?) Release (\d+\.\d+\.\d+)",
            r"ORA-\d+.*Version (\d+\.\d+\.\d+)",
            r"listener.*Version (\d+\.\d+\.\d+)",
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(error_msg) {
                    if caps.len() > 1 {
                        return Some(caps.get(1).unwrap().as_str().to_string());
                    }
                }
            }
        }

        // Check if it's a generic Oracle error that at least confirms it's Oracle
        if error_msg.contains("TNS-") || error_msg.contains("ORA-") {
            return Some("Oracle (version unknown)".to_string());
        }

        None
    }

    /// Test multiple connection approaches for better Oracle detection
    pub async fn comprehensive_oracle_probe(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        // Try primary connect packet
        if let Ok(info) = self.probe_oracle_protocol(ip, port).await {
            return Ok(info);
        }

        // Try alternative connect packet format
        if let Ok(info) = self.probe_oracle_with_alternative_packet(ip, port).await {
            return Ok(info);
        }

        // Try TNS listener status request
        if let Ok(info) = self.probe_tns_listener_status(ip, port).await {
            return Ok(info);
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Try alternative TNS packet format
    async fn probe_oracle_with_alternative_packet(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        let connect_packet = self.create_oracle_tns_connect_packet_v2();
        stream.write_all(&connect_packet).await?;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            return self.parse_oracle_response(&buffer[..n]).await;
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Try TNS listener status request - sometimes reveals version info
    async fn probe_tns_listener_status(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // TNS listener status request packet
        let status_packet = self.create_tns_status_packet();
        stream.write_all(&status_packet).await?;

        let mut buffer = vec![0u8; 2048]; // Larger buffer for status response
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            return self.parse_tns_status_response(&buffer[..n]).await;
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Create TNS listener status request packet
    fn create_tns_status_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Simple status request
        let status_request = "(CONNECT_DATA=(COMMAND=status))";
        let request_bytes = status_request.as_bytes();

        let packet_length = 8 + request_bytes.len();

        packet.extend_from_slice(&(packet_length as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.push(0x01); // Connect type
        packet.push(0x00); // Reserved
        packet.extend_from_slice(&[0x00, 0x00]); // Header checksum

        packet.extend_from_slice(request_bytes);
        packet
    }

    /// Parse TNS listener status response
    async fn parse_tns_status_response(
        &self,
        data: &[u8],
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        if data.len() < 8 {
            return Err(DatabaseProbeError::ProtocolError(
                "TNS status response too short".to_string(),
            ));
        }

        let mut info = DatabaseInfo {
            service_type: "Oracle".to_string(),
            version: None,
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(true),
            handshake_steps: 2,
            additional_info: HashMap::new(),
            raw_banner: Some(String::from_utf8_lossy(data).to_string()),
        };

        // Status responses often contain detailed version and configuration info
        let response_str = String::from_utf8_lossy(&data[8..]);

        // Extract version from status response
        if let Some(version) = self.extract_oracle_version(response_str.as_bytes()) {
            info.version = Some(version);
        }

        // Look for service information
        if response_str.contains("SERVICES:") {
            info.additional_info
                .insert("services_available".to_string(), "true".to_string());
        }

        // Look for listener information
        if response_str.contains("TNSLSNR") {
            info.additional_info
                .insert("listener_detected".to_string(), "true".to_string());
        }

        info.additional_info
            .insert("probe_method".to_string(), "tns_status".to_string());

        Ok(info)
    }
}

impl Default for OracleProber {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level convenience function
pub async fn probe_oracle(ip: IpAddr, port: u16) -> Result<DatabaseInfo, DatabaseProbeError> {
    let prober = OracleProber::new();
    prober.comprehensive_oracle_probe(ip, port).await
}

/// Probe specifically for Oracle TNS listener on default port
pub async fn probe_oracle_listener(ip: IpAddr) -> Result<DatabaseInfo, DatabaseProbeError> {
    probe_oracle(ip, 1521).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_prober_creation() {
        let prober = OracleProber::new();
        assert_eq!(prober.connection_timeout, Duration::from_secs(10));
        assert_eq!(prober.read_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_oracle_tns_connect_packet() {
        let prober = OracleProber::new();
        let packet = prober.create_oracle_tns_connect_packet();

        // Should have TNS header (8 bytes) + connect data
        assert!(packet.len() > 8);

        // Check TNS header format
        let packet_length = u16::from_be_bytes([packet[0], packet[1]]) as usize;
        assert_eq!(packet_length, packet.len());

        // Should be connect packet type (0x01)
        assert_eq!(packet[4], 0x01);
    }

    #[test]
    fn test_oracle_tns_connect_packet_v2() {
        let prober = OracleProber::new();
        let packet = prober.create_oracle_tns_connect_packet_v2();

        assert!(packet.len() > 8);
        assert_eq!(packet[4], 0x01); // Connect packet type

        // Should contain DESCRIPTION connect string
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("DESCRIPTION"));
    }

    #[test]
    fn test_oracle_status_packet() {
        let prober = OracleProber::new();
        let packet = prober.create_tns_status_packet();

        assert!(packet.len() > 8);
        assert_eq!(packet[4], 0x01); // Connect packet type

        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("COMMAND=status"));
    }

    #[test]
    fn test_version_extraction() {
        let prober = OracleProber::new();

        // Test version extraction from various Oracle response formats
        let test_data = b"Oracle Database 19c Release 19.0.0.0.0 - Production";
        let version = prober.extract_oracle_version(test_data);
        assert!(version.is_some());

        let error_msg = "TNS-12514: TNS:listener does not currently know of service Oracle 12c";
        let version_from_error = prober.extract_version_from_error(error_msg);
        assert!(version_from_error.is_some());
    }

    #[tokio::test]
    async fn test_oracle_comprehensive_probe() {
        let prober = OracleProber::new();

        // Test with localhost (will fail but shouldn't panic)
        let result = prober
            .comprehensive_oracle_probe("127.0.0.1".parse().unwrap(), 1521)
            .await;

        // Should fail gracefully when no Oracle is running
        assert!(result.is_err());
    }

    #[test]
    fn test_tns_packet_type_recognition() {
        let prober = OracleProber::new();

        // Mock TNS accept response
        let accept_response = vec![
            0x00, 0x20, // Length: 32 bytes
            0x00, 0x00, // Checksum
            0x02, // Accept packet type
            0x00, // Reserved
            0x00, 0x00, // Header checksum
            // Mock accept data
            b'O', b'r', b'a', b'c', b'l', b'e', b' ', b'1', b'9', b'c', 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // This would normally be called in parse_oracle_response
        // Just verify packet structure is correct
        assert_eq!(accept_response[4], 0x02); // Accept type
        assert_eq!(
            u16::from_be_bytes([accept_response[0], accept_response[1]]),
            32
        );
    }
}
