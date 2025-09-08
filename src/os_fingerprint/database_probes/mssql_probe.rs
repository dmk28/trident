use super::types::{DatabaseInfo, DatabaseProbeError};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

pub struct MSSQLProber {
    connection_timeout: Duration,
    read_timeout: Duration,
}

impl MSSQLProber {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Test MSSQL/TDS protocol
    pub async fn probe_mssql_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // MSSQL TDS protocol handshake
        let handshake = self.create_mssql_prelogin_packet();
        stream.write_all(&handshake).await?;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            return self.parse_mssql_response(&buffer[..n]).await;
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Create TDS pre-login packet
    fn create_mssql_prelogin_packet(&self) -> Vec<u8> {
        let mut message = Vec::new();

        // TDS Header (8 bytes)
        message.extend_from_slice(&[0x12, 0x01, 0x00, 0x14]); // Type, Status, Length (20 bytes)
        message.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // SPID, PacketNum, Window

        // Token table
        message.extend_from_slice(&[0x00]); // Version token
        message.extend_from_slice(&[0x00, 0x08]); // Offset (8 bytes into data section)
        message.extend_from_slice(&[0x00, 0x06]); // Length (6 bytes of version data)
        message.extend_from_slice(&[0xFF]); // Terminator

        // Version data (6 bytes)
        message.extend_from_slice(&[0x08, 0x00, 0x01, 0x55, 0x00, 0x00]); // Version 8.0.341.0

        message
    }

    /// Parse MSSQL TDS response
    async fn parse_mssql_response(&self, data: &[u8]) -> Result<DatabaseInfo, DatabaseProbeError> {
        if data.len() < 8 {
            return Err(DatabaseProbeError::ProtocolError(
                "MSSQL response too short for TDS header".to_string(),
            ));
        }

        let packet_type = data[0];
        if packet_type != 0x04 {
            return Err(DatabaseProbeError::ProtocolError(
                "Not a TDS response packet".to_string(),
            ));
        }

        let mut pos = 8;
        let mut version_info: Option<String> = None;

        while pos + 5 <= data.len() {
            let token_type = data[pos];

            if token_type == 0xFF {
                break;
            }

            if token_type == 0x00 {
                let offset = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
                let length = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;

                let data_start = self.find_data_section_start(&data[8..])? + 8;
                let version_start = data_start + offset;

                if version_start + length <= data.len() && length >= 6 {
                    let version_bytes = &data[version_start..version_start + 6];
                    let major = version_bytes[0];
                    let minor = version_bytes[1];
                    let build = u16::from_le_bytes([version_bytes[2], version_bytes[3]]);
                    let revision = u16::from_le_bytes([version_bytes[4], version_bytes[5]]);

                    version_info = Some(format!("{}.{}.{}.{}", major, minor, build, revision));
                }
            }
            pos += 5;
        }

        let mut info = DatabaseInfo {
            service_type: "MSSQL".to_string(),
            version: version_info,
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(true), // MSSQL can be case-sensitive depending on collation
            handshake_steps: 3,         // TDS has 3-step handshake
            additional_info: HashMap::new(),
            raw_banner: Some(String::from_utf8_lossy(data).to_string()),
        };

        info.additional_info.insert(
            "protocol_notes".to_string(),
            "TDS protocol, three-step handshake (init + auth + data)".to_string(),
        );

        Ok(info)
    }

    /// Find where the data section starts after token table
    fn find_data_section_start(&self, token_data: &[u8]) -> Result<usize, DatabaseProbeError> {
        let mut pos = 0;
        while pos < token_data.len() {
            if token_data[pos] == 0xFF {
                return Ok(pos + 1);
            }
            pos += 5;
        }
        Err(DatabaseProbeError::ProtocolError(
            "No token terminator found".to_string(),
        ))
    }

    pub async fn test_mssql_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<Option<bool>, DatabaseProbeError> {
        // MSSQL case sensitivity depends on collation settings
        // This would require actual authentication and queries to test properly
        Ok(Some(true)) // Default assumption - depends on server collation
    }
}

impl Default for MSSQLProber {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level convenience function
pub async fn probe_mssql(ip: IpAddr, port: u16) -> Result<DatabaseInfo, DatabaseProbeError> {
    let prober = MSSQLProber::new();
    prober.probe_mssql_protocol(ip, port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mssql_prelogin_packet_structure() {
        let prober = MSSQLProber::new();
        let packet = prober.create_mssql_prelogin_packet();

        // Should be exactly 20 bytes
        assert_eq!(packet.len(), 20);

        // Should start with TDS prelogin packet type
        assert_eq!(packet[0], 0x12);

        // Should have correct status
        assert_eq!(packet[1], 0x01);

        // Should have correct length (20 bytes)
        assert_eq!(packet[2], 0x00);
        assert_eq!(packet[3], 0x14);
    }

    #[test]
    fn test_data_section_finder() {
        let prober = MSSQLProber::new();

        // Mock token data: [token][offset][length][terminator][data]
        let token_data = vec![0x00, 0x00, 0x05, 0x00, 0x06, 0xFF, 0x08, 0x00];

        let data_start = prober.find_data_section_start(&token_data).unwrap();
        assert_eq!(data_start, 6); // Should find terminator at position 5, data starts at 6
    }

    #[test]
    fn test_data_section_finder_no_terminator() {
        let prober = MSSQLProber::new();

        // Token data without terminator
        let token_data = vec![0x00, 0x00, 0x05, 0x00, 0x06];

        let result = prober.find_data_section_start(&token_data);
        assert!(result.is_err());
    }
}
