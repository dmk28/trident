use super::types::{DatabaseInfo, DatabaseProbeError};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

pub struct MySQLProber {
    connection_timeout: Duration,
    read_timeout: Duration,
}

impl MySQLProber {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Test protocols where server sends greeting first (MySQL, MariaDB)
    pub async fn probe_server_first_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        let mut buffer = vec![0u8; 1024];

        // Wait for server to speak first
        let bytes_read = timeout(self.read_timeout, stream.readable())
            .await
            .map_err(|_| DatabaseProbeError::Timeout)?;

        let mut stream = stream;
        let n = stream.read(&mut buffer).await?;

        if n == 0 {
            return Err(DatabaseProbeError::InvalidResponse);
        }

        let response = String::from_utf8_lossy(&buffer[..n]);

        // MySQL greeting packet analysis
        if self.is_mysql_greeting(&buffer[..n]) {
            return self.parse_mysql_greeting(&buffer[..n]).await;
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Check if response looks like MySQL greeting packet
    pub fn is_mysql_greeting(&self, data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }

        // MySQL greeting packet starts with packet length + sequence number
        // Byte 4 should be protocol version (usually 10)
        data.len() > 4 && data[4] == 10
    }

    /// Parse MySQL greeting packet to extract version and capabilities
    pub async fn parse_mysql_greeting(
        &self,
        data: &[u8],
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        if data.len() < 10 {
            return Err(DatabaseProbeError::ProtocolError(
                "MySQL greeting too short".to_string(),
            ));
        }

        let mut info = DatabaseInfo {
            service_type: "MySQL".to_string(),
            version: None,
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(false), // MySQL/MariaDB is case-insensitive
            handshake_steps: 1,          // Single-step authentication process
            additional_info: HashMap::new(),
            raw_banner: Some(String::from_utf8_lossy(data).to_string()),
        };

        // Extract version string (null-terminated string starting at byte 5)
        let version_start = 5;
        if let Some(null_pos) = data[version_start..].iter().position(|&b| b == 0) {
            let version_bytes = &data[version_start..version_start + null_pos];
            if let Ok(version) = String::from_utf8(version_bytes.to_vec()) {
                info.version = Some(version.clone());
                info.additional_info
                    .insert("server_version".to_string(), version);
            }
        }

        // Extract server capabilities (2 bytes after version string + other data)
        // This is where we'd parse capability flags to determine features

        Ok(info)
    }

    pub async fn test_mysql_anonymous_access(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<bool, DatabaseProbeError> {
        // Implement MySQL anonymous connection attempt
        // This would involve sending login packet with empty credentials
        Ok(false) // Placeholder
    }

    pub async fn test_mysql_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<Option<bool>, DatabaseProbeError> {
        // MySQL/MariaDB is generally case-insensitive for identifiers
        // but this can be configured. We'll test by attempting connections
        // with different case variations in database names
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // Wait for server greeting
        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 && self.is_mysql_greeting(&buffer[..n]) {
            // Attempt case sensitivity test through login packet variations
            // This is a simplified test - full implementation would require
            // complete MySQL protocol implementation
            Ok(Some(false)) // MySQL is typically case-insensitive
        } else {
            Ok(None)
        }
    }
}

impl Default for MySQLProber {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level convenience function
pub async fn probe_mysql(ip: IpAddr, port: u16) -> Result<DatabaseInfo, DatabaseProbeError> {
    let prober = MySQLProber::new();
    prober.probe_server_first_protocol(ip, port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_greeting_detection() {
        let prober = MySQLProber::new();

        // Mock MySQL greeting packet
        let mysql_greeting = vec![
            0x4a, 0x00, 0x00, 0x00, // packet length + sequence
            0x0a, // protocol version 10
            b'5', b'.', b'7', b'.', b'3', b'4', 0x00, // version string + null
        ];

        assert!(prober.is_mysql_greeting(&mysql_greeting));

        // Non-MySQL data
        let not_mysql = vec![0x00, 0x01, 0x02, 0x03];
        assert!(!prober.is_mysql_greeting(&not_mysql));
    }
}
