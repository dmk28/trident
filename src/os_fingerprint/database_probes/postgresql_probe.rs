use super::types::{DatabaseInfo, DatabaseProbeError};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

pub struct PostgreSQLProber {
    connection_timeout: Duration,
    read_timeout: Duration,
}

impl PostgreSQLProber {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }

    /// Test protocols where client must speak first (PostgreSQL)
    pub async fn probe_client_first_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // PostgreSQL startup message
        let startup_message = self.create_postgresql_startup_message();
        stream.write_all(&startup_message).await?;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            return self.parse_postgresql_response(&buffer[..n]).await;
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Create PostgreSQL startup message
    pub fn create_postgresql_startup_message(&self) -> Vec<u8> {
        let mut message = Vec::new();

        // Protocol version (3.0)
        message.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

        // Parameters (user, database, application_name)
        message.extend_from_slice(b"user\0postgres\0");
        message.extend_from_slice(b"database\0postgres\0");
        message.extend_from_slice(b"application_name\0probe\0");
        message.push(0); // Terminator

        // Prepend message length
        let len = (message.len() + 4) as u32;
        let mut full_message = len.to_be_bytes().to_vec();
        full_message.extend(message);

        full_message
    }

    /// Create PostgreSQL startup message with custom parameters
    pub fn create_postgresql_startup_message_with_params(
        &self,
        database: &str,
        username: &str,
    ) -> Vec<u8> {
        let mut message = Vec::new();

        // Protocol version (3.0)
        message.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

        // Parameters with custom database and username
        message.extend_from_slice(b"user\0");
        message.extend_from_slice(username.as_bytes());
        message.push(0);

        message.extend_from_slice(b"database\0");
        message.extend_from_slice(database.as_bytes());
        message.push(0);

        message.extend_from_slice(b"application_name\0case_test\0");
        message.push(0); // Terminator

        // Prepend message length
        let len = (message.len() + 4) as u32;
        let mut full_message = len.to_be_bytes().to_vec();
        full_message.extend(message);

        full_message
    }

    /// Parse PostgreSQL server response
    pub async fn parse_postgresql_response(
        &self,
        data: &[u8],
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        if data.is_empty() {
            return Err(DatabaseProbeError::InvalidResponse);
        }

        let mut info = DatabaseInfo {
            service_type: "PostgreSQL".to_string(),
            version: None,
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(true), // PostgreSQL is case-sensitive
            handshake_steps: 2,         // Two-step process: secure channel + authentication
            additional_info: HashMap::new(),
            raw_banner: Some(String::from_utf8_lossy(data).to_string()),
        };

        // PostgreSQL response analysis
        match data[0] {
            b'R' => {
                // Authentication request
                if data.len() >= 9 {
                    let auth_type = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                    match auth_type {
                        0 => {
                            info.authentication_required = false;
                            info.anonymous_access_possible = true;
                            info.additional_info
                                .insert("auth_method".to_string(), "trust".to_string());
                        }
                        3 => {
                            info.additional_info
                                .insert("auth_method".to_string(), "cleartext".to_string());
                        }
                        5 => {
                            info.additional_info
                                .insert("auth_method".to_string(), "md5".to_string());
                        }
                        _ => {
                            info.additional_info
                                .insert("auth_method".to_string(), format!("type_{}", auth_type));
                        }
                    }
                }
            }
            b'E' => {
                // Error response - still indicates PostgreSQL
                let error_msg = String::from_utf8_lossy(&data[1..]);
                info.additional_info
                    .insert("error".to_string(), error_msg.to_string());
            }
            _ => {
                return Err(DatabaseProbeError::ProtocolError(
                    "Unexpected PostgreSQL response".to_string(),
                ));
            }
        }

        Ok(info)
    }

    pub async fn test_postgresql_anonymous_access(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<bool, DatabaseProbeError> {
        // We already get this info from the authentication response
        // But we could try different usernames here
        Ok(false) // Placeholder
    }

    pub async fn test_postgresql_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<Option<bool>, DatabaseProbeError> {
        // PostgreSQL is case-sensitive by default
        // Test by connecting with different case variations
        let test_cases = vec![
            ("POSTGRES", "POSTGRES"),
            ("postgres", "postgres"),
            ("Postgres", "Postgres"),
        ];

        let mut case_sensitive_evidence = 0;
        let mut total_tests = 0;

        for (db_name, user_name) in test_cases {
            if let Ok(response) = self
                .test_postgresql_connection_case(ip, port, db_name, user_name)
                .await
            {
                total_tests += 1;
                if response.contains("database") && response.contains("does not exist") {
                    case_sensitive_evidence += 1;
                }
            }
        }

        if total_tests > 0 {
            // PostgreSQL is case-sensitive if we get different responses for different cases
            Ok(Some(case_sensitive_evidence > 0))
        } else {
            Ok(Some(true)) // Default assumption for PostgreSQL
        }
    }

    async fn test_postgresql_connection_case(
        &self,
        ip: IpAddr,
        port: u16,
        database: &str,
        username: &str,
    ) -> Result<String, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // Create startup message with specific database and username
        let startup_message =
            self.create_postgresql_startup_message_with_params(database, username);
        stream.write_all(&startup_message).await?;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
        } else {
            Err(DatabaseProbeError::InvalidResponse)
        }
    }
}

impl Default for PostgreSQLProber {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level convenience function
pub async fn probe_postgresql(ip: IpAddr, port: u16) -> Result<DatabaseInfo, DatabaseProbeError> {
    let prober = PostgreSQLProber::new();
    prober.probe_client_first_protocol(ip, port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgresql_startup_message() {
        let prober = PostgreSQLProber::new();
        let message = prober.create_postgresql_startup_message();

        // Should start with length
        assert!(message.len() > 4);

        // Should contain protocol version 3.0
        assert_eq!(&message[4..8], &[0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn test_postgresql_custom_startup_message() {
        let prober = PostgreSQLProber::new();
        let message = prober.create_postgresql_startup_message_with_params("TestDB", "testuser");

        // Should start with length
        assert!(message.len() > 4);

        // Should contain protocol version 3.0
        assert_eq!(&message[4..8], &[0x00, 0x03, 0x00, 0x00]);

        // Should contain our custom parameters
        let message_str = String::from_utf8_lossy(&message);
        assert!(message_str.contains("TestDB"));
        assert!(message_str.contains("testuser"));
    }
}
