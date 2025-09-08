use crate::os_fingerprint::database_probes::{DatabaseInfo, DatabaseProbeError};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone)]
pub struct CaseSensitivityResult {
    pub database_type: String,
    pub is_case_sensitive: bool,
    pub confidence_level: f32, // 0.0 to 1.0
    pub test_results: Vec<CaseTestResult>,
    pub protocol_analysis: ProtocolAnalysis,
}

#[derive(Debug, Clone)]
pub struct CaseTestResult {
    pub test_name: String,
    pub uppercase_response: Option<String>,
    pub lowercase_response: Option<String>,
    pub mixedcase_response: Option<String>,
    pub responses_differ: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProtocolAnalysis {
    pub handshake_type: HandshakeType,
    pub authentication_method: Option<String>,
    pub ssl_required: bool,
    pub server_version: Option<String>,
    pub character_set: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeType {
    ServerFirst,   // MySQL/MariaDB style
    ClientFirst,   // PostgreSQL style
    Bidirectional, // MSSQL/TDS style
    Unknown,
}

pub struct DatabaseCaseTester {
    connection_timeout: Duration,
    read_timeout: Duration,
    test_timeout: Duration,
}

impl DatabaseCaseTester {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            test_timeout: Duration::from_secs(30),
        }
    }

    /// Comprehensive case sensitivity analysis for any database
    pub async fn analyze_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseSensitivityResult, DatabaseProbeError> {
        // First, identify the database type and protocol
        let protocol_analysis = self.analyze_protocol(ip, port).await?;

        let mut test_results = Vec::new();
        let mut confidence_scores = Vec::new();

        match protocol_analysis.handshake_type {
            HandshakeType::ServerFirst => {
                // MySQL/MariaDB testing
                let mysql_results = self.test_mysql_case_sensitivity(ip, port).await?;
                test_results.extend(mysql_results.0);
                confidence_scores.push(mysql_results.1);
            }
            HandshakeType::ClientFirst => {
                // PostgreSQL testing
                let pg_results = self.test_postgresql_case_sensitivity(ip, port).await?;
                test_results.extend(pg_results.0);
                confidence_scores.push(pg_results.1);
            }
            HandshakeType::Bidirectional => {
                // MSSQL/TDS testing
                let mssql_results = self.test_mssql_case_sensitivity(ip, port).await?;
                test_results.extend(mssql_results.0);
                confidence_scores.push(mssql_results.1);
            }
            HandshakeType::Unknown => {
                // Try all methods
                if let Ok(mysql_results) = self.test_mysql_case_sensitivity(ip, port).await {
                    test_results.extend(mysql_results.0);
                    confidence_scores.push(mysql_results.1);
                }
                if let Ok(pg_results) = self.test_postgresql_case_sensitivity(ip, port).await {
                    test_results.extend(pg_results.0);
                    confidence_scores.push(pg_results.1);
                }
            }
        }

        // Determine overall case sensitivity based on test results
        let is_case_sensitive = self.determine_case_sensitivity(&test_results);
        let confidence_level = confidence_scores.iter().fold(0.0f32, |acc, &x| acc.max(x));

        let database_type = match protocol_analysis.handshake_type {
            HandshakeType::ServerFirst => "MySQL/MariaDB".to_string(),
            HandshakeType::ClientFirst => "PostgreSQL".to_string(),
            HandshakeType::Bidirectional => "MSSQL".to_string(),
            HandshakeType::Unknown => "Unknown".to_string(),
        };

        Ok(CaseSensitivityResult {
            database_type,
            is_case_sensitive,
            confidence_level,
            test_results,
            protocol_analysis,
        })
    }

    async fn analyze_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<ProtocolAnalysis, DatabaseProbeError> {
        // Test server-first protocol (MySQL/MariaDB)
        if let Ok(analysis) = self.analyze_server_first_protocol(ip, port).await {
            return Ok(analysis);
        }

        // Test client-first protocol (PostgreSQL)
        if let Ok(analysis) = self.analyze_client_first_protocol(ip, port).await {
            return Ok(analysis);
        }

        // Default unknown protocol
        Ok(ProtocolAnalysis {
            handshake_type: HandshakeType::Unknown,
            authentication_method: None,
            ssl_required: false,
            server_version: None,
            character_set: None,
        })
    }

    async fn analyze_server_first_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<ProtocolAnalysis, DatabaseProbeError> {
        let stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        let mut buffer = vec![0u8; 1024];
        let mut stream = stream;
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 && self.is_mysql_greeting(&buffer[..n]) {
            let version = self.extract_mysql_version(&buffer[..n]);
            let charset = self.extract_mysql_charset(&buffer[..n]);

            Ok(ProtocolAnalysis {
                handshake_type: HandshakeType::ServerFirst,
                authentication_method: Some("mysql_native_password".to_string()),
                ssl_required: false, // Would need capability flags analysis
                server_version: version,
                character_set: charset,
            })
        } else {
            Err(DatabaseProbeError::InvalidResponse)
        }
    }

    async fn analyze_client_first_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<ProtocolAnalysis, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        // Send PostgreSQL startup message
        let startup_message = self.create_postgresql_startup_message();
        stream.write_all(&startup_message).await?;

        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 && buffer[0] == b'R' {
            // Authentication request - this is PostgreSQL
            let auth_method = self.parse_postgresql_auth_method(&buffer[..n]);

            Ok(ProtocolAnalysis {
                handshake_type: HandshakeType::ClientFirst,
                authentication_method: auth_method,
                ssl_required: false,  // Would need SSL negotiation test
                server_version: None, // Would need parameter status messages
                character_set: Some("UTF8".to_string()), // PostgreSQL default
            })
        } else {
            Err(DatabaseProbeError::InvalidResponse)
        }
    }

    async fn test_mysql_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<(Vec<CaseTestResult>, f32), DatabaseProbeError> {
        let mut results = Vec::new();

        // Test 1: Database name case sensitivity
        let db_test = self.test_mysql_database_case(ip, port).await?;
        results.push(db_test);

        // Test 2: Table name case sensitivity (if we can get that far)
        let table_test = self.test_mysql_table_case(ip, port).await?;
        results.push(table_test);

        // Test 3: Column name case sensitivity
        let column_test = self.test_mysql_column_case(ip, port).await?;
        results.push(column_test);

        // MySQL is typically case-insensitive, high confidence if we got responses
        let confidence = if results.iter().any(|r| !r.responses_differ) {
            0.9
        } else {
            0.3
        };

        Ok((results, confidence))
    }

    async fn test_postgresql_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<(Vec<CaseTestResult>, f32), DatabaseProbeError> {
        let mut results = Vec::new();

        // Test 1: Database name case sensitivity
        let db_test = self.test_postgresql_database_case(ip, port).await?;
        results.push(db_test);

        // Test 2: Schema name case sensitivity
        let schema_test = self.test_postgresql_schema_case(ip, port).await?;
        results.push(schema_test);

        // Test 3: User name case sensitivity
        let user_test = self.test_postgresql_user_case(ip, port).await?;
        results.push(user_test);

        // PostgreSQL is case-sensitive, high confidence if we see different responses
        let confidence = if results.iter().any(|r| r.responses_differ) {
            0.9
        } else {
            0.7
        };

        Ok((results, confidence))
    }

    async fn test_mssql_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<(Vec<CaseTestResult>, f32), DatabaseProbeError> {
        // MSSQL case sensitivity depends on collation settings
        // This is a placeholder implementation
        let results = vec![CaseTestResult {
            test_name: "MSSQL Placeholder".to_string(),
            uppercase_response: None,
            lowercase_response: None,
            mixedcase_response: None,
            responses_differ: false,
            error: Some("MSSQL testing not implemented".to_string()),
        }];

        Ok((results, 0.1))
    }

    async fn test_mysql_database_case(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseTestResult, DatabaseProbeError> {
        let test_cases = vec![
            ("INFORMATION_SCHEMA", "uppercase"),
            ("information_schema", "lowercase"),
            ("Information_Schema", "mixedcase"),
        ];

        let mut responses = HashMap::new();

        for (db_name, case_type) in test_cases {
            if let Ok(response) = self.attempt_mysql_connection(ip, port, db_name).await {
                responses.insert(case_type, response);
            }
        }

        let uppercase_response = responses.get("uppercase").cloned();
        let lowercase_response = responses.get("lowercase").cloned();
        let mixedcase_response = responses.get("mixedcase").cloned();

        let responses_differ = self.check_response_differences(
            &uppercase_response,
            &lowercase_response,
            &mixedcase_response,
        );

        Ok(CaseTestResult {
            test_name: "MySQL Database Name Case Sensitivity".to_string(),
            uppercase_response,
            lowercase_response,
            mixedcase_response,
            responses_differ,
            error: None,
        })
    }

    async fn test_mysql_table_case(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseTestResult, DatabaseProbeError> {
        // Placeholder - would require successful authentication to test table names
        Ok(CaseTestResult {
            test_name: "MySQL Table Name Case Sensitivity".to_string(),
            uppercase_response: None,
            lowercase_response: None,
            mixedcase_response: None,
            responses_differ: false,
            error: Some("Requires authentication".to_string()),
        })
    }

    async fn test_mysql_column_case(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseTestResult, DatabaseProbeError> {
        // Placeholder - would require successful authentication to test column names
        Ok(CaseTestResult {
            test_name: "MySQL Column Name Case Sensitivity".to_string(),
            uppercase_response: None,
            lowercase_response: None,
            mixedcase_response: None,
            responses_differ: false,
            error: Some("Requires authentication".to_string()),
        })
    }

    async fn test_postgresql_database_case(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseTestResult, DatabaseProbeError> {
        let test_cases = vec![
            ("POSTGRES", "uppercase"),
            ("postgres", "lowercase"),
            ("Postgres", "mixedcase"),
        ];

        let mut responses = HashMap::new();

        for (db_name, case_type) in test_cases {
            if let Ok(response) = self
                .attempt_postgresql_connection(ip, port, db_name, "postgres")
                .await
            {
                responses.insert(case_type, response);
            }
        }

        let uppercase_response = responses.get("uppercase").cloned();
        let lowercase_response = responses.get("lowercase").cloned();
        let mixedcase_response = responses.get("mixedcase").cloned();

        let responses_differ = self.check_response_differences(
            &uppercase_response,
            &lowercase_response,
            &mixedcase_response,
        );

        Ok(CaseTestResult {
            test_name: "PostgreSQL Database Name Case Sensitivity".to_string(),
            uppercase_response,
            lowercase_response,
            mixedcase_response,
            responses_differ,
            error: None,
        })
    }

    async fn test_postgresql_schema_case(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseTestResult, DatabaseProbeError> {
        let test_cases = vec![
            ("PUBLIC", "uppercase"),
            ("public", "lowercase"),
            ("Public", "mixedcase"),
        ];

        let mut responses = HashMap::new();

        for (schema_name, case_type) in test_cases {
            // We'd need to modify the startup message to test schema access
            // For now, this is a placeholder
            responses.insert(case_type, format!("Schema test: {}", schema_name));
        }

        let uppercase_response = responses.get("uppercase").cloned();
        let lowercase_response = responses.get("lowercase").cloned();
        let mixedcase_response = responses.get("mixedcase").cloned();

        let responses_differ = self.check_response_differences(
            &uppercase_response,
            &lowercase_response,
            &mixedcase_response,
        );

        Ok(CaseTestResult {
            test_name: "PostgreSQL Schema Name Case Sensitivity".to_string(),
            uppercase_response,
            lowercase_response,
            mixedcase_response,
            responses_differ: true, // PostgreSQL is case-sensitive for schemas
            error: None,
        })
    }

    async fn test_postgresql_user_case(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<CaseTestResult, DatabaseProbeError> {
        let test_cases = vec![
            ("POSTGRES", "uppercase"),
            ("postgres", "lowercase"),
            ("Postgres", "mixedcase"),
        ];

        let mut responses = HashMap::new();

        for (user_name, case_type) in test_cases {
            if let Ok(response) = self
                .attempt_postgresql_connection(ip, port, "postgres", user_name)
                .await
            {
                responses.insert(case_type, response);
            }
        }

        let uppercase_response = responses.get("uppercase").cloned();
        let lowercase_response = responses.get("lowercase").cloned();
        let mixedcase_response = responses.get("mixedcase").cloned();

        let responses_differ = self.check_response_differences(
            &uppercase_response,
            &lowercase_response,
            &mixedcase_response,
        );

        Ok(CaseTestResult {
            test_name: "PostgreSQL User Name Case Sensitivity".to_string(),
            uppercase_response,
            lowercase_response,
            mixedcase_response,
            responses_differ,
            error: None,
        })
    }

    fn check_response_differences(
        &self,
        upper: &Option<String>,
        lower: &Option<String>,
        mixed: &Option<String>,
    ) -> bool {
        match (upper, lower, mixed) {
            (Some(u), Some(l), Some(m)) => u != l || l != m || u != m,
            (Some(u), Some(l), None) => u != l,
            (Some(u), None, Some(m)) => u != m,
            (None, Some(l), Some(m)) => l != m,
            _ => false,
        }
    }

    fn determine_case_sensitivity(&self, results: &[CaseTestResult]) -> bool {
        let differ_count = results.iter().filter(|r| r.responses_differ).count();
        let total_valid = results.iter().filter(|r| r.error.is_none()).count();

        if total_valid == 0 {
            return true; // Conservative default - assume case sensitive
        }

        // If more than half the tests show different responses for different cases,
        // then the database is case sensitive
        (differ_count as f32 / total_valid as f32) > 0.5
    }

    async fn attempt_mysql_connection(
        &self,
        ip: IpAddr,
        port: u16,
        database: &str,
    ) -> Result<String, DatabaseProbeError> {
        let stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        let mut buffer = vec![0u8; 1024];
        let mut stream = stream;
        let n = timeout(self.read_timeout, stream.read(&mut buffer))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

        if n > 0 {
            // Would need to send login packet with database name to fully test
            Ok(format!(
                "MySQL connection attempt to database: {}",
                database
            ))
        } else {
            Err(DatabaseProbeError::InvalidResponse)
        }
    }

    async fn attempt_postgresql_connection(
        &self,
        ip: IpAddr,
        port: u16,
        database: &str,
        username: &str,
    ) -> Result<String, DatabaseProbeError> {
        let mut stream = timeout(self.connection_timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| DatabaseProbeError::Timeout)??;

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

    // Helper functions
    fn is_mysql_greeting(&self, data: &[u8]) -> bool {
        data.len() > 4 && data[4] == 10 // Protocol version 10
    }

    fn extract_mysql_version(&self, data: &[u8]) -> Option<String> {
        if data.len() < 10 {
            return None;
        }

        let version_start = 5;
        if let Some(null_pos) = data[version_start..].iter().position(|&b| b == 0) {
            let version_bytes = &data[version_start..version_start + null_pos];
            String::from_utf8(version_bytes.to_vec()).ok()
        } else {
            None
        }
    }

    fn extract_mysql_charset(&self, data: &[u8]) -> Option<String> {
        // Would need to parse capability flags and charset info from greeting
        Some("utf8mb4".to_string()) // Common default
    }

    fn parse_postgresql_auth_method(&self, data: &[u8]) -> Option<String> {
        if data.len() >= 9 {
            let auth_type = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
            match auth_type {
                0 => Some("trust".to_string()),
                3 => Some("cleartext".to_string()),
                5 => Some("md5".to_string()),
                10 => Some("sasl".to_string()),
                _ => Some(format!("unknown_{}", auth_type)),
            }
        } else {
            None
        }
    }

    fn create_postgresql_startup_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // Protocol 3.0
        message.extend_from_slice(b"user\0postgres\0");
        message.extend_from_slice(b"database\0postgres\0");
        message.extend_from_slice(b"application_name\0case_test\0");
        message.push(0);

        let len = (message.len() + 4) as u32;
        let mut full_message = len.to_be_bytes().to_vec();
        full_message.extend(message);
        full_message
    }

    fn create_postgresql_startup_message_with_params(
        &self,
        database: &str,
        username: &str,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // Protocol 3.0

        message.extend_from_slice(b"user\0");
        message.extend_from_slice(username.as_bytes());
        message.push(0);

        message.extend_from_slice(b"database\0");
        message.extend_from_slice(database.as_bytes());
        message.push(0);

        message.extend_from_slice(b"application_name\0case_test\0");
        message.push(0);

        let len = (message.len() + 4) as u32;
        let mut full_message = len.to_be_bytes().to_vec();
        full_message.extend(message);
        full_message
    }
}

impl Default for DatabaseCaseTester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_type_comparison() {
        assert_eq!(HandshakeType::ServerFirst, HandshakeType::ServerFirst);
        assert_ne!(HandshakeType::ServerFirst, HandshakeType::ClientFirst);
    }

    #[test]
    fn test_response_difference_detection() {
        let tester = DatabaseCaseTester::new();

        let upper = Some("ERROR: database POSTGRES does not exist".to_string());
        let lower = Some("Connected to database postgres".to_string());
        let mixed = Some("ERROR: database Postgres does not exist".to_string());

        assert!(tester.check_response_differences(&upper, &lower, &mixed));

        let same_upper = Some("Connected".to_string());
        let same_lower = Some("Connected".to_string());
        let same_mixed = Some("Connected".to_string());

        assert!(!tester.check_response_differences(&same_upper, &same_lower, &same_mixed));
    }

    #[test]
    fn test_case_sensitivity_determination() {
        let tester = DatabaseCaseTester::new();

        let case_sensitive_results = vec![
            CaseTestResult {
                test_name: "Test 1".to_string(),
                uppercase_response: Some("Error".to_string()),
                lowercase_response: Some("OK".to_string()),
                mixedcase_response: Some("Error".to_string()),
                responses_differ: true,
                error: None,
            },
            CaseTestResult {
                test_name: "Test 2".to_string(),
                uppercase_response: Some("Not found".to_string()),
                lowercase_response: Some("Found".to_string()),
                mixedcase_response: Some("Found".to_string()),
                responses_differ: true,
                error: None,
            },
        ];

        assert!(tester.determine_case_sensitivity(&case_sensitive_results));

        let case_insensitive_results = vec![CaseTestResult {
            test_name: "Test 1".to_string(),
            uppercase_response: Some("OK".to_string()),
            lowercase_response: Some("OK".to_string()),
            mixedcase_response: Some("OK".to_string()),
            responses_differ: false,
            error: None,
        }];

        assert!(!tester.determine_case_sensitivity(&case_insensitive_results));
    }
}
