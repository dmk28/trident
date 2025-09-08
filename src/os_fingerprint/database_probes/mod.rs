pub mod mssql_probe;
pub mod mysql_probe;
pub mod oracle_probe;
pub mod postgresql_probe;
pub mod test_refactor;
pub mod types;

// Re-export types for convenience
pub use types::{DatabaseInfo, DatabaseProbeError};

// Re-export individual probers
pub use mssql_probe::{MSSQLProber, probe_mssql};
pub use mysql_probe::{MySQLProber, probe_mysql};
pub use oracle_probe::{OracleProber, probe_oracle};
pub use postgresql_probe::{PostgreSQLProber, probe_postgresql};
pub use test_refactor::*;

use std::net::IpAddr;
use tokio::time::Duration;

/// Core database probing engine that orchestrates all database-specific probers
pub struct DatabaseProber {
    connection_timeout: Duration,
    read_timeout: Duration,
    mysql_prober: MySQLProber,
    postgresql_prober: PostgreSQLProber,
    mssql_prober: MSSQLProber,
    oracle_prober: OracleProber,
}

impl DatabaseProber {
    pub fn new() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            mysql_prober: MySQLProber::new(),
            postgresql_prober: PostgreSQLProber::new(),
            mssql_prober: MSSQLProber::new(),
            oracle_prober: OracleProber::new(),
        }
    }

    /// Main probe function - tries to identify any database service
    pub async fn probe_database(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        // First, try to connect and see if server speaks first (like MySQL)
        if let Ok(info) = self.probe_server_first_protocol(ip, port).await {
            return Ok(info);
        }

        // Then try client-first protocols (like PostgreSQL)
        if let Ok(info) = self.probe_client_first_protocol(ip, port).await {
            return Ok(info);
        }

        // Try MSSQL/TDS protocol
        if let Ok(info) = self.probe_mssql_protocol(ip, port).await {
            return Ok(info);
        }

        // Try Oracle/TNS protocol
        if let Ok(info) = self.probe_oracle_protocol(ip, port).await {
            return Ok(info);
        }

        Err(DatabaseProbeError::InvalidResponse)
    }

    /// Test protocols where server sends greeting first (MySQL, MariaDB)
    async fn probe_server_first_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        self.mysql_prober
            .probe_server_first_protocol(ip, port)
            .await
    }

    /// Test protocols where client must speak first (PostgreSQL)
    async fn probe_client_first_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        self.postgresql_prober
            .probe_client_first_protocol(ip, port)
            .await
    }

    /// Test MSSQL/TDS protocol
    async fn probe_mssql_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        self.mssql_prober.probe_mssql_protocol(ip, port).await
    }

    /// Test Oracle/TNS protocol
    async fn probe_oracle_protocol(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        self.oracle_prober.probe_oracle_protocol(ip, port).await
    }

    /// Test for anonymous access by attempting actual connection
    pub async fn test_anonymous_access(
        &self,
        ip: IpAddr,
        port: u16,
        service_type: &str,
    ) -> Result<bool, DatabaseProbeError> {
        match service_type {
            "MySQL" => {
                self.mysql_prober
                    .test_mysql_anonymous_access(ip, port)
                    .await
            }
            "PostgreSQL" => {
                self.postgresql_prober
                    .test_postgresql_anonymous_access(ip, port)
                    .await
            }
            "MSSQL" => Ok(false),  // MSSQL rarely allows anonymous access
            "Oracle" => Ok(false), // Oracle rarely allows anonymous access
            _ => Ok(false),
        }
    }

    /// Test case sensitivity by attempting queries with different case variations
    pub async fn test_case_sensitivity(
        &self,
        ip: IpAddr,
        port: u16,
        service_type: &str,
    ) -> Result<Option<bool>, DatabaseProbeError> {
        match service_type {
            "MySQL" | "MariaDB" => {
                self.mysql_prober
                    .test_mysql_case_sensitivity(ip, port)
                    .await
            }
            "PostgreSQL" => {
                self.postgresql_prober
                    .test_postgresql_case_sensitivity(ip, port)
                    .await
            }
            "MSSQL" => {
                self.mssql_prober
                    .test_mssql_case_sensitivity(ip, port)
                    .await
            }
            "Oracle" => Ok(Some(true)), // Oracle is case-sensitive by default
            _ => Ok(None),
        }
    }

    /// Enhanced database fingerprinting that includes case sensitivity analysis
    pub async fn comprehensive_database_probe(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> Result<DatabaseInfo, DatabaseProbeError> {
        let mut info = self.probe_database(ip, port).await?;

        // Test case sensitivity if we successfully identified the database
        if let Ok(Some(case_sensitive)) = self
            .test_case_sensitivity(ip, port, &info.service_type)
            .await
        {
            info.case_sensitive = Some(case_sensitive);
        }

        // Add protocol-specific information
        match info.service_type.as_str() {
            "MySQL" | "MariaDB" => {
                info.additional_info.insert(
                    "protocol_notes".to_string(),
                    "Server-first protocol, single-step authentication".to_string(),
                );
            }
            "PostgreSQL" => {
                info.additional_info.insert(
                    "protocol_notes".to_string(),
                    "Client-first protocol, two-step handshake (secure channel + auth)".to_string(),
                );
            }
            "MSSQL" => {
                info.additional_info.insert(
                    "protocol_notes".to_string(),
                    "TDS protocol, three-step handshake (init + auth + data)".to_string(),
                );
            }
            "Oracle" => {
                info.additional_info.insert(
                    "protocol_notes".to_string(),
                    "TNS protocol, connection-oriented with service names".to_string(),
                );
            }
            _ => {}
        }

        Ok(info)
    }
}

impl Default for DatabaseProber {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level convenience functions
pub async fn probe_any_database(ip: IpAddr, port: u16) -> Result<DatabaseInfo, DatabaseProbeError> {
    let prober = DatabaseProber::new();
    prober.probe_database(ip, port).await
}

pub async fn comprehensive_probe_any_database(
    ip: IpAddr,
    port: u16,
) -> Result<DatabaseInfo, DatabaseProbeError> {
    let prober = DatabaseProber::new();
    prober.comprehensive_database_probe(ip, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_database_prober_creation() {
        let prober = DatabaseProber::new();
        assert_eq!(prober.connection_timeout, Duration::from_secs(10));
        assert_eq!(prober.read_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_case_sensitivity_defaults() {
        // Test that we correctly identify database case sensitivity defaults
        let mysql_info = DatabaseInfo {
            service_type: "MySQL".to_string(),
            version: Some("8.0.32".to_string()),
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(false),
            handshake_steps: 1,
            additional_info: std::collections::HashMap::new(),
            raw_banner: None,
        };

        let postgresql_info = DatabaseInfo {
            service_type: "PostgreSQL".to_string(),
            version: Some("15.2".to_string()),
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(true),
            handshake_steps: 2,
            additional_info: std::collections::HashMap::new(),
            raw_banner: None,
        };

        let mssql_info = DatabaseInfo {
            service_type: "MSSQL".to_string(),
            version: Some("2019.15.0.2000".to_string()),
            authentication_required: true,
            anonymous_access_possible: false,
            case_sensitive: Some(true),
            handshake_steps: 3,
            additional_info: std::collections::HashMap::new(),
            raw_banner: None,
        };

        assert_eq!(mysql_info.case_sensitive, Some(false));
        assert_eq!(mysql_info.handshake_steps, 1);
        assert_eq!(postgresql_info.case_sensitive, Some(true));
        assert_eq!(postgresql_info.handshake_steps, 2);
        assert_eq!(mssql_info.case_sensitive, Some(true));
        assert_eq!(mssql_info.handshake_steps, 3);
    }
}
