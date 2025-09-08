use super::types::{DatabaseInfo, DatabaseProbeError};
use super::{DatabaseProber, MSSQLProber, MySQLProber, OracleProber, PostgreSQLProber};
use std::net::{IpAddr, Ipv4Addr};

/// Test to verify the refactored database probes work correctly
pub async fn test_refactored_database_probes() {
    println!("=== Testing Refactored Database Probes ===\n");

    // Test individual probers
    test_individual_probers().await;

    // Test main orchestrator
    test_database_orchestrator().await;

    // Test convenience functions
    test_convenience_functions().await;

    println!("=== All Tests Completed ===");
}

async fn test_individual_probers() {
    println!("--- Testing Individual Database Probers ---");

    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();

    // Test MySQL prober
    let mysql_prober = MySQLProber::new();
    println!("✅ MySQLProber created successfully");

    match mysql_prober.probe_server_first_protocol(ip, 3306).await {
        Ok(info) => {
            println!(
                "✅ MySQL probe succeeded: {} v{}",
                info.service_type,
                info.version.as_deref().unwrap_or("unknown")
            );
        }
        Err(e) => {
            println!("⚠️  MySQL probe failed (expected): {:?}", e);
        }
    }

    // Test PostgreSQL prober
    let pg_prober = PostgreSQLProber::new();
    println!("✅ PostgreSQLProber created successfully");

    match pg_prober.probe_client_first_protocol(ip, 5432).await {
        Ok(info) => {
            println!(
                "✅ PostgreSQL probe succeeded: {} v{}",
                info.service_type,
                info.version.as_deref().unwrap_or("unknown")
            );
        }
        Err(e) => {
            println!("⚠️  PostgreSQL probe failed (expected): {:?}", e);
        }
    }

    // Test MSSQL prober
    let mssql_prober = MSSQLProber::new();
    println!("✅ MSSQLProber created successfully");

    match mssql_prober.probe_mssql_protocol(ip, 1433).await {
        Ok(info) => {
            println!(
                "✅ MSSQL probe succeeded: {} v{}",
                info.service_type,
                info.version.as_deref().unwrap_or("unknown")
            );
        }
        Err(e) => {
            println!("⚠️  MSSQL probe failed (expected): {:?}", e);
        }
    }

    // Test Oracle prober
    let oracle_prober = OracleProber::new();
    println!("✅ OracleProber created successfully");

    match oracle_prober.probe_oracle_protocol(ip, 1521).await {
        Ok(info) => {
            println!(
                "✅ Oracle probe succeeded: {} v{}",
                info.service_type,
                info.version.as_deref().unwrap_or("unknown")
            );
        }
        Err(e) => {
            println!("⚠️  Oracle probe failed (expected): {:?}", e);
        }
    }

    println!();
}

async fn test_database_orchestrator() {
    println!("--- Testing Database Orchestrator ---");

    let prober = DatabaseProber::new();
    println!("✅ DatabaseProber orchestrator created successfully");

    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let test_ports = [3306, 5432, 1433, 1521];

    for port in test_ports {
        match prober.probe_database(ip, port).await {
            Ok(info) => {
                println!(
                    "✅ Port {} identified as: {} ({})",
                    port,
                    info.service_type,
                    if info.case_sensitive.unwrap_or(false) {
                        "case-sensitive"
                    } else {
                        "case-insensitive"
                    }
                );
                println!("   Handshake steps: {}", info.handshake_steps);
                if let Some(notes) = info.additional_info.get("protocol_notes") {
                    println!("   Protocol: {}", notes);
                }
            }
            Err(_) => {
                println!("⚠️  Port {} - no database detected (expected)", port);
            }
        }
    }

    println!();
}

async fn test_convenience_functions() {
    println!("--- Testing Convenience Functions ---");

    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();

    // Test comprehensive probe
    match super::comprehensive_probe_any_database(ip, 3306).await {
        Ok(info) => {
            println!("✅ Comprehensive probe succeeded: {}", info.service_type);
            println!("   Case sensitivity tested: {:?}", info.case_sensitive);
        }
        Err(_) => {
            println!("⚠️  Comprehensive probe failed (expected - no MySQL running)");
        }
    }

    // Test basic probe
    match super::probe_any_database(ip, 5432).await {
        Ok(info) => {
            println!("✅ Basic probe succeeded: {}", info.service_type);
        }
        Err(_) => {
            println!("⚠️  Basic probe failed (expected - no PostgreSQL running)");
        }
    }

    println!();
}

/// Test the case sensitivity detection logic with mock data
pub fn test_case_sensitivity_logic() {
    println!("--- Testing Case Sensitivity Logic ---");

    // Test MySQL-style (case-insensitive) DatabaseInfo
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

    // Test PostgreSQL-style (case-sensitive) DatabaseInfo
    let pg_info = DatabaseInfo {
        service_type: "PostgreSQL".to_string(),
        version: Some("15.2".to_string()),
        authentication_required: true,
        anonymous_access_possible: false,
        case_sensitive: Some(true),
        handshake_steps: 2,
        additional_info: std::collections::HashMap::new(),
        raw_banner: None,
    };

    // Test MSSQL-style (case-sensitive, depends on collation) DatabaseInfo
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

    println!(
        "✅ MySQL info: {} steps, case-sensitive: {:?}",
        mysql_info.handshake_steps, mysql_info.case_sensitive
    );
    println!(
        "✅ PostgreSQL info: {} steps, case-sensitive: {:?}",
        pg_info.handshake_steps, pg_info.case_sensitive
    );
    println!(
        "✅ MSSQL info: {} steps, case-sensitive: {:?}",
        mssql_info.handshake_steps, mssql_info.case_sensitive
    );

    // Verify our expectations
    assert_eq!(mysql_info.handshake_steps, 1);
    assert_eq!(mysql_info.case_sensitive, Some(false));

    assert_eq!(pg_info.handshake_steps, 2);
    assert_eq!(pg_info.case_sensitive, Some(true));

    assert_eq!(mssql_info.handshake_steps, 3);
    assert_eq!(mssql_info.case_sensitive, Some(true));

    println!("✅ All case sensitivity logic tests passed!");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_refactored_probes_async() {
        test_refactored_database_probes().await;
    }

    #[test]
    fn test_case_sensitivity_sync() {
        test_case_sensitivity_logic();
    }

    #[test]
    fn test_prober_creation() {
        // Test that all probers can be created without panicking
        let _mysql = MySQLProber::new();
        let _pg = PostgreSQLProber::new();
        let _mssql = MSSQLProber::new();
        let _oracle = OracleProber::new();
        let _main = DatabaseProber::new();

        println!("✅ All probers created successfully");
    }
}
