//! Shared services for plugins to reduce overlap and improve efficiency
//!
//! This module provides centralized services that multiple plugins can use
//! to avoid duplicate work and improve overall scanning efficiency.

pub mod database_service;

pub use database_service::{
    CachedDatabaseInfo, DatabaseDetectionService, DatabaseServiceStats, get_database_service,
    init_database_service,
};

use std::time::Duration;

/// Initialize all shared services with default settings
pub async fn init_shared_services() {
    // Initialize database service with 5-minute cache
    init_database_service(Duration::from_secs(300)).await;

    println!("🔧 Shared services initialized");
}

/// Initialize all shared services with custom settings
pub async fn init_shared_services_with_config(database_cache_duration: Duration) {
    init_database_service(database_cache_duration).await;

    println!("🔧 Shared services initialized with custom config");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_services_init() {
        init_shared_services().await;

        // Test that database service is available
        let db_service = get_database_service().await;
        assert!(db_service.is_database_port(3306));
    }
}
