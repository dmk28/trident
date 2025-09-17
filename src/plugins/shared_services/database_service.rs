//! Shared database detection service to eliminate overlap between plugins
//!
//! This service provides centralized database detection, caching results to avoid
//! duplicate probing when multiple plugins need database information.

use crate::os_fingerprint::database_probes::{
    DatabaseInfo, DatabaseProbeError, comprehensive_probe_any_database,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OnceCell, RwLock};

/// Cached database detection result
#[derive(Debug, Clone)]
pub struct CachedDatabaseInfo {
    pub info: Option<DatabaseInfo>,
    pub timestamp: Instant,
    pub probe_duration: Duration,
}

impl CachedDatabaseInfo {
    /// Check if the cached result is still valid
    pub fn is_valid(&self, max_age: Duration) -> bool {
        self.timestamp.elapsed() < max_age
    }
}

/// Shared database detection service with caching
#[derive(Debug)]
pub struct DatabaseDetectionService {
    /// Cache of database detection results keyed by (ip, port)
    cache: Arc<RwLock<HashMap<(IpAddr, u16), CachedDatabaseInfo>>>,
    /// Default cache validity duration
    default_cache_duration: Duration,
    /// Statistics for monitoring
    pub stats: Arc<RwLock<DatabaseServiceStats>>,
}

/// Statistics for the database detection service
#[derive(Debug, Default, Clone)]
pub struct DatabaseServiceStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub probes_performed: u64,
    pub successful_detections: u64,
    pub failed_detections: u64,
}

impl DatabaseDetectionService {
    /// Create a new database detection service
    pub fn new(cache_duration: Option<Duration>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_cache_duration: cache_duration.unwrap_or(Duration::from_secs(300)), // 5 minutes default
            stats: Arc::new(RwLock::new(DatabaseServiceStats::default())),
        }
    }

    /// Detect database service, using cache if available
    pub async fn detect_database(&self, ip: IpAddr, port: u16) -> Option<DatabaseInfo> {
        let key = (ip, port);

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&key) {
                if cached.is_valid(self.default_cache_duration) {
                    // Update stats
                    {
                        let mut stats = self.stats.write().await;
                        stats.cache_hits += 1;
                    }
                    return cached.info.clone();
                }
            }
        }

        // Cache miss - perform actual detection
        {
            let mut stats = self.stats.write().await;
            stats.cache_misses += 1;
            stats.probes_performed += 1;
        }

        let start_time = Instant::now();
        let result = self.probe_database(ip, port).await;
        let probe_duration = start_time.elapsed();

        // Update stats
        {
            let mut stats = self.stats.write().await;
            if result.is_some() {
                stats.successful_detections += 1;
            } else {
                stats.failed_detections += 1;
            }
        }

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                key,
                CachedDatabaseInfo {
                    info: result.clone(),
                    timestamp: start_time,
                    probe_duration,
                },
            );
        }

        result
    }

    /// Force refresh database detection (bypass cache)
    pub async fn refresh_database_detection(&self, ip: IpAddr, port: u16) -> Option<DatabaseInfo> {
        let key = (ip, port);

        // Remove from cache to force fresh detection
        {
            let mut cache = self.cache.write().await;
            cache.remove(&key);
        }

        self.detect_database(ip, port).await
    }

    /// Check if a port is a known database port
    pub fn is_database_port(&self, port: u16) -> bool {
        matches!(
            port,
            3306 | 3307 | // MySQL/MariaDB
            5432 | 5433 | // PostgreSQL
            1433 | 1434 | // MSSQL
            1521 | 1522 | // Oracle
            27017 | 27018 | 27019 | // MongoDB
            6379 | 6380 | // Redis
            5984 | // CouchDB
            9042 | // Cassandra
            7000 | 7001 | // Cassandra JMX
            8086 | // InfluxDB
            9200 | 9300 // Elasticsearch
        )
    }

    /// Get database type hint based on port
    pub fn get_database_type_hint(&self, port: u16) -> Option<&'static str> {
        match port {
            3306 | 3307 => Some("MySQL/MariaDB"),
            5432 | 5433 => Some("PostgreSQL"),
            1433 | 1434 => Some("MSSQL"),
            1521 | 1522 => Some("Oracle"),
            27017 | 27018 | 27019 => Some("MongoDB"),
            6379 | 6380 => Some("Redis"),
            5984 => Some("CouchDB"),
            9042 => Some("Cassandra"),
            7000 | 7001 => Some("Cassandra JMX"),
            8086 => Some("InfluxDB"),
            9200 | 9300 => Some("Elasticsearch"),
            _ => None,
        }
    }

    /// Clear expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();

        cache.retain(|_, cached_info| cached_info.timestamp + self.default_cache_duration > now);
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> DatabaseServiceStats {
        self.stats.read().await.clone()
    }

    /// Get current cache size
    pub async fn cache_size(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Clear all cached data
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Internal method to perform actual database probing
    async fn probe_database(&self, ip: IpAddr, port: u16) -> Option<DatabaseInfo> {
        match comprehensive_probe_any_database(ip, port).await {
            Ok(db_info) => {
                println!(
                    "🔍 Database detected: {} on {}:{}",
                    db_info.service_type, ip, port
                );
                Some(db_info)
            }
            Err(DatabaseProbeError::Timeout) => {
                println!("⏱️  Database probe timeout for {}:{}", ip, port);
                None
            }
            Err(DatabaseProbeError::ConnectionFailed(e)) => {
                // Don't log connection failures for non-database ports
                if self.is_database_port(port) {
                    println!("🔌 Database connection failed for {}:{}: {}", ip, port, e);
                }
                None
            }
            Err(_) => {
                if self.is_database_port(port) {
                    println!("❌ Database probe failed for {}:{}", ip, port);
                }
                None
            }
        }
    }

    /// Batch detect databases for multiple targets
    pub async fn batch_detect(
        &self,
        targets: Vec<(IpAddr, u16)>,
    ) -> HashMap<(IpAddr, u16), Option<DatabaseInfo>> {
        let mut results = HashMap::new();

        // Use futures to parallelize detection
        let mut tasks = Vec::new();
        for (ip, port) in targets {
            let service = self.clone();
            tasks.push(tokio::spawn(async move {
                let result = service.detect_database(ip, port).await;
                ((ip, port), result)
            }));
        }

        // Collect results
        for task in tasks {
            if let Ok((key, result)) = task.await {
                results.insert(key, result);
            }
        }

        results
    }
}

impl Clone for DatabaseDetectionService {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            default_cache_duration: self.default_cache_duration,
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Global database detection service instance
static DATABASE_SERVICE: OnceCell<Mutex<DatabaseDetectionService>> = OnceCell::const_new();

/// Get or initialize the global database detection service
pub async fn get_database_service() -> tokio::sync::MutexGuard<'static, DatabaseDetectionService> {
    let service = DATABASE_SERVICE
        .get_or_init(|| async { Mutex::new(DatabaseDetectionService::new(None)) })
        .await;
    service.lock().await
}

/// Initialize the global database service with custom settings
pub async fn init_database_service(cache_duration: Duration) {
    let service = DATABASE_SERVICE
        .get_or_init(|| async { Mutex::new(DatabaseDetectionService::new(Some(cache_duration))) })
        .await;
    let _ = service.lock().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_database_service_caching() {
        let service = DatabaseDetectionService::new(Some(Duration::from_secs(60)));
        let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let port = 3306;

        // First call should be a cache miss
        let _result1 = service.detect_database(ip, port).await;
        let stats = service.get_stats().await;
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.probes_performed, 1);

        // Second call should be a cache hit
        let _result2 = service.detect_database(ip, port).await;
        let stats = service.get_stats().await;
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.probes_performed, 1); // No additional probe
    }

    #[test]
    fn test_database_port_recognition() {
        let service = DatabaseDetectionService::new(None);

        assert!(service.is_database_port(3306)); // MySQL
        assert!(service.is_database_port(5432)); // PostgreSQL
        assert!(service.is_database_port(1433)); // MSSQL
        assert!(service.is_database_port(27017)); // MongoDB
        assert!(service.is_database_port(6379)); // Redis

        assert!(!service.is_database_port(80)); // HTTP
        assert!(!service.is_database_port(22)); // SSH
    }

    #[test]
    fn test_database_type_hints() {
        let service = DatabaseDetectionService::new(None);

        assert_eq!(service.get_database_type_hint(3306), Some("MySQL/MariaDB"));
        assert_eq!(service.get_database_type_hint(5432), Some("PostgreSQL"));
        assert_eq!(service.get_database_type_hint(1433), Some("MSSQL"));
        assert_eq!(service.get_database_type_hint(27017), Some("MongoDB"));
        assert_eq!(service.get_database_type_hint(6379), Some("Redis"));
        assert_eq!(service.get_database_type_hint(80), None);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let service = DatabaseDetectionService::new(Some(Duration::from_millis(10)));
        let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        let port = 3306;

        // First call
        let _result1 = service.detect_database(ip, port).await;

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Second call should be a cache miss due to expiration
        let _result2 = service.detect_database(ip, port).await;
        let stats = service.get_stats().await;
        assert_eq!(stats.cache_misses, 2);
        assert_eq!(stats.probes_performed, 2);
    }

    #[tokio::test]
    async fn test_batch_detection() {
        let service = DatabaseDetectionService::new(None);
        let targets = vec![
            (Ipv4Addr::new(127, 0, 0, 1).into(), 3306),
            (Ipv4Addr::new(127, 0, 0, 1).into(), 5432),
        ];

        let results = service.batch_detect(targets.clone()).await;
        assert_eq!(results.len(), 2);

        for (ip, port) in targets {
            assert!(results.contains_key(&(ip, port)));
        }
    }
}
