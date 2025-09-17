//! CVE caching system for local storage and incremental updates
//!
//! This module provides persistent caching of CVE data to reduce GitHub API calls
//! and enable incremental updates for better performance.

use crate::plugins::plugin_trait::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCve {
    pub cve_id: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub affected_services: Vec<String>,
    pub affected_versions: Vec<String>,
    pub ports: Vec<u16>,
    pub references: Vec<String>,
    pub exploitable: bool,
    pub patch_available: bool,
    pub last_modified: SystemTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheMetadata {
    pub last_update: SystemTime,
    pub version: String,
    pub total_cves: usize,
    pub years_cached: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
struct YearCache {
    pub year: u16,
    pub cves: Vec<CachedCve>,
    pub last_update: SystemTime,
    pub total_count: usize,
}

pub struct CveCache {
    cache_dir: String,
    max_age: Duration,
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_cves: usize,
    pub cached_years: Vec<u16>,
    pub cache_size_bytes: u64,
    pub last_update: Option<SystemTime>,
    pub hit_rate: f32,
}

impl CveCache {
    pub fn new(cache_dir: String, max_age: Duration) -> Self {
        Self { cache_dir, max_age }
    }

    /// Initialize cache directory
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(&self.cache_dir).await?;
        println!("💾 CVE cache initialized at: {}", self.cache_dir);
        Ok(())
    }

    /// Check if cache exists and is valid
    pub async fn is_valid(&self) -> bool {
        let metadata_path = format!("{}/metadata.json", self.cache_dir);
        if !Path::new(&metadata_path).exists() {
            return false;
        }

        match self.load_metadata().await {
            Ok(metadata) => {
                if let Ok(elapsed) = metadata.last_update.elapsed() {
                    elapsed < self.max_age
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Load metadata from cache
    async fn load_metadata(&self) -> Result<CacheMetadata, Box<dyn std::error::Error>> {
        let metadata_path = format!("{}/metadata.json", self.cache_dir);
        let content = fs::read_to_string(metadata_path).await?;
        let metadata: CacheMetadata = serde_json::from_str(&content)?;
        Ok(metadata)
    }

    /// Save metadata to cache
    async fn save_metadata(
        &self,
        metadata: &CacheMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let metadata_path = format!("{}/metadata.json", self.cache_dir);
        let content = serde_json::to_string_pretty(metadata)?;
        fs::write(metadata_path, content).await?;
        Ok(())
    }

    /// Load CVEs for a specific year from cache
    pub async fn load_year(&self, year: u16) -> Result<Vec<CachedCve>, Box<dyn std::error::Error>> {
        let year_path = format!("{}/year_{}.json", self.cache_dir, year);
        if !Path::new(&year_path).exists() {
            return Err(format!("No cache found for year {}", year).into());
        }

        let content = fs::read_to_string(year_path).await?;
        let year_cache: YearCache = serde_json::from_str(&content)?;

        // Check if year cache is still valid
        if let Ok(elapsed) = year_cache.last_update.elapsed() {
            if elapsed > self.max_age {
                return Err(format!("Cache for year {} is expired", year).into());
            }
        }

        Ok(year_cache.cves)
    }

    /// Save CVEs for a specific year to cache
    pub async fn save_year(
        &self,
        year: u16,
        cves: &[CachedCve],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let year_path = format!("{}/year_{}.json", self.cache_dir, year);

        let year_cache = YearCache {
            year,
            cves: cves.to_vec(),
            last_update: SystemTime::now(),
            total_count: cves.len(),
        };

        let content = serde_json::to_string_pretty(&year_cache)?;
        fs::write(year_path, content).await?;

        println!("💾 Cached {} CVEs for year {}", cves.len(), year);
        Ok(())
    }

    /// Load all cached CVEs
    pub async fn load_all(&self) -> Result<HashMap<String, CachedCve>, Box<dyn std::error::Error>> {
        let mut all_cves = HashMap::new();

        let metadata = self.load_metadata().await?;

        for &year in &metadata.years_cached {
            match self.load_year(year).await {
                Ok(year_cves) => {
                    for cve in year_cves {
                        all_cves.insert(cve.cve_id.clone(), cve);
                    }
                }
                Err(e) => {
                    println!("⚠️  Warning: Could not load cache for year {}: {}", year, e);
                }
            }
        }

        println!("📦 Loaded {} CVEs from cache", all_cves.len());
        Ok(all_cves)
    }

    /// Save all CVEs to cache (organized by year)
    pub async fn save_all(
        &self,
        cves: &HashMap<String, CachedCve>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Organize CVEs by year based on CVE ID
        let mut years_map: HashMap<u16, Vec<CachedCve>> = HashMap::new();

        for cve in cves.values() {
            if let Some(year) = self.extract_year_from_cve_id(&cve.cve_id) {
                years_map
                    .entry(year)
                    .or_insert_with(Vec::new)
                    .push(cve.clone());
            }
        }

        // Save each year's CVEs
        let mut cached_years = Vec::new();
        for (year, year_cves) in years_map {
            self.save_year(year, &year_cves).await?;
            cached_years.push(year);
        }

        // Update metadata
        let metadata = CacheMetadata {
            last_update: SystemTime::now(),
            version: "1.0".to_string(),
            total_cves: cves.len(),
            years_cached: cached_years,
        };

        self.save_metadata(&metadata).await?;
        println!(
            "✅ Saved {} CVEs to cache across {} years",
            cves.len(),
            metadata.years_cached.len()
        );
        Ok(())
    }

    /// Check if a specific year needs updating
    pub async fn year_needs_update(&self, year: u16) -> bool {
        match self.load_year(year).await {
            Ok(_) => false, // Year cache exists and is valid
            Err(_) => true, // Year cache doesn't exist or is invalid
        }
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let mut stats = CacheStats {
            total_cves: 0,
            cached_years: Vec::new(),
            cache_size_bytes: 0,
            last_update: None,
            hit_rate: 0.0,
        };

        if let Ok(metadata) = self.load_metadata().await {
            stats.total_cves = metadata.total_cves;
            stats.cached_years = metadata.years_cached;
            stats.last_update = Some(metadata.last_update);
        }

        // Calculate cache size
        if let Ok(mut entries) = fs::read_dir(&self.cache_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(file_metadata) = entry.metadata().await {
                    stats.cache_size_bytes += file_metadata.len();
                }
            }
        }

        stats
    }

    /// Clear all cached data
    pub async fn clear(&self) -> Result<(), Box<dyn std::error::Error>> {
        if Path::new(&self.cache_dir).exists() {
            fs::remove_dir_all(&self.cache_dir).await?;
            fs::create_dir_all(&self.cache_dir).await?;
            println!("🗑️  Cleared CVE cache");
        }
        Ok(())
    }

    /// Clear cache for specific year
    pub async fn clear_year(&self, year: u16) -> Result<(), Box<dyn std::error::Error>> {
        let year_path = format!("{}/year_{}.json", self.cache_dir, year);
        if Path::new(&year_path).exists() {
            fs::remove_file(year_path).await?;
            println!("🗑️  Cleared cache for year {}", year);
        }
        Ok(())
    }

    /// Extract year from CVE ID (e.g., "CVE-2024-1234" -> 2024)
    fn extract_year_from_cve_id(&self, cve_id: &str) -> Option<u16> {
        let parts: Vec<&str> = cve_id.split('-').collect();
        if parts.len() >= 2 {
            parts[1].parse().ok()
        } else {
            None
        }
    }

    /// Get years that should be cached (current year and last few years)
    pub fn get_relevant_years(&self, current_year: u16, years_back: u16) -> Vec<u16> {
        let start_year = current_year.saturating_sub(years_back);
        (start_year..=current_year).collect()
    }

    /// Perform incremental update for recent years only
    pub async fn incremental_update_needed(&self, years_to_check: &[u16]) -> Vec<u16> {
        let mut years_needing_update = Vec::new();

        for &year in years_to_check {
            if self.year_needs_update(year).await {
                years_needing_update.push(year);
            }
        }

        years_needing_update
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cache_creation() {
        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let cache = CveCache::new(cache_dir, Duration::from_secs(3600));

        assert!(cache.init().await.is_ok());
        assert!(!cache.is_valid().await); // Should be invalid when empty
    }

    #[tokio::test]
    async fn test_year_extraction() {
        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let cache = CveCache::new(cache_dir, Duration::from_secs(3600));

        assert_eq!(cache.extract_year_from_cve_id("CVE-2024-1234"), Some(2024));
        assert_eq!(cache.extract_year_from_cve_id("CVE-2023-5678"), Some(2023));
        assert_eq!(cache.extract_year_from_cve_id("invalid"), None);
    }

    #[tokio::test]
    async fn test_relevant_years() {
        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().to_str().unwrap().to_string();
        let cache = CveCache::new(cache_dir, Duration::from_secs(3600));

        let years = cache.get_relevant_years(2025, 3);
        assert_eq!(years, vec![2022, 2023, 2024, 2025]);
    }
}
