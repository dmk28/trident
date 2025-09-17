//! CVE confidence scoring system based on service evidence
//!
//! This module provides intelligent confidence scoring for CVE matches based on
//! the quality of evidence gathered from service detection, version information,
//! port analysis, and banner content.

use crate::plugins::plugin_trait::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceQuality {
    /// Service name match confidence (0.0-1.0)
    pub service_match: f32,
    /// Version match confidence (0.0-1.0)
    pub version_match: f32,
    /// Port relevance confidence (0.0-1.0)
    pub port_match: f32,
    /// Banner content match confidence (0.0-1.0)
    pub banner_match: f32,
    /// Overall weighted confidence score (0.0-1.0)
    pub overall_confidence: f32,
}

impl EvidenceQuality {
    pub fn new() -> Self {
        Self {
            service_match: 0.0,
            version_match: 0.0,
            port_match: 0.0,
            banner_match: 0.0,
            overall_confidence: 0.0,
        }
    }

    /// Calculate weighted overall confidence
    /// Service match: 40%, Version: 30%, Port: 20%, Banner: 10%
    pub fn calculate_confidence(&mut self) {
        self.overall_confidence = (self.service_match * 0.4)
            + (self.version_match * 0.3)
            + (self.port_match * 0.2)
            + (self.banner_match * 0.1);
    }

    /// Get confidence level as human-readable string
    pub fn confidence_level(&self) -> &'static str {
        match self.overall_confidence {
            c if c >= 0.9 => "Very High",
            c if c >= 0.8 => "High",
            c if c >= 0.7 => "Medium-High",
            c if c >= 0.6 => "Medium",
            c if c >= 0.5 => "Medium-Low",
            c if c >= 0.3 => "Low",
            _ => "Very Low",
        }
    }
}

impl Default for EvidenceQuality {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub affected_services: Vec<String>,
    pub affected_versions: Vec<String>,
    pub ports: Vec<u16>,
    pub references: Vec<String>,
}

pub struct ConfidenceScorer {
    /// Service name mappings for better matching
    service_aliases: HashMap<String, Vec<String>>,
}

impl ConfidenceScorer {
    pub fn new() -> Self {
        let mut service_aliases = HashMap::new();

        // Build service alias mappings
        service_aliases.insert(
            "mysql".to_string(),
            vec![
                "mysql".to_string(),
                "mariadb".to_string(),
                "percona".to_string(),
            ],
        );

        service_aliases.insert(
            "postgresql".to_string(),
            vec![
                "postgresql".to_string(),
                "postgres".to_string(),
                "pgsql".to_string(),
            ],
        );

        service_aliases.insert(
            "apache".to_string(),
            vec![
                "apache".to_string(),
                "httpd".to_string(),
                "apache2".to_string(),
            ],
        );

        service_aliases.insert(
            "nginx".to_string(),
            vec![
                "nginx".to_string(),
                "nginx-full".to_string(),
                "nginx-light".to_string(),
            ],
        );

        service_aliases.insert(
            "ssh".to_string(),
            vec![
                "ssh".to_string(),
                "openssh".to_string(),
                "dropbear".to_string(),
            ],
        );

        Self { service_aliases }
    }

    /// Calculate confidence score for a CVE match
    pub fn calculate_confidence(
        &self,
        cve: &CveMatch,
        detected_service: &str,
        detected_version: Option<&str>,
        port: u16,
        banner: Option<&str>,
    ) -> EvidenceQuality {
        let mut evidence = EvidenceQuality::new();

        evidence.service_match = self.calculate_service_match(cve, detected_service);
        evidence.version_match = self.calculate_version_match(cve, detected_version);
        evidence.port_match = self.calculate_port_match(cve, port, detected_service);
        evidence.banner_match = self.calculate_banner_match(cve, banner);

        evidence.calculate_confidence();
        evidence
    }

    /// Calculate service name matching score
    fn calculate_service_match(&self, cve: &CveMatch, detected_service: &str) -> f32 {
        let detected_lower = detected_service.to_lowercase();

        for affected_service in &cve.affected_services {
            let affected_lower = affected_service.to_lowercase();

            // Exact match
            if detected_lower == affected_lower {
                return 1.0;
            }

            // Check aliases
            for (canonical, aliases) in &self.service_aliases {
                let detected_matches = aliases.iter().any(|alias| detected_lower.contains(alias));
                let affected_matches = aliases.iter().any(|alias| affected_lower.contains(alias));

                if detected_matches && affected_matches {
                    return 0.9;
                }
            }

            // Partial substring matching
            if affected_lower.contains(&detected_lower) || detected_lower.contains(&affected_lower)
            {
                let longer = std::cmp::max(affected_lower.len(), detected_lower.len());
                let shorter = std::cmp::min(affected_lower.len(), detected_lower.len());
                return 0.6 + (shorter as f32 / longer as f32) * 0.2;
            }
        }

        // No match found
        0.2
    }

    /// Calculate version matching score
    fn calculate_version_match(&self, cve: &CveMatch, detected_version: Option<&str>) -> f32 {
        let Some(version) = detected_version else {
            return 0.5; // Neutral score if no version available
        };

        if cve.affected_versions.is_empty() {
            return 0.6; // CVE doesn't specify versions, so any version info is somewhat relevant
        }

        let cleaned_version = self.clean_version_string(version);

        for affected_version in &cve.affected_versions {
            let cleaned_affected = self.clean_version_string(affected_version);

            // Exact match
            if cleaned_version == cleaned_affected {
                return 1.0;
            }

            // Version range matching (simplified)
            if self.version_in_range(&cleaned_version, affected_version) {
                return 0.9;
            }

            // Major version match
            if self.major_version_matches(&cleaned_version, &cleaned_affected) {
                return 0.7;
            }

            // Minor version match
            if self.minor_version_matches(&cleaned_version, &cleaned_affected) {
                return 0.8;
            }
        }

        0.4 // Version info available but no matches
    }

    /// Calculate port relevance score
    fn calculate_port_match(&self, cve: &CveMatch, port: u16, service: &str) -> f32 {
        // Direct port match in CVE
        if cve.ports.contains(&port) {
            return 1.0;
        }

        // Service-port association scoring
        let service_lower = service.to_lowercase();
        match port {
            80 | 443 | 8080 | 8443 | 8000 | 8443 => {
                if service_lower.contains("http")
                    || service_lower.contains("apache")
                    || service_lower.contains("nginx")
                    || service_lower.contains("iis")
                {
                    0.8
                } else {
                    0.3
                }
            }
            22 => {
                if service_lower.contains("ssh") || service_lower.contains("openssh") {
                    0.9
                } else {
                    0.2
                }
            }
            21 => {
                if service_lower.contains("ftp") {
                    0.9
                } else {
                    0.2
                }
            }
            25 | 587 | 465 => {
                if service_lower.contains("smtp") || service_lower.contains("mail") {
                    0.9
                } else {
                    0.2
                }
            }
            3306 | 3307 => {
                if service_lower.contains("mysql") || service_lower.contains("mariadb") {
                    0.9
                } else {
                    0.2
                }
            }
            5432 | 5433 => {
                if service_lower.contains("postgres") {
                    0.9
                } else {
                    0.2
                }
            }
            1433 | 1434 => {
                if service_lower.contains("mssql") || service_lower.contains("sqlserver") {
                    0.9
                } else {
                    0.2
                }
            }
            6379 => {
                if service_lower.contains("redis") {
                    0.9
                } else {
                    0.2
                }
            }
            27017 | 27018 | 27019 => {
                if service_lower.contains("mongodb") || service_lower.contains("mongo") {
                    0.9
                } else {
                    0.2
                }
            }
            _ => 0.5, // Unknown port, neutral score
        }
    }

    /// Calculate banner content matching score
    fn calculate_banner_match(&self, cve: &CveMatch, banner: Option<&str>) -> f32 {
        let Some(banner_text) = banner else {
            return 0.5; // Neutral score if no banner
        };

        let banner_lower = banner_text.to_lowercase();
        let mut max_score: f32 = 0.3; // Minimum score for having a banner

        // Check for service mentions in banner
        for service in &cve.affected_services {
            let service_lower = service.to_lowercase();
            if banner_lower.contains(&service_lower) {
                max_score = max_score.max(0.8);
            }
        }

        // Check for version mentions in banner
        for version in &cve.affected_versions {
            if banner_lower.contains(version) {
                max_score = max_score.max(0.9);
            }
        }

        // Check for CVE description keywords
        let description_words: Vec<String> = cve
            .description
            .to_lowercase()
            .split_whitespace()
            .filter(|word| word.len() > 4) // Only meaningful words
            .map(|word| word.to_string())
            .collect();

        let mut keyword_matches = 0;
        for word in description_words.iter().take(10) {
            // Limit to first 10 words
            if banner_lower.contains(word) {
                keyword_matches += 1;
            }
        }

        if keyword_matches > 0 {
            let keyword_score = 0.6 + (keyword_matches as f32 / 10.0) * 0.2;
            max_score = max_score.max(keyword_score);
        }

        max_score
    }

    /// Clean version string for comparison
    fn clean_version_string(&self, version: &str) -> String {
        version
            .to_lowercase()
            .replace("version", "")
            .replace("v", "")
            .replace("-", ".")
            .replace("_", ".")
            .trim()
            .to_string()
    }

    /// Check if version falls within a range (simplified)
    fn version_in_range(&self, version: &str, range_spec: &str) -> bool {
        // Handle simple range patterns like "< 2.4.0", ">= 1.0", "1.0-2.0"
        if range_spec.contains("<=")
            || range_spec.contains(">=")
            || range_spec.contains("<")
            || range_spec.contains(">")
            || range_spec.contains("-")
        {
            // This would need a proper semver library in production
            range_spec.contains(version)
        } else {
            false
        }
    }

    /// Check if major versions match (e.g., "2.4.1" and "2.5.0" both have major version 2)
    fn major_version_matches(&self, v1: &str, v2: &str) -> bool {
        let v1_parts: Vec<&str> = v1.split('.').collect();
        let v2_parts: Vec<&str> = v2.split('.').collect();

        !v1_parts.is_empty() && !v2_parts.is_empty() && v1_parts[0] == v2_parts[0]
    }

    /// Check if major and minor versions match
    fn minor_version_matches(&self, v1: &str, v2: &str) -> bool {
        let v1_parts: Vec<&str> = v1.split('.').collect();
        let v2_parts: Vec<&str> = v2.split('.').collect();

        v1_parts.len() >= 2
            && v2_parts.len() >= 2
            && v1_parts[0] == v2_parts[0]
            && v1_parts[1] == v2_parts[1]
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_calculation() {
        let mut evidence = EvidenceQuality::new();
        evidence.service_match = 1.0;
        evidence.version_match = 0.8;
        evidence.port_match = 0.9;
        evidence.banner_match = 0.7;

        evidence.calculate_confidence();

        // Expected: 1.0*0.4 + 0.8*0.3 + 0.9*0.2 + 0.7*0.1 = 0.4 + 0.24 + 0.18 + 0.07 = 0.89
        assert!((evidence.overall_confidence - 0.89).abs() < 0.01);
    }

    #[test]
    fn test_confidence_levels() {
        let mut evidence = EvidenceQuality::new();

        evidence.overall_confidence = 0.95;
        assert_eq!(evidence.confidence_level(), "Very High");

        evidence.overall_confidence = 0.75;
        assert_eq!(evidence.confidence_level(), "Medium-High");

        evidence.overall_confidence = 0.25;
        assert_eq!(evidence.confidence_level(), "Very Low");
    }

    #[test]
    fn test_version_cleaning() {
        let scorer = ConfidenceScorer::new();

        assert_eq!(scorer.clean_version_string("version 2.4.1"), "2.4.1");
        assert_eq!(scorer.clean_version_string("v1.0.0"), "1.0.0");
        assert_eq!(scorer.clean_version_string("2.4-beta"), "2.4.beta");
    }

    #[test]
    fn test_major_version_matching() {
        let scorer = ConfidenceScorer::new();

        assert!(scorer.major_version_matches("2.4.1", "2.5.0"));
        assert!(!scorer.major_version_matches("1.4.1", "2.5.0"));
        assert!(scorer.minor_version_matches("2.4.1", "2.4.0"));
        assert!(!scorer.minor_version_matches("2.4.1", "2.5.0"));
    }

    #[test]
    fn test_service_matching() {
        let scorer = ConfidenceScorer::new();
        let cve = CveMatch {
            cve_id: "CVE-2024-1234".to_string(),
            description: "Test CVE".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            affected_services: vec!["mysql".to_string()],
            affected_versions: vec![],
            ports: vec![],
            references: vec![],
        };

        // Exact match
        assert_eq!(scorer.calculate_service_match(&cve, "mysql"), 1.0);

        // Alias match
        assert_eq!(scorer.calculate_service_match(&cve, "mariadb"), 0.9);

        // No match
        assert_eq!(scorer.calculate_service_match(&cve, "postgresql"), 0.2);
    }
}
