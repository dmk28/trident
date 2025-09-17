use crate::plugins::plugin_trait::Finding;
use crate::scanner::ScanResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub license: String,
    pub capabilities: Vec<PluginCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCapability {
    ServiceDetection { ports: Vec<u16> },
    VulnerabilityScanning { service_types: Vec<String> },
    BannerGrabbing { protocols: Vec<String> },
    Custom(String),
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> &PluginMetadata;

    async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    async fn execute(
        &self,
        context: PluginContext,
    ) -> Result<PluginResult, Box<dyn std::error::Error>>;

    async fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    fn as_any(&self) -> &dyn Any;
}

#[derive(Debug, Clone)]
pub struct PluginContext {
    pub target_ip: std::net::IpAddr,
    pub target_port: u16,
    pub scan_result: Option<ScanResult>,
    pub config: PluginConfig,
    pub shared_data: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub timeout_seconds: u64,
    pub options: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PluginResult {
    pub findings: Vec<Finding>,
    pub raw_data: Option<Vec<u8>>,
    pub metadata: std::collections::HashMap<String, String>,
}
