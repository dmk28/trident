use crate::plugins::core::{Plugin, PluginCapability, PluginConfig, PluginContext, PluginResult};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::read_dir;
use tokio::sync::RwLock;
use toml;

pub struct PluginRegistry {
    plugins: Arc<RwLock<HashMap<String, Box<dyn Plugin>>>>,
    configs: Arc<RwLock<HashMap<String, PluginConfig>>>,
    plugin_paths: Vec<PathBuf>,
}

impl PluginRegistry {
    fn matches_capability(a: &PluginCapability, b: &PluginCapability) -> bool {
        use PluginCapability::*;

        match (a, b) {
            // ServiceDetection matches if any ports overlap
            (ServiceDetection { ports: a_ports }, ServiceDetection { ports: b_ports }) => {
                a_ports.iter().any(|port| b_ports.contains(port))
            }

            // VulnerabilityScanning matches if any service types overlap
            (
                VulnerabilityScanning {
                    service_types: a_types,
                },
                VulnerabilityScanning {
                    service_types: b_types,
                },
            ) => a_types.iter().any(|svc| b_types.contains(svc)),

            // BannerGrabbing matches if any protocols overlap
            (
                BannerGrabbing {
                    protocols: a_protos,
                },
                BannerGrabbing {
                    protocols: b_protos,
                },
            ) => a_protos.iter().any(|proto| b_protos.contains(proto)),

            // Custom matches if the strings are equal
            (Custom(a_str), Custom(b_str)) => a_str == b_str,

            // Different capability types don't match
            _ => false,
        }
    }

    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
            plugin_paths: vec![],
        }
    }

    pub fn add_plugin_path(&mut self, path: PathBuf) {
        self.plugin_paths.push(path);
    }

    pub async fn load_plugins(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut loaded = 0;

        for path in &self.plugin_paths {
            loaded += self.load_plugins_from_directory(path).await?;
        }
        Ok(loaded)
    }

    async fn load_plugins_from_directory(
        &self,
        path: &Path,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut loaded = 0;

        let mut entries = tokio::fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "so") {
                // Note: load_plugin method doesn't exist, should be load_plugin_from_manifest
                // For now, skip this as it needs proper implementation
                // loaded += self.load_plugin(&path).await?;
            }
        }
        Ok(loaded)
    }

    async fn load_plugin_from_manifest(
        &self,
        manifest_path: &Path,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let manifest_content = tokio::fs::read_to_string(manifest_path).await?;
        let manifest: PluginManifest = toml::from_str(&manifest_content)?;
        match manifest.plugin_type.as_str() {
            "native" => {
                self.load_native_plugin(&manifest, manifest_path.parent().unwrap())
                    .await
            }
            "script" => {
                self.load_script_plugin(&manifest, manifest_path.parent().unwrap())
                    .await
            }
            _ => Err("Unsupported plugin type".into()),
        }
    }

    async fn load_native_plugin(
        &self,
        manifest: &PluginManifest,
        plugin_dir: &Path,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let library_path = plugin_dir.join(&manifest.entry_point);
        let plugin = crate::plugins::loader::native::load_native_plugin(&library_path)?;
        self.register_plugin(plugin).await?;
        Ok(1)
    }

    async fn load_script_plugin(
        &self,
        manifest: &PluginManifest,
        plugin_dir: &Path,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let script_path = plugin_dir.join(&manifest.entry_point);
        let script_path_str = script_path.to_str().ok_or("Invalid script path")?;
        let plugin = Box::new(crate::plugins::loader::script::LuaPlugin::new(
            script_path_str,
        )?);
        self.register_plugin(plugin).await?;
        Ok(1)
    }

    pub async fn register_plugin(
        &self,
        mut plugin: Box<dyn Plugin>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize first, then get metadata (to avoid borrow issues)
        plugin.initialize().await?;
        let metadata = plugin.metadata();
        let mut plugins = self.plugins.write().await;
        plugins.insert(metadata.name.clone(), plugin);
        Ok(())
    }

    pub async fn get_plugins_by_capability(&self, capability: &PluginCapability) -> Vec<String> {
        let plugins = self.plugins.read().await;

        let mut matching = Vec::new();
        for (name, plugin) in plugins.iter() {
            let metadata = plugin.metadata();
            if metadata
                .capabilities
                .iter()
                .any(|c| Self::matches_capability(c, capability))
            {
                matching.push(name.clone());
            }
        }
        matching
    }

    pub async fn execute_plugin(
        &self,
        plugin_name: &str,
        context: PluginContext,
    ) -> Result<PluginResult, Box<dyn std::error::Error>> {
        let plugins = self.plugins.read().await;
        let plugin = plugins
            .get(plugin_name)
            .ok_or_else(|| format!("Plugin {} not found", plugin_name))?;
        plugin.execute(context).await
    }
}

#[derive(Debug, Deserialize)]
struct PluginManifest {
    pub name: String,
    pub version: String,
    pub plugin_type: String,
    pub entry_point: String,
    pub author: String,
    pub description: String,
    pub license: String,
    pub capabilities: Vec<String>,
    pub dependencies: Option<Vec<String>>,
    pub config: Option<HashMap<String, String>>,
}
