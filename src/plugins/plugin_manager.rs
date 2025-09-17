use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;

use super::plugin_trait::{Plugin, PluginConfig, PluginPriority, PluginResult};
use crate::scanner::ScanResult;

/// Plugin execution statistics
#[derive(Debug, Clone)]
pub struct PluginStats {
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub total_execution_time: Duration,
    pub average_execution_time: Duration,
    pub findings_generated: u64,
}

impl Default for PluginStats {
    fn default() -> Self {
        Self {
            total_executions: 0,
            successful_executions: 0,
            failed_executions: 0,
            total_execution_time: Duration::from_secs(0),
            average_execution_time: Duration::from_secs(0),
            findings_generated: 0,
        }
    }
}

/// Plugin execution mode
#[derive(Debug, Clone)]
pub enum ExecutionMode {
    Sequential, // Execute plugins one by one
    Parallel,   // Execute all plugins concurrently
    Priority,   // Execute by priority groups (Critical first, then High, etc.)
}

/// Main plugin management system
pub struct PluginManager {
    plugins: Vec<Arc<dyn Plugin>>,
    configs: HashMap<String, PluginConfig>,
    stats: HashMap<String, PluginStats>,
    execution_mode: ExecutionMode,
    global_timeout: Duration,
    verbose: bool,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            configs: HashMap::new(),
            stats: HashMap::new(),
            execution_mode: ExecutionMode::Sequential,
            global_timeout: Duration::from_secs(300),
            verbose: false,
        }
    }

    pub fn new_with_verbose(verbose: bool) -> Self {
        Self {
            plugins: Vec::new(),
            configs: HashMap::new(),
            stats: HashMap::new(),
            execution_mode: ExecutionMode::Sequential,
            global_timeout: Duration::from_secs(300),
            verbose,
        }
    }

    /// Register a plugin
    pub fn register_plugin(&mut self, plugin: Arc<dyn Plugin>) {
        let name = plugin.name().to_string();
        self.plugins.push(plugin);
        self.configs.insert(name.clone(), PluginConfig::default());
        self.stats.insert(name, PluginStats::default());
    }

    /// Configure a specific plugin
    pub fn configure_plugin(
        &mut self,
        plugin_name: &str,
        config: PluginConfig,
    ) -> Result<(), String> {
        if let Some(plugin) = self.plugins.iter().find(|p| p.name() == plugin_name) {
            plugin.validate_config(&config)?;
            self.configs.insert(plugin_name.to_string(), config);
            Ok(())
        } else {
            Err(format!("Plugin '{}' not found", plugin_name))
        }
    }

    /// Set global execution parameters
    pub fn set_execution_mode(&mut self, mode: ExecutionMode) {
        self.execution_mode = mode;
    }

    /// Execute plugins against scan results
    pub async fn execute_plugins(&mut self, scan_results: &[ScanResult]) -> Vec<PluginResult> {
        self.execute_plugins_with_target(scan_results, [127, 0, 0, 1].into())
            .await
    }

    /// Execute plugins against scan results with specific target IP
    pub async fn execute_plugins_with_target(
        &mut self,
        scan_results: &[ScanResult],
        target_ip: IpAddr,
    ) -> Vec<PluginResult> {
        let start_time = Instant::now();
        let mut all_results = Vec::new();

        if self.verbose {
            println!(
                "🔍 Running plugins against {} scan results...",
                scan_results.len()
            );
        }

        for scan_result in scan_results {
            let results = self
                .execute_plugins_for_result_with_target(scan_result, target_ip)
                .await;
            all_results.extend(results);
        }

        let total_time = start_time.elapsed();
        if self.verbose {
            println!("✅ Plugin execution complete in {:?}", total_time);
        }
        self.print_summary(&all_results);

        all_results
    }

    /// Execute plugins for a single scan result
    async fn execute_plugins_for_result(&mut self, scan_result: &ScanResult) -> Vec<PluginResult> {
        self.execute_plugins_for_result_with_target(scan_result, [127, 0, 0, 1].into())
            .await
    }

    /// Execute plugins for a single scan result with specific target IP
    async fn execute_plugins_for_result_with_target(
        &mut self,
        scan_result: &ScanResult,
        target_ip: IpAddr,
    ) -> Vec<PluginResult> {
        let mut results = Vec::new();
        let mut sorted_plugins: Vec<_> = self.plugins.iter().cloned().collect();
        sorted_plugins.sort_by(|a, b| a.priority().cmp(&b.priority()));

        for plugin in sorted_plugins {
            let plugin_name = plugin.name().to_string();
            if let Some(config) = self.configs.get(&plugin_name).cloned() {
                if config.enabled && plugin.can_analyze(scan_result) {
                    let result = self
                        .execute_single_plugin_with_target(
                            plugin.clone(),
                            scan_result,
                            &config,
                            target_ip,
                        )
                        .await;
                    // Update stats after the borrow check passes
                    if let Some(stats) = self.stats.get_mut(&plugin_name) {
                        stats.total_executions += 1;
                        if result.success {
                            stats.successful_executions += 1;
                        } else {
                            stats.failed_executions += 1;
                        }
                        stats.total_execution_time += result.execution_time;
                        stats.average_execution_time =
                            stats.total_execution_time / stats.total_executions as u32;
                        stats.findings_generated += result.findings.len() as u64;
                    }
                    results.push(result);
                }
            }
        }

        results
    }

    /// Execute a single plugin with timeout and error handling
    async fn execute_single_plugin(
        &self,
        plugin: Arc<dyn Plugin>,
        scan_result: &ScanResult,
        config: &PluginConfig,
    ) -> PluginResult {
        self.execute_single_plugin_with_target(plugin, scan_result, config, [127, 0, 0, 1].into())
            .await
    }

    /// Execute a single plugin with timeout and error handling and specific target IP
    async fn execute_single_plugin_with_target(
        &self,
        plugin: Arc<dyn Plugin>,
        scan_result: &ScanResult,
        config: &PluginConfig,
        target_ip: IpAddr,
    ) -> PluginResult {
        let start_time = Instant::now();
        let plugin_timeout = Duration::from_secs(config.timeout_seconds);

        let result = timeout(
            plugin_timeout,
            plugin.analyze(target_ip, scan_result.port, scan_result, config),
        )
        .await;

        match result {
            Ok(mut plugin_result) => {
                plugin_result.execution_time = start_time.elapsed();
                plugin_result
            }
            Err(_) => PluginResult {
                plugin_name: plugin.name().to_string(),
                target_ip,
                target_port: scan_result.port,
                execution_time: start_time.elapsed(),
                success: false,
                error_message: Some("Plugin execution timed out".to_string()),
                findings: Vec::new(),
                raw_data: None,
            },
        }
    }

    /// Print execution summary
    fn print_summary(&self, results: &[PluginResult]) {
        let total_plugins = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let failed = total_plugins - successful;
        let total_findings = results.iter().map(|r| r.findings.len()).sum::<usize>();

        println!("\n📊 Plugin Execution Summary:");
        println!("   Total plugins executed: {}", total_plugins);
        println!("   Successful: {} | Failed: {}", successful, failed);
        println!("   Total findings: {}", total_findings);

        if total_findings > 0 {
            println!("\n🔍 Findings by severity:");
            let mut severity_counts = HashMap::new();
            for result in results {
                for finding in &result.findings {
                    *severity_counts
                        .entry(format!("{:?}", finding.severity))
                        .or_insert(0) += 1;
                }
            }
            for (severity, count) in severity_counts {
                println!("   {}: {}", severity, count);
            }
        }
    }

    /// Get plugin statistics
    pub fn get_stats(&self, plugin_name: &str) -> Option<&PluginStats> {
        self.stats.get(plugin_name)
    }

    /// List all registered plugins
    pub fn list_plugins(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }
}
