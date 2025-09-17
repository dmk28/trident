use crate::plugins::core::{Plugin, PluginContext, PluginMetadata, PluginResult};
use crate::plugins::plugin_trait::{Finding, Severity};
use async_trait::async_trait;
use mlua::{Function, Lua, Table, Value};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct LuaPlugin {
    lua: Arc<Mutex<Lua>>,
    script_path: String,
    metadata: PluginMetadata,
}

impl LuaPlugin {
    pub fn new(script_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let script = std::fs::read_to_string(script_path)?;

        // Create metadata - in a real implementation, this could be loaded from the script
        let metadata = PluginMetadata {
            name: "lua_plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Unknown".to_string(),
            description: "Lua plugin".to_string(),
            license: "MIT".to_string(),
            capabilities: Vec::new(),
        };

        // Create Lua instance with send feature enabled
        let lua = Lua::new();

        // Load and execute the script
        lua.load(&script).exec()?;

        Ok(LuaPlugin {
            lua: Arc::new(Mutex::new(lua)),
            script_path: script_path.to_string(),
            metadata,
        })
    }
}

#[async_trait]
impl Plugin for LuaPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let lua_clone = Arc::clone(&self.lua);

        let result = tokio::task::spawn_blocking(move || {
            let lua = futures::executor::block_on(lua_clone.lock());

            // Check if initialize function exists and call it
            let globals = lua.globals();
            if let Ok(init_fn) = globals.get::<_, Function>("initialize") {
                init_fn.call::<_, ()>(()).map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e: String| {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                as Box<dyn std::error::Error>
        })?;

        Ok(result)
    }

    async fn execute(
        &self,
        context: PluginContext,
    ) -> Result<PluginResult, Box<dyn std::error::Error>> {
        let lua_clone = Arc::clone(&self.lua);

        let result = tokio::task::spawn_blocking(move || {
            let lua = futures::executor::block_on(lua_clone.lock());

            // Check if execute function exists
            let globals = lua.globals();

            if let Ok(execute_fn) = globals.get::<_, Function>("execute") {
                // Create a Lua table from the context
                let ctx_table = lua.create_table().map_err(|e| e.to_string())?;

                // Set target IP and port
                ctx_table
                    .set("target_ip", format!("{}", context.target_ip))
                    .map_err(|e| e.to_string())?;
                ctx_table
                    .set("target_port", context.target_port)
                    .map_err(|e| e.to_string())?;

                // Add config to the table
                let config_table = lua.create_table().map_err(|e| e.to_string())?;
                config_table
                    .set("enabled", context.config.enabled)
                    .map_err(|e| e.to_string())?;
                config_table
                    .set("timeout_seconds", context.config.timeout_seconds)
                    .map_err(|e| e.to_string())?;

                // Add config options
                let options_table = lua.create_table().map_err(|e| e.to_string())?;
                for (key, value) in context.config.options.iter() {
                    options_table
                        .set(key.as_str(), value.as_str())
                        .map_err(|e| e.to_string())?;
                }
                config_table
                    .set("options", options_table)
                    .map_err(|e| e.to_string())?;
                ctx_table
                    .set("config", config_table)
                    .map_err(|e| e.to_string())?;

                // Add shared data
                let shared_table = lua.create_table().map_err(|e| e.to_string())?;
                for (key, value) in context.shared_data.iter() {
                    shared_table
                        .set(key.as_str(), value.as_str())
                        .map_err(|e| e.to_string())?;
                }
                ctx_table
                    .set("shared_data", shared_table)
                    .map_err(|e| e.to_string())?;

                // Call the execute function
                let result_value: Value = execute_fn.call(ctx_table).map_err(|e| e.to_string())?;

                // Parse the result
                if let Value::Table(result_table) = result_value {
                    let mut findings = Vec::new();
                    let mut metadata = HashMap::new();
                    let mut raw_data = None;

                    // Extract findings if present
                    if let Ok(findings_table) = result_table.get::<_, Table>("findings") {
                        for pair in findings_table.pairs::<i32, Table>() {
                            if let Ok((_, finding_table)) = pair {
                                // Parse severity
                                let severity_str = finding_table
                                    .get::<_, String>("severity")
                                    .unwrap_or_else(|_| "info".to_string())
                                    .to_lowercase();

                                let severity = match severity_str.as_str() {
                                    "critical" => Severity::Critical,
                                    "high" => Severity::High,
                                    "medium" => Severity::Medium,
                                    "low" => Severity::Low,
                                    _ => Severity::Info,
                                };

                                // Parse other finding fields
                                let title = finding_table
                                    .get::<_, String>("title")
                                    .unwrap_or_else(|_| "Unknown".to_string());
                                let description = finding_table
                                    .get::<_, String>("description")
                                    .unwrap_or_else(|_| "".to_string());
                                let confidence =
                                    finding_table.get::<_, f32>("confidence").unwrap_or(0.5);

                                // Parse evidence array
                                let mut evidence = Vec::new();
                                if let Ok(evidence_table) =
                                    finding_table.get::<_, Table>("evidence")
                                {
                                    for pair in evidence_table.pairs::<i32, String>() {
                                        if let Ok((_, ev)) = pair {
                                            evidence.push(ev);
                                        }
                                    }
                                }

                                // Parse recommendations array
                                let mut recommendations = Vec::new();
                                if let Ok(rec_table) =
                                    finding_table.get::<_, Table>("recommendations")
                                {
                                    for pair in rec_table.pairs::<i32, String>() {
                                        if let Ok((_, rec)) = pair {
                                            recommendations.push(rec);
                                        }
                                    }
                                }

                                // Parse references array
                                let mut references = Vec::new();
                                if let Ok(ref_table) = finding_table.get::<_, Table>("references") {
                                    for pair in ref_table.pairs::<i32, String>() {
                                        if let Ok((_, rf)) = pair {
                                            references.push(rf);
                                        }
                                    }
                                }

                                // Parse metadata
                                let mut finding_metadata = HashMap::new();
                                if let Ok(meta_table) = finding_table.get::<_, Table>("metadata") {
                                    for pair in meta_table.pairs::<String, String>() {
                                        if let Ok((key, value)) = pair {
                                            finding_metadata.insert(key, value);
                                        }
                                    }
                                }

                                findings.push(Finding {
                                    title,
                                    description,
                                    severity,
                                    confidence,
                                    evidence,
                                    recommendations,
                                    references,
                                    metadata: finding_metadata,
                                });
                            }
                        }
                    }

                    // Extract metadata if present
                    if let Ok(metadata_table) = result_table.get::<_, Table>("metadata") {
                        for pair in metadata_table.pairs::<String, String>() {
                            if let Ok((key, value)) = pair {
                                metadata.insert(key, value);
                            }
                        }
                    }

                    // Extract raw_data if present
                    if let Ok(raw_data_str) = result_table.get::<_, String>("raw_data") {
                        raw_data = Some(raw_data_str.into_bytes());
                    } else if let Ok(raw_data_table) = result_table.get::<_, Table>("raw_data") {
                        // Support raw_data as byte array
                        let mut bytes = Vec::new();
                        for pair in raw_data_table.pairs::<i32, u8>() {
                            if let Ok((_, byte)) = pair {
                                bytes.push(byte);
                            }
                        }
                        if !bytes.is_empty() {
                            raw_data = Some(bytes);
                        }
                    }

                    return Ok(PluginResult {
                        findings,
                        raw_data,
                        metadata,
                    });
                }
            }

            // If no execute function or invalid return, return empty result
            Ok::<PluginResult, String>(PluginResult {
                findings: Vec::new(),
                raw_data: None,
                metadata: HashMap::new(),
            })
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e: String| {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                as Box<dyn std::error::Error>
        })?;

        Ok(result)
    }

    async fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let lua_clone = Arc::clone(&self.lua);

        let result = tokio::task::spawn_blocking(move || {
            let lua = futures::executor::block_on(lua_clone.lock());

            // Check if cleanup function exists and call it
            let globals = lua.globals();
            if let Ok(cleanup_fn) = globals.get::<_, Function>("cleanup") {
                cleanup_fn.call::<_, ()>(()).map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e: String| {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                as Box<dyn std::error::Error>
        })?;

        Ok(result)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
