use crate::plugins::plugin_trait::{Finding, PluginResult};
use crate::scanner::ScanResult;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Output format types
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Markdown,
}

/// Scan session summary for output
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSession {
    pub session_id: String,
    pub timestamp: String,
    pub target_ip: String,
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub filtered_ports: usize,
    pub closed_ports: usize,
    pub scan_duration_ms: u128,
    pub plugin_results: Vec<PluginResultOutput>,
}

/// Plugin result for output serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginResultOutput {
    pub plugin_name: String,
    pub target_ip: String,
    pub target_port: u16,
    pub execution_time_ms: u128,
    pub success: bool,
    pub error_message: Option<String>,
    pub findings_count: usize,
    pub findings: Vec<FindingOutput>,
}

/// Finding for output serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct FindingOutput {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
    pub references: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl From<&PluginResult> for PluginResultOutput {
    fn from(result: &PluginResult) -> Self {
        Self {
            plugin_name: result.plugin_name.clone(),
            target_ip: result.target_ip.to_string(),
            target_port: result.target_port,
            execution_time_ms: result.execution_time.as_millis(),
            success: result.success,
            error_message: result.error_message.clone(),
            findings_count: result.findings.len(),
            findings: result.findings.iter().map(FindingOutput::from).collect(),
        }
    }
}

impl From<&Finding> for FindingOutput {
    fn from(finding: &Finding) -> Self {
        Self {
            title: finding.title.clone(),
            description: finding.description.clone(),
            severity: format!("{:?}", finding.severity),
            confidence: finding.confidence,
            evidence: finding.evidence.clone(),
            recommendations: finding.recommendations.clone(),
            references: finding.references.clone(),
            metadata: finding.metadata.clone(),
        }
    }
}

/// Main output writer
pub struct OutputWriter {
    format: OutputFormat,
    output_dir: String,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, output_dir: Option<String>) -> Self {
        Self {
            format,
            output_dir: output_dir.unwrap_or_else(|| "trident_outputs".to_string()),
        }
    }

    /// Generate timestamped filename
    fn generate_filename(&self, target_ip: &str) -> String {
        let now: DateTime<Local> = Local::now();
        let timestamp = now.format("%H%M%S-%m%d%Y");
        let extension = match self.format {
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "md",
        };
        format!(
            "trident-{}-{}.{}",
            timestamp,
            target_ip.replace(".", "_"),
            extension
        )
    }

    /// Write scan results to file
    pub fn write_scan_results(
        &self,
        target_ip: &str,
        scan_results: &[ScanResult],
        plugin_results: &[PluginResult],
        scan_duration: std::time::Duration,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Create output directory if it doesn't exist
        fs::create_dir_all(&self.output_dir)?;

        // Generate filename
        let filename = self.generate_filename(target_ip);
        let filepath = Path::new(&self.output_dir).join(filename);

        // Count port statuses
        let mut open_ports = 0;
        let mut filtered_ports = 0;
        let mut closed_ports = 0;

        for result in scan_results {
            match result.status {
                crate::scanner::PortStatus::Open => open_ports += 1,
                crate::scanner::PortStatus::Filtered => filtered_ports += 1,
                crate::scanner::PortStatus::Closed => closed_ports += 1,
                crate::scanner::PortStatus::OpenFiltered => filtered_ports += 1, //defaulting to filtered
                crate::scanner::PortStatus::ClosedFiltered => filtered_ports += 1, //defaulting to filtered
            }
        }

        // Create session data
        let session = ScanSession {
            session_id: format!("trident-{}", Local::now().timestamp()),
            timestamp: Local::now().to_rfc3339(),
            target_ip: target_ip.to_string(),
            total_ports_scanned: scan_results.len(),
            open_ports,
            filtered_ports,
            closed_ports,
            scan_duration_ms: scan_duration.as_millis(),
            plugin_results: plugin_results
                .iter()
                .map(PluginResultOutput::from)
                .collect(),
        };

        // Write to file based on format
        let content = match self.format {
            OutputFormat::Json => self.generate_json(&session)?,
            OutputFormat::Markdown => self.generate_markdown(&session, scan_results)?,
        };

        fs::write(&filepath, content)?;
        Ok(filepath.to_string_lossy().to_string())
    }

    /// Generate JSON output
    fn generate_json(&self, session: &ScanSession) -> Result<String, Box<dyn std::error::Error>> {
        Ok(serde_json::to_string_pretty(session)?)
    }

    /// Generate Markdown output
    fn generate_markdown(
        &self,
        session: &ScanSession,
        scan_results: &[ScanResult],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut content = String::new();

        // Header
        content.push_str("# Trident Security Scan Report\n\n");
        content.push_str(&format!("**Session ID:** {}\n", session.session_id));
        content.push_str(&format!("**Timestamp:** {}\n", session.timestamp));
        content.push_str(&format!("**Target IP:** {}\n", session.target_ip));
        content.push_str(&format!(
            "**Scan Duration:** {} ms\n\n",
            session.scan_duration_ms
        ));

        // Port scan summary
        content.push_str("## Port Scan Summary\n\n");
        content.push_str(&format!(
            "- **Total Ports Scanned:** {}\n",
            session.total_ports_scanned
        ));
        content.push_str(&format!("- **Open Ports:** {}\n", session.open_ports));
        content.push_str(&format!(
            "- **Filtered Ports:** {}\n",
            session.filtered_ports
        ));
        content.push_str(&format!("- **Closed Ports:** {}\n\n", session.closed_ports));

        // Open ports table
        if session.open_ports > 0 {
            content.push_str("### Open Ports\n\n");
            content.push_str("| Port | Status |\n");
            content.push_str("|------|--------|\n");

            for result in scan_results {
                if matches!(result.status, crate::scanner::PortStatus::Open) {
                    content.push_str(&format!("| {} | {:?} |\n", result.port, result.status));
                }
            }
            content.push_str("\n");
        }

        // Security findings
        content.push_str("## Security Analysis Results\n\n");

        let total_findings: usize = session
            .plugin_results
            .iter()
            .map(|r| r.findings_count)
            .sum();

        if total_findings > 0 {
            content.push_str(&format!("**Total Findings:** {}\n\n", total_findings));

            for plugin_result in &session.plugin_results {
                if plugin_result.findings_count > 0 {
                    content.push_str(&format!(
                        "### {} ({}:{})\n\n",
                        plugin_result.plugin_name,
                        plugin_result.target_ip,
                        plugin_result.target_port
                    ));

                    content.push_str(&format!(
                        "- **Execution Time:** {} ms\n",
                        plugin_result.execution_time_ms
                    ));
                    content.push_str(&format!("- **Success:** {}\n", plugin_result.success));

                    if let Some(ref error) = plugin_result.error_message {
                        content.push_str(&format!("- **Error:** {}\n", error));
                    }

                    content.push_str("\n#### Findings\n\n");

                    for finding in &plugin_result.findings {
                        let severity_emoji = match finding.severity.as_str() {
                            "Critical" => "🔴",
                            "High" => "🟠",
                            "Medium" => "🟡",
                            "Low" => "🔵",
                            _ => "ℹ️",
                        };

                        content.push_str(&format!("**{} {}**\n\n", severity_emoji, finding.title));
                        content.push_str(&format!("**Severity:** {}\n", finding.severity));
                        content.push_str(&format!(
                            "**Confidence:** {:.1}%\n\n",
                            finding.confidence * 100.0
                        ));
                        content.push_str(&format!("**Description:** {}\n\n", finding.description));

                        if !finding.evidence.is_empty() {
                            content.push_str("**Evidence:**\n");
                            for evidence in &finding.evidence {
                                content.push_str(&format!("- {}\n", evidence));
                            }
                            content.push_str("\n");
                        }

                        if !finding.recommendations.is_empty() {
                            content.push_str("**Recommendations:**\n");
                            for rec in &finding.recommendations {
                                content.push_str(&format!("- {}\n", rec));
                            }
                            content.push_str("\n");
                        }

                        if !finding.references.is_empty() {
                            content.push_str("**References:**\n");
                            for reference in &finding.references {
                                content.push_str(&format!("- {}\n", reference));
                            }
                            content.push_str("\n");
                        }

                        if !finding.metadata.is_empty() {
                            content.push_str("**Metadata:**\n");
                            for (key, value) in &finding.metadata {
                                content.push_str(&format!("- **{}:** {}\n", key, value));
                            }
                            content.push_str("\n");
                        }

                        content.push_str("---\n\n");
                    }
                }
            }
        } else {
            content.push_str("✅ **No security issues detected by plugins**\n\n");
        }

        // Footer
        content.push_str("---\n\n");
        content.push_str("*Report generated by Trident Security Scanner*");

        Ok(content)
    }

    /// Write summary to console
    pub fn print_summary(&self, session: &ScanSession) {
        println!("\n📊 === Scan Summary ===");
        println!("Target: {}", session.target_ip);
        println!("Ports scanned: {}", session.total_ports_scanned);
        println!(
            "Open: {}, Filtered: {}, Closed: {}",
            session.open_ports, session.filtered_ports, session.closed_ports
        );
        println!("Scan duration: {} ms", session.scan_duration_ms);

        let total_findings: usize = session
            .plugin_results
            .iter()
            .map(|r| r.findings_count)
            .sum();
        if total_findings > 0 {
            println!("Security findings: {}", total_findings);

            // Count by severity
            let mut critical = 0;
            let mut high = 0;
            let mut medium = 0;
            let mut low = 0;
            let mut info = 0;

            for plugin_result in &session.plugin_results {
                for finding in &plugin_result.findings {
                    match finding.severity.as_str() {
                        "Critical" => critical += 1,
                        "High" => high += 1,
                        "Medium" => medium += 1,
                        "Low" => low += 1,
                        _ => info += 1,
                    }
                }
            }

            if critical > 0 {
                println!("  🔴 Critical: {}", critical);
            }
            if high > 0 {
                println!("  🟠 High: {}", high);
            }
            if medium > 0 {
                println!("  🟡 Medium: {}", medium);
            }
            if low > 0 {
                println!("  🔵 Low: {}", low);
            }
            if info > 0 {
                println!("  ℹ️ Info: {}", info);
            }
        } else {
            println!("✅ No security issues detected");
        }
    }
}
