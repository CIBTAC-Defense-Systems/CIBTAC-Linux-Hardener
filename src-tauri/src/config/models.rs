use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfiguration {
    pub version: String,
    pub first_run: bool,
    pub llm_config: LLMConfiguration,
    pub security_config: SecurityConfig,
    pub ui_preferences: UIPreferences,
    pub package_analysis_config: PackageAnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfiguration {
    pub enabled: bool,
    pub model_path: Option<PathBuf>,
    pub model_type: Option<String>,
    pub max_memory_usage: Option<usize>,
    pub threads: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub kernel_hardening: bool,
    pub behavior_detection: bool,
    pub sandboxing: bool,
    pub mac_enforcement: bool,
    pub integrity_monitoring: bool,
    pub ai_analysis: bool,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageAnalysisConfig {
    pub enable_deep_inspection: bool,
    pub analysis_timeout: u64,
    pub max_package_size: usize,
    pub allowed_sources: Vec<String>,
    pub blocked_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UIPreferences {
    pub theme: String,
    pub log_level_display: String,
    pub dashboard_layout: String,
    pub refresh_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InitializationStatus {
    RequiresSetup,
    Ready,
    Error(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to load configuration: {0}")]
    LoadError(String),

    #[error("Failed to save configuration: {0}")]
    SaveError(String),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),

    #[error("LLM configuration error: {0}")]
    LLMError(String),

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

impl Default for SystemConfiguration {
    fn default() -> Self {
        Self {
            version: crate::config::CONFIG_VERSION.to_string(),
            first_run: true,
            llm_config: LLMConfiguration::default(),
            security_config: SecurityConfig::default(),
            ui_preferences: UIPreferences::default(),
            package_analysis_config: PackageAnalysisConfig::default(),
        }
    }
}

impl Default for LLMConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: None,
            model_type: None,
            max_memory_usage: Some(4 * 1024 * 1024 * 1024), // 4GB default
            threads: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            kernel_hardening: true,
            behavior_detection: true,
            sandboxing: true,
            mac_enforcement: true,
            integrity_monitoring: true,
            ai_analysis: false,
            log_level: LogLevel::Info,
        }
    }
}

impl Default for UIPreferences {
    fn default() -> Self {
        Self {
            theme: "light".to_string(),
            log_level_display: "info".to_string(),
            dashboard_layout: "default".to_string(),
            refresh_interval: 5000,
        }
    }
}

impl Default for PackageAnalysisConfig {
    fn default() -> Self {
        Self {
            enable_deep_inspection: true,
            analysis_timeout: 300,                // 5 minutes
            max_package_size: 1024 * 1024 * 1024, // 1GB
            allowed_sources: vec!["official".to_string()],
            blocked_patterns: Vec::new(),
        }
    }
}
