mod analyzers;
mod isolation;
mod manager;
mod monitor;

pub use analyzers::{PackageAnalyzer, SecurityAnalysis};
pub use isolation::{IsolationConfig, PackageIsolationManager, SecurityLevel};
pub use manager::PackageManager;
pub use monitor::PackageSecurityMonitor;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::{
    ai::AIEngine, behavior::BehaviorEngine, config::ConfigurationManager,
    integrity::IntegrityMonitor, sandbox::Sandbox,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub signatures: Vec<PackageSignature>,
    pub metadata: PackageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageSource {
    // System package managers
    Apt(String),
    Dnf(String),
    Yum(String),
    Pacman(String),
    Zypper(String),

    // Language-specific package managers
    Pip(String),
    Npm(String),
    Cargo(String),
    Gem(String),
    Composer(String),

    // Other sources
    Curl(String),
    Git(String),
    Local(PathBuf),
    Official(String),
    ThirdParty(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub maintainer: Option<String>,
    pub description: Option<String>,
    pub dependencies: Vec<PackageDependency>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub repository: Option<String>,
    pub security_policy: Option<SecurityPolicy>,
    pub package_manager: Option<PackageManagerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManagerInfo {
    pub manager_type: PackageManagerType,
    pub config_path: PathBuf,
    pub log_path: PathBuf,
    pub database_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageManagerType {
    System(SystemPackageManager),
    Language(LanguagePackageManager),
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemPackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LanguagePackageManager {
    Pip,
    Npm,
    Cargo,
    Gem,
    Composer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSignature {
    pub key_id: String,
    pub signature: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub verification_type: SignatureType,
    pub key_source: Option<KeySource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    GPG,
    NPM,
    PIP,
    Cargo,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeySource {
    System,
    UserProvided(PathBuf),
    KeyServer(String),
    PackageManager(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageConfig {
    pub analysis_config: AnalysisConfig,
    pub monitoring_config: MonitoringConfig,
    pub verification_config: VerificationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    pub verify_signatures: bool,
    pub required_for_official: bool,
    pub trusted_keys: Vec<KeySource>,
    pub verification_timeout: Duration,
    pub prompt_for_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_process_monitoring: bool,
    pub enable_filesystem_monitoring: bool,
    pub enable_network_monitoring: bool,
    pub monitoring_interval: Duration,
    pub log_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub enable_deep_inspection: bool,
    pub analysis_timeout: Duration,
    pub max_package_size: usize,
    pub allowed_sources: Vec<String>,
    pub blocked_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDependency {
    pub name: String,
    pub version_requirement: String,
    pub optional: bool,
    pub source: PackageSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub required_permissions: Vec<String>,
    pub network_access: bool,
    pub filesystem_access: FilesystemAccess,
    pub isolation_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilesystemAccess {
    None,
    ReadOnly(Vec<PathBuf>),
    ReadWrite(Vec<PathBuf>),
    Full,
}

#[derive(Error, Debug)]
pub enum PackageError {
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Installation error: {0}")]
    InstallationError(String),

    #[error("Package manager error: {0}")]
    PackageManagerError(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("Isolation error: {0}")]
    IsolationError(String),

    #[error("Monitoring error: {0}")]
    MonitoringError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Key verification error: {0}")]
    KeyVerificationError(String),
}

impl Default for PackageConfig {
    fn default() -> Self {
        Self {
            analysis_config: AnalysisConfig {
                enable_deep_inspection: true,
                analysis_timeout: Duration::from_secs(300),
                max_package_size: 1024 * 1024 * 1024,
                allowed_sources: vec!["official".to_string()],
                blocked_patterns: Vec::new(),
            },
            monitoring_config: MonitoringConfig {
                enable_process_monitoring: true,
                enable_filesystem_monitoring: true,
                enable_network_monitoring: true,
                monitoring_interval: Duration::from_secs(1),
                log_retention_days: 30,
            },
            verification_config: VerificationConfig {
                verify_signatures: true,
                required_for_official: true,
                trusted_keys: vec![KeySource::System],
                verification_timeout: Duration::from_secs(30),
                prompt_for_key: true,
            },
        }
    }
}

// Helper function to check if AI analysis is available
pub fn is_ai_enabled(config: &ConfigurationManager) -> bool {
    if let Ok(system_config) = config.get_current_config() {
        system_config.llm_config.enabled
    } else {
        false
    }
}

// Create a new package instance
pub fn new_package(
    name: String,
    version: String,
    source: PackageSource,
) -> Result<Package, PackageError> {
    if name.is_empty() || version.is_empty() {
        return Err(PackageError::ConfigurationError(
            "Invalid package details".into(),
        ));
    }

    Ok(Package {
        id: format!("{}-{}", name, version),
        name,
        version,
        source,
        signatures: Vec::new(),
        metadata: PackageMetadata {
            maintainer: None,
            description: None,
            dependencies: Vec::new(),
            homepage: None,
            license: None,
            repository: None,
            security_policy: None,
            package_manager: None,
        },
    })
}
