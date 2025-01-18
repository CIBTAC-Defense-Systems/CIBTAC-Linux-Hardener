mod container;
mod network;
mod policy;
mod resources;

pub use container::Sandbox;
pub use network::NetworkPolicy;
pub use policy::{PolicyRule, SandboxPolicy};
pub use resources::ResourceLimits;

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub isolation_level: IsolationLevel,
    pub network_policy: NetworkPolicy,
    pub resource_limits: ResourceLimits,
    pub filesystem_policy: FilesystemPolicy,
    pub monitoring_config: MonitoringConfig,
}

#[derive(Debug, Clone)]
pub enum IsolationLevel {
    Minimal,  // Basic process isolation
    Standard, // Default for trusted applications
    High,     // Enhanced isolation for third-party apps
    Maximum,  // Maximum isolation for untrusted code
    Custom(Box<IsolationConfig>),
}

#[derive(Debug, Clone)]
pub struct IsolationConfig {
    pub namespace_isolation: NamespaceConfig,
    pub seccomp_profile: Option<String>,
    pub apparmor_profile: Option<String>,
    pub selinux_context: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub user_ns: bool,
    pub pid_ns: bool,
    pub net_ns: bool,
    pub mount_ns: bool,
    pub ipc_ns: bool,
    pub uts_ns: bool,
    pub cgroup_ns: bool,
}

#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub enable_resource_monitoring: bool,
    pub enable_network_monitoring: bool,
    pub enable_syscall_monitoring: bool,
    pub monitoring_interval: std::time::Duration,
}

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Filesystem error: {0}")]
    FilesystemError(String),

    #[error("Process error: {0}")]
    ProcessError(String),
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            isolation_level: IsolationLevel::Standard,
            network_policy: NetworkPolicy::default(),
            resource_limits: ResourceLimits::default(),
            filesystem_policy: FilesystemPolicy::default(),
            monitoring_config: MonitoringConfig::default(),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_resource_monitoring: true,
            enable_network_monitoring: true,
            enable_syscall_monitoring: true,
            monitoring_interval: std::time::Duration::from_secs(1),
        }
    }
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            user_ns: true,
            pid_ns: true,
            net_ns: true,
            mount_ns: true,
            ipc_ns: true,
            uts_ns: true,
            cgroup_ns: false,
        }
    }
}
