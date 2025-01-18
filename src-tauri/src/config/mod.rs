mod manager;
mod models;
mod storage;

pub use manager::ConfigurationManager;
pub use models::{
    ConfigError, InitializationStatus, LLMConfiguration, SecurityConfig, SystemConfiguration,
    UIPreferences,
};
pub use storage::ConfigurationStorage;

// Re-export common types and constants
pub const CONFIG_VERSION: &str = "1.0.0";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/cibtac/config.json";
