use crate::config::models::{ConfigError, SystemConfiguration};
use serde_json;
use std::path::{Path, PathBuf};
use tokio::fs;

pub struct ConfigurationStorage {
    config_path: PathBuf,
}

impl ConfigurationStorage {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }

    pub async fn load(&self) -> Result<SystemConfiguration, ConfigError> {
        if !self.config_path.exists() {
            return Ok(SystemConfiguration::default());
        }

        let content = fs::read_to_string(&self.config_path).await?;
        let config = serde_json::from_str(&content)?;

        Ok(config)
    }

    pub async fn save(&self, config: &SystemConfiguration) -> Result<(), ConfigError> {
        // Ensure directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Serialize and save atomically
        let temp_path = self.config_path.with_extension("tmp");
        let content = serde_json::to_string_pretty(config)?;

        fs::write(&temp_path, content).await?;
        fs::rename(&temp_path, &self.config_path).await?;

        Ok(())
    }

    pub async fn ensure_config_dir(&self) -> Result<(), ConfigError> {
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }

    pub async fn backup_config(&self) -> Result<PathBuf, ConfigError> {
        let backup_path = self.config_path.with_extension("backup");
        if self.config_path.exists() {
            fs::copy(&self.config_path, &backup_path).await?;
        }
        Ok(backup_path)
    }

    pub async fn restore_backup(&self) -> Result<(), ConfigError> {
        let backup_path = self.config_path.with_extension("backup");
        if backup_path.exists() {
            fs::copy(&backup_path, &self.config_path).await?;
        }
        Ok(())
    }
}
