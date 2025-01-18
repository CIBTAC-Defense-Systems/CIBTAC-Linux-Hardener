use super::models::{
    ConfigError, InitializationStatus, LLMConfiguration, SecurityConfig, SystemConfiguration,
    UIPreferences,
};
use super::storage::ConfigurationStorage;
use crate::config::DEFAULT_CONFIG_PATH;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ConfigurationManager {
    storage: ConfigurationStorage,
    current_config: Arc<RwLock<SystemConfiguration>>,
}

impl ConfigurationManager {
    pub async fn new() -> Result<Self, ConfigError> {
        let storage = ConfigurationStorage::new(DEFAULT_CONFIG_PATH);
        let config = storage.load().await?;

        Ok(Self {
            storage,
            current_config: Arc::new(RwLock::new(config)),
        })
    }

    pub async fn new_with_path(
        config_path: impl Into<std::path::PathBuf>,
    ) -> Result<Self, ConfigError> {
        let storage = ConfigurationStorage::new(config_path);
        let config = storage.load().await?;

        Ok(Self {
            storage,
            current_config: Arc::new(RwLock::new(config)),
        })
    }

    pub async fn initialize(&self) -> Result<InitializationStatus, ConfigError> {
        let config = self.current_config.read().await;

        // Check if this is the first run
        if config.first_run {
            return Ok(InitializationStatus::RequiresSetup);
        }

        // Verify LLM configuration if AI analysis is enabled
        if config.security_config.ai_analysis {
            if let Err(e) = self.verify_llm_configuration(&config.llm_config).await {
                return Ok(InitializationStatus::Error(e.to_string()));
            }
        }

        Ok(InitializationStatus::Ready)
    }

    pub async fn get_current_config(&self) -> Result<SystemConfiguration, ConfigError> {
        Ok(self.current_config.read().await.clone())
    }

    pub async fn update_config(&self, config: SystemConfiguration) -> Result<(), ConfigError> {
        // Validate the new configuration
        self.validate_configuration(&config).await?;

        // Save to storage first
        self.storage.backup_config().await?;
        self.storage.save(&config).await?;

        // Update current config
        let mut current = self.current_config.write().await;
        *current = config;

        Ok(())
    }

    pub async fn complete_initial_setup(
        &mut self,
        llm_config: LLMConfiguration,
        security_config: SecurityConfig,
        ui_preferences: UIPreferences,
    ) -> Result<(), ConfigError> {
        let mut config = self.current_config.write().await;

        config.first_run = false;
        config.llm_config = llm_config;
        config.security_config = security_config;
        config.ui_preferences = ui_preferences;

        // Save the configuration
        self.storage.save(&config).await?;

        Ok(())
    }

    async fn verify_llm_configuration(
        &self,
        llm_config: &LLMConfiguration,
    ) -> Result<(), ConfigError> {
        if !llm_config.enabled {
            return Ok(());
        }

        let model_path = llm_config
            .model_path
            .as_ref()
            .ok_or_else(|| ConfigError::LLMError("Model path not specified".to_string()))?;

        if !model_path.exists() {
            return Err(ConfigError::LLMError(format!(
                "Model file not found at: {}",
                model_path.display()
            )));
        }

        Ok(())
    }

    async fn validate_configuration(
        &self,
        config: &SystemConfiguration,
    ) -> Result<(), ConfigError> {
        // Validate version
        if config.version != crate::config::CONFIG_VERSION {
            return Err(ConfigError::ValidationError(format!(
                "Invalid configuration version: {}",
                config.version
            )));
        }

        // Validate LLM configuration if AI analysis is enabled
        if config.security_config.ai_analysis {
            self.verify_llm_configuration(&config.llm_config).await?;
        }

        // Validate security settings
        if !config.security_config.kernel_hardening && config.security_config.ai_analysis {
            return Err(ConfigError::ValidationError(
                "AI analysis requires kernel hardening to be enabled".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn reset_to_defaults(&mut self) -> Result<(), ConfigError> {
        let default_config = SystemConfiguration::default();
        self.storage.backup_config().await?;
        self.update_config(default_config).await
    }
}
