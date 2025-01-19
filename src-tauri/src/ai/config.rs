use crate::ai::{AICapability, AIError, ModelType};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    pub enabled: bool,
    pub models: Vec<ModelConfig>,
    pub training: TrainingConfig,
    pub inference: InferenceConfig,
    pub resource_limits: ResourceLimits,
    pub feature_flags: AIFeatureFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model_type: ModelType,
    pub model_path: PathBuf,
    pub version: String,
    pub capabilities: Vec<AICapability>,
    pub parameters: ModelParameters,
    pub cache_config: Option<CacheConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelParameters {
    pub batch_size: usize,
    pub threads: usize,
    pub max_memory_mb: usize,
    pub timeout_ms: u64,
    pub threshold: f32,
    pub custom_params: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingConfig {
    pub enabled: bool,
    pub data_path: PathBuf,
    pub batch_size: usize,
    pub epochs: usize,
    pub validation_split: f32,
    pub learning_rate: f32,
    pub auto_tune: bool,
    pub save_checkpoints: bool,
    pub checkpoint_interval: Duration,
    pub early_stopping: Option<EarlyStoppingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarlyStoppingConfig {
    pub patience: usize,
    pub min_delta: f32,
    pub monitor_metric: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    pub batch_size: usize,
    pub timeout: Duration,
    pub max_concurrent_requests: usize,
    pub confidence_threshold: f32,
    pub cache_predictions: bool,
    pub cache_ttl: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: usize,
    pub max_threads: usize,
    pub max_batch_size: usize,
    pub max_inference_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_size_mb: usize,
    pub ttl: Duration,
    pub cleanup_interval: Duration,
}

impl AIConfig {
    pub fn new(model_path: PathBuf) -> Result<Self, AIError> {
        Ok(Self {
            enabled: true,
            models: vec![ModelConfig::default()],
            training: TrainingConfig::default(),
            inference: InferenceConfig::default(),
            resource_limits: ResourceLimits::default(),
            feature_flags: AIFeatureFlags::default(),
        })
    }

    pub fn validate(&self) -> Result<(), AIError> {
        // Validate model configurations
        for model_config in &self.models {
            model_config.validate()?;
        }

        // Validate training configuration
        if self.training.enabled {
            self.validate_training_config()?;
        }

        // Validate inference configuration
        self.validate_inference_config()?;

        // Validate resource limits
        self.validate_resource_limits()?;

        Ok(())
    }

    fn validate_training_config(&self) -> Result<(), AIError> {
        let training = &self.training;

        if training.validation_split <= 0.0 || training.validation_split >= 1.0 {
            return Err(AIError::ConfigError(
                "Validation split must be between 0 and 1".into(),
            ));
        }

        if training.learning_rate <= 0.0 {
            return Err(AIError::ConfigError(
                "Learning rate must be positive".into(),
            ));
        }

        if let Some(early_stopping) = &training.early_stopping {
            if early_stopping.patience == 0 {
                return Err(AIError::ConfigError(
                    "Early stopping patience must be greater than 0".into(),
                ));
            }
        }

        Ok(())
    }

    fn validate_inference_config(&self) -> Result<(), AIError> {
        let inference = &self.inference;

        if inference.confidence_threshold < 0.0 || inference.confidence_threshold > 1.0 {
            return Err(AIError::ConfigError(
                "Confidence threshold must be between 0 and 1".into(),
            ));
        }

        if inference.max_concurrent_requests == 0 {
            return Err(AIError::ConfigError(
                "Max concurrent requests must be greater than 0".into(),
            ));
        }

        Ok(())
    }

    fn validate_resource_limits(&self) -> Result<(), AIError> {
        let limits = &self.resource_limits;

        if limits.max_memory_mb == 0 {
            return Err(AIError::ConfigError(
                "Maximum memory must be greater than 0".into(),
            ));
        }

        if limits.max_threads == 0 {
            return Err(AIError::ConfigError(
                "Maximum threads must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}

impl ModelConfig {
    pub fn validate(&self) -> Result<(), AIError> {
        // Validate model path
        if !self.model_path.exists() {
            return Err(AIError::ConfigError(format!(
                "Model path does not exist: {}",
                self.model_path.display()
            )));
        }

        // Validate capabilities
        if self.capabilities.is_empty() {
            return Err(AIError::ConfigError(
                "Model must have at least one capability".into(),
            ));
        }

        // Validate parameters
        self.parameters.validate()?;

        Ok(())
    }
}

impl ModelParameters {
    pub fn validate(&self) -> Result<(), AIError> {
        if self.batch_size == 0 {
            return Err(AIError::ConfigError(
                "Batch size must be greater than 0".into(),
            ));
        }

        if self.threads == 0 {
            return Err(AIError::ConfigError(
                "Thread count must be greater than 0".into(),
            ));
        }

        if self.threshold < 0.0 || self.threshold > 1.0 {
            return Err(AIError::ConfigError(
                "Threshold must be between 0 and 1".into(),
            ));
        }

        Ok(())
    }
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            models: vec![ModelConfig::default()],
            training: TrainingConfig::default(),
            inference: InferenceConfig::default(),
            resource_limits: ResourceLimits::default(),
            feature_flags: AIFeatureFlags::default(),
        }
    }
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model_type: ModelType::default(),
            model_path: PathBuf::from("/etc/cibtac/models/default"),
            version: "1.0.0".to_string(),
            capabilities: vec![AICapability::PackageAnalysis],
            parameters: ModelParameters::default(),
            cache_config: Some(CacheConfig::default()),
        }
    }
}

impl Default for ModelParameters {
    fn default() -> Self {
        Self {
            batch_size: 32,
            threads: 4,
            max_memory_mb: 4096,
            timeout_ms: 5000,
            threshold: 0.5,
            custom_params: HashMap::new(),
        }
    }
}

impl Default for TrainingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            data_path: PathBuf::from("/etc/cibtac/training_data"),
            batch_size: 32,
            epochs: 100,
            validation_split: 0.2,
            learning_rate: 0.001,
            auto_tune: true,
            save_checkpoints: true,
            checkpoint_interval: Duration::from_secs(3600),
            early_stopping: Some(EarlyStoppingConfig::default()),
        }
    }
}

impl Default for EarlyStoppingConfig {
    fn default() -> Self {
        Self {
            patience: 10,
            min_delta: 0.001,
            monitor_metric: "val_loss".to_string(),
        }
    }
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            timeout: Duration::from_secs(30),
            max_concurrent_requests: 10,
            confidence_threshold: 0.8,
            cache_predictions: true,
            cache_ttl: Duration::from_secs(3600),
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 4096,
            max_threads: 4,
            max_batch_size: 64,
            max_inference_time_ms: 5000,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_mb: 1024,
            ttl: Duration::from_secs(3600),
            cleanup_interval: Duration::from_secs(300),
        }
    }
}
