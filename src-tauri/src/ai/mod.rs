mod config;
mod engine;
mod models;

pub use config::{AIConfig, ModelConfig, TrainingConfig};
pub use engine::AIEngine;
pub use models::{AIAnalysis, ModelType, SecurityPrediction, ThreatAssessment};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum AIError {
    #[error("Model initialization failed: {0}")]
    ModelInitError(String),

    #[error("Analysis failed: {0}")]
    AnalysisError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Training error: {0}")]
    TrainingError(String),

    #[error("No model available")]
    NoModelAvailable,

    #[error("Data processing error: {0}")]
    DataProcessingError(String),

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Model error: {0}")]
    ModelError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub model_type: ModelType,
    pub version: String,
    pub capabilities: Vec<AICapability>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub performance_metrics: ModelMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1_score: f32,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AICapability {
    PackageAnalysis,
    BehaviorAnalysis,
    ThreatDetection,
    CodeAnalysis,
    AnomalyDetection,
    Custom(String),
}

// Trait for AI-capable components
#[async_trait::async_trait]
pub trait AIAnalyzer {
    async fn analyze(&self, data: &[u8]) -> Result<AIAnalysis, AIError>;
    async fn train(&mut self, data: &[u8]) -> Result<(), AIError>;
    fn supports_capability(&self, capability: &AICapability) -> bool;
}

// Training data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingData {
    pub data_type: DataType,
    pub samples: Vec<TrainingSample>,
    pub metadata: TrainingMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingSample {
    pub input: Vec<f32>,
    pub label: String,
    pub weight: Option<f32>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetadata {
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub validation_metrics: Option<ValidationMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetrics {
    pub accuracy: f32,
    pub loss: f32,
    pub validation_split: f32,
    pub cross_validation_folds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    PackageBehavior,
    SystemCalls,
    NetworkTraffic,
    FileOperations,
    Custom(String),
}

// Model management structures
#[derive(Debug)]
pub struct ModelManager {
    models: HashMap<String, Arc<RwLock<dyn AIAnalyzer>>>,
    config: Arc<RwLock<ModelConfig>>,
}

impl ModelManager {
    pub async fn new(config: ModelConfig) -> Result<Self, AIError> {
        let mut manager = Self {
            models: HashMap::new(),
            config: Arc::new(RwLock::new(config)),
        };
        manager.initialize_models().await?;
        Ok(manager)
    }

    pub async fn get_model(
        &self,
        model_type: ModelType,
    ) -> Result<Arc<RwLock<dyn AIAnalyzer>>, AIError> {
        if let Some(model) = self.models.get(&model_type.to_string()) {
            Ok(model.clone())
        } else {
            Err(AIError::NoModelAvailable)
        }
    }

    async fn initialize_models(&mut self) -> Result<(), AIError> {
        let config = self.config.read().await;

        for model_config in &config.models {
            let model = self.load_model(model_config).await?;
            self.models.insert(
                model_config.model_type.to_string(),
                Arc::new(RwLock::new(model)),
            );
        }

        Ok(())
    }

    async fn load_model(&self, config: &ModelConfig) -> Result<Box<dyn AIAnalyzer>, AIError> {
        // Model loading implementation
        todo!()
    }
}

// Result types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub confidence: f32,
    pub predictions: Vec<SecurityPrediction>,
    pub threat_assessment: Option<ThreatAssessment>,
    pub explanation: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl AnalysisResult {
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.8
    }

    pub fn has_threats(&self) -> bool {
        if let Some(assessment) = &self.threat_assessment {
            assessment.risk_level >= 0.7
        } else {
            false
        }
    }

    pub fn get_risk_level(&self) -> f32 {
        self.threat_assessment
            .as_ref()
            .map(|a| a.risk_level)
            .unwrap_or(0.0)
    }
}

// Feature flags for AI capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIFeatureFlags {
    pub enable_training: bool,
    pub enable_prediction: bool,
    pub enable_anomaly_detection: bool,
    pub enable_active_learning: bool,
    pub experimental_features: bool,
}

impl Default for AIFeatureFlags {
    fn default() -> Self {
        Self {
            enable_training: false,
            enable_prediction: true,
            enable_anomaly_detection: true,
            enable_active_learning: false,
            experimental_features: false,
        }
    }
}
