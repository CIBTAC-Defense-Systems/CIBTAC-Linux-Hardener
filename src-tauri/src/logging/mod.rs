mod aggregator;
mod analyzer;
mod logger;
mod rotation;
mod storage;

pub use aggregator::LogAggregator;
pub use analyzer::LogAnalyzer;
pub use logger::{LogCategory, LogEvent, LogLevel, Logger};
pub use rotation::LogRotator;
pub use storage::LogStorage;

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("Aggregation error: {0}")]
    AggregationError(String),

    #[error("Rotation error: {0}")]
    RotationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}

pub struct LoggingSystem {
    logger: Arc<RwLock<Logger>>,
    analyzer: Arc<RwLock<LogAnalyzer>>,
    aggregator: Arc<RwLock<LogAggregator>>,
    rotator: Arc<RwLock<LogRotator>>,
    config: Arc<RwLock<LoggingConfig>>,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub log_level: LogLevel,
    pub rotation: RotationConfig,
    pub analysis: AnalysisConfig,
    pub aggregation: AggregationConfig,
    pub storage: StorageConfig,
}

impl LoggingSystem {
    pub async fn new(config: LoggingConfig) -> Result<Self, LoggingError> {
        let logger = Arc::new(RwLock::new(Logger::new(&config).await?));
        let analyzer = Arc::new(RwLock::new(LogAnalyzer::new(&config).await?));
        let aggregator = Arc::new(RwLock::new(LogAggregator::new(&config).await?));
        let rotator = Arc::new(RwLock::new(LogRotator::new(&config).await?));
        let config = Arc::new(RwLock::new(config));

        Ok(Self {
            logger,
            analyzer,
            aggregator,
            rotator,
            config,
        })
    }

    pub async fn initialize(&self) -> Result<(), LoggingError> {
        // Initialize all components
        self.logger.write().await.initialize().await?;
        self.analyzer.write().await.initialize().await?;
        self.aggregator.write().await.initialize().await?;
        self.rotator.write().await.initialize().await?;

        Ok(())
    }

    pub async fn log(&self, event: LogEvent) -> Result<(), LoggingError> {
        // Log the event
        self.logger.write().await.log(event.clone()).await?;

        // Process through aggregator
        self.aggregator.write().await.process_entry(&event).await?;

        // Analyze event
        let analysis = self.analyzer.read().await.analyze_event(&event).await?;

        // Handle analysis results
        if analysis.requires_action() {
            self.handle_analysis_results(analysis).await?;
        }

        Ok(())
    }

    pub async fn get_logs(&self, query: LogQuery) -> Result<Vec<LogEvent>, LoggingError> {
        self.logger.read().await.query_logs(query).await
    }

    pub async fn get_aggregated_view(&self) -> Result<AggregatedLogs, LoggingError> {
        self.aggregator.read().await.get_current_view().await
    }

    async fn handle_analysis_results(&self, analysis: Analysis) -> Result<(), LoggingError> {
        // Handle any actions required by the analysis
        if analysis.should_rotate_logs() {
            self.rotator.write().await.rotate_logs().await?;
        }

        if analysis.has_alerts() {
            self.process_alerts(analysis.alerts()).await?;
        }

        Ok(())
    }

    async fn process_alerts(&self, alerts: Vec<Alert>) -> Result<(), LoggingError> {
        for alert in alerts {
            // Process each alert based on its severity and type
            match alert.severity() {
                AlertSeverity::High | AlertSeverity::Critical => {
                    // Trigger immediate notification
                    self.notify_alert(&alert).await?;
                }
                _ => {
                    // Log alert for regular monitoring
                    self.logger.write().await.log_alert(alert).await?;
                }
            }
        }
        Ok(())
    }

    async fn notify_alert(&self, alert: &Alert) -> Result<(), LoggingError> {
        // Implement alert notification logic
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LogQuery {
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub level: Option<LogLevel>,
    pub category: Option<LogCategory>,
    pub source: Option<String>,
    pub limit: Option<usize>,
}
