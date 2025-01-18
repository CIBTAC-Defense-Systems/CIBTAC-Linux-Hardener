use super::{LoggingConfig, LoggingError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub source: String,
    pub category: LogCategory,
    pub message: String,
    pub metadata: LogMetadata,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogCategory {
    Security,
    System,
    Application,
    Audit,
    Performance,
    Network,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMetadata {
    pub process_id: u32,
    pub thread_id: u64,
    pub user: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub stack_trace: Option<Vec<String>>,
}

pub struct Logger {
    config: Arc<RwLock<LoggingConfig>>,
    storage: Arc<RwLock<LogStorage>>,
    event_sender: mpsc::Sender<LogEvent>,
    alert_channel: broadcast::Sender<LogAlert>,
}

#[derive(Debug)]
pub struct LogAlert {
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub message: String,
    pub context: LogAlertContext,
}

#[derive(Debug)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl Logger {
    pub async fn new(config: &LoggingConfig) -> Result<Self, LoggingError> {
        let (event_tx, event_rx) = mpsc::channel(10000);
        let (alert_tx, _) = broadcast::channel(1000);

        let storage = Arc::new(RwLock::new(LogStorage::new(&config.storage).await?));
        let config = Arc::new(RwLock::new(config.clone()));

        let logger = Self {
            config,
            storage,
            event_sender: event_tx,
            alert_channel: alert_tx,
        };

        // Start log processing pipeline
        logger.start_processing_pipeline(event_rx).await?;

        Ok(logger)
    }

    pub async fn initialize(&mut self) -> Result<(), LoggingError> {
        // Initialize storage
        self.storage.write().await.initialize().await?;

        // Set up log rotation if configured
        if let Some(rotation_config) = &self.config.read().await.rotation {
            self.setup_rotation(rotation_config).await?;
        }

        Ok(())
    }

    pub async fn log(&self, event: LogEvent) -> Result<(), LoggingError> {
        // Validate log level against configuration
        if !self.should_log(&event) {
            return Ok(());
        }

        // Send to processing pipeline
        self.event_sender
            .send(event)
            .await
            .map_err(|e| LoggingError::StorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn log_alert(&self, alert: LogAlert) -> Result<(), LoggingError> {
        // Create log event from alert
        let event = LogEvent {
            timestamp: alert.timestamp,
            level: LogLevel::Alert,
            source: "alert_system".to_string(),
            category: LogCategory::Security,
            message: alert.message,
            metadata: self.create_alert_metadata(&alert).await?,
            context: alert.context.into_hash_map(),
        };

        // Log the event
        self.log(event).await?;

        // Broadcast alert
        let _ = self.alert_channel.send(alert);

        Ok(())
    }

    pub async fn query_logs(&self, query: LogQuery) -> Result<Vec<LogEvent>, LoggingError> {
        self.storage.read().await.query(&query).await
    }

    async fn start_processing_pipeline(
        &self,
        mut event_rx: mpsc::Receiver<LogEvent>,
    ) -> Result<(), LoggingError> {
        let storage = Arc::clone(&self.storage);

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                // Process and store the event
                if let Err(e) = storage.write().await.store(&event).await {
                    eprintln!("Error storing log event: {:?}", e);
                }
            }
        });

        Ok(())
    }

    fn should_log(&self, event: &LogEvent) -> bool {
        let config = self.config.try_read().expect("Config lock poisoned");
        event.level >= config.log_level
    }

    async fn create_alert_metadata(&self, alert: &LogAlert) -> Result<LogMetadata, LoggingError> {
        Ok(LogMetadata {
            process_id: std::process::id(),
            thread_id: tokio::runtime::Handle::current().id(),
            user: None,
            session_id: None,
            ip_address: None,
            stack_trace: None,
        })
    }

    async fn setup_rotation(&self, config: &RotationConfig) -> Result<(), LoggingError> {
        // Set up log rotation task
        let storage = Arc::clone(&self.storage);
        let config = config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.check_interval);
            loop {
                interval.tick().await;
                if let Err(e) = storage.write().await.rotate(&config).await {
                    eprintln!("Error rotating logs: {:?}", e);
                }
            }
        });

        Ok(())
    }
}

// Helper functions for metadata collection
impl LogMetadata {
    pub fn new() -> Self {
        Self {
            process_id: std::process::id(),
            thread_id: tokio::runtime::Handle::current().id(),
            user: None,
            session_id: None,
            ip_address: None,
            stack_trace: None,
        }
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_stack_trace(mut self, trace: Vec<String>) -> Self {
        self.stack_trace = Some(trace);
        self
    }
}
