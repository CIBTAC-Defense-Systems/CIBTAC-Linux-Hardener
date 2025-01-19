mod analyzer;
mod events;
mod monitor;
mod patterns;
mod system;

pub use analyzer::{ThreatAnalysis, ThreatAnalyzer};
pub use events::{EventContext, EventType, SystemEvent};
pub use monitor::BehaviorMonitor;
pub use patterns::{BehaviorPattern, PatternMatcher};
pub use system::SystemMonitor;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::{
    ai::AIEngine, config::ConfigurationManager, integrity::IntegrityMonitor,
    package::PackageSecurityMonitor,
};

pub struct BehaviorEngine {
    analyzer: Arc<ThreatAnalyzer>,
    pattern_matcher: Arc<PatternMatcher>,
    system_monitor: Arc<SystemMonitor>,
    behavior_monitor: Arc<BehaviorMonitor>,
    ai_engine: Option<Arc<AIEngine>>,
    config: Arc<RwLock<BehaviorConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorConfig {
    pub system_monitoring: SystemMonitoringConfig,
    pub pattern_matching: PatternMatchingConfig,
    pub analysis_config: AnalysisConfig,
    pub alert_config: AlertConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMonitoringConfig {
    pub monitor_processes: bool,
    pub monitor_network: bool,
    pub monitor_filesystem: bool,
    pub monitor_packages: bool,
    pub process_monitoring_interval: std::time::Duration,
    pub package_monitoring_interval: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatchingConfig {
    pub enabled_patterns: Vec<String>,
    pub custom_patterns: Vec<CustomPattern>,
    pub pattern_timeout: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub use_ai: bool,
    pub analysis_depth: AnalysisDepth,
    pub alert_threshold: f32,
    pub analysis_interval: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisDepth {
    Basic,
    Standard,
    Deep,
    Custom(u32),
}

#[derive(Error, Debug)]
pub enum BehaviorError {
    #[error("Analysis failed: {0}")]
    AnalysisError(String),

    #[error("Pattern matching failed: {0}")]
    PatternError(String),

    #[error("Monitoring error: {0}")]
    MonitoringError(String),

    #[error("System error: {0}")]
    SystemError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl BehaviorEngine {
    pub async fn new(config: &ConfigurationManager) -> Result<Self, BehaviorError> {
        let behavior_config = Arc::new(RwLock::new(BehaviorConfig::default()));

        // Initialize AI engine if enabled
        let ai_engine = if config.is_ai_enabled() {
            Some(Arc::new(AIEngine::new().await?))
        } else {
            None
        };

        Ok(Self {
            analyzer: Arc::new(ThreatAnalyzer::new(ai_engine.clone())),
            pattern_matcher: Arc::new(PatternMatcher::new()),
            system_monitor: Arc::new(SystemMonitor::new(behavior_config.clone())),
            behavior_monitor: Arc::new(BehaviorMonitor::new(behavior_config.clone())),
            ai_engine,
            config: behavior_config,
        })
    }

    pub async fn start_monitoring(&self) -> Result<(), BehaviorError> {
        let config = self.config.read().await;

        // Start system-wide monitoring
        if config.system_monitoring.monitor_processes {
            self.system_monitor.start_process_monitoring().await?;
        }

        // Start package monitoring
        if config.system_monitoring.monitor_packages {
            self.system_monitor.start_package_monitoring().await?;
        }

        // Start pattern matching
        if !config.pattern_matching.enabled_patterns.is_empty() {
            self.pattern_matcher.start_matching().await?;
        }

        // Start behavior monitoring
        self.behavior_monitor.start_monitoring().await?;

        Ok(())
    }

    pub async fn analyze_event(
        &self,
        event: &SystemEvent,
    ) -> Result<ThreatAnalysis, BehaviorError> {
        // Match patterns first
        let patterns = self.pattern_matcher.match_event(event).await?;

        // Analyze with ThreatAnalyzer
        self.analyzer.analyze_patterns(&patterns, event).await
    }

    pub async fn handle_system_event(
        &self,
        event: SystemEvent,
    ) -> Result<EventResponse, BehaviorError> {
        // Match patterns
        let matches = self.pattern_matcher.match_event(&event).await?;

        // Get threat analysis
        let analysis = self.analyze_event(&event).await?;

        // Generate response
        Ok(EventResponse {
            event,
            matches: matches.unwrap_or_default(),
            analysis,
            recommendations: self.generate_recommendations(&analysis).await?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EventResponse {
    pub event: SystemEvent,
    pub matches: Vec<BehaviorPattern>,
    pub analysis: ThreatAnalysis,
    pub recommendations: Vec<SecurityRecommendation>,
}
