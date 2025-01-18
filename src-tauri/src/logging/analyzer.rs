use super::{LogCategory, LogEvent, LogLevel, LoggingConfig, LoggingError};
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct LogAnalyzer {
    config: Arc<RwLock<AnalysisConfig>>,
    patterns: Vec<AnalysisPattern>,
    state: Arc<RwLock<AnalyzerState>>,
    ml_engine: Option<Arc<MLEngine>>,
}

#[derive(Debug)]
struct AnalyzerState {
    event_history: VecDeque<LogEvent>,
    pattern_matches: HashMap<String, Vec<PatternMatch>>,
    anomaly_scores: HashMap<String, f64>,
    last_analysis: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub patterns_matched: Vec<PatternMatch>,
    pub anomalies_detected: Vec<Anomaly>,
    pub suggestions: Vec<Suggestion>,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub events: Vec<LogEvent>,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub description: String,
    pub severity: Severity,
    pub confidence: f64,
    pub affected_components: Vec<String>,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Suggestion {
    pub action: SuggestedAction,
    pub reason: String,
    pub priority: Priority,
}

#[derive(Debug, Clone)]
pub enum SuggestedAction {
    IncreaseLogLevel(String),
    EnableDebugging(String),
    InvestigateComponent(String),
    AdjustThreshold { parameter: String, value: f64 },
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Medium,
    High,
    Urgent,
}

impl LogAnalyzer {
    pub async fn new(config: &LoggingConfig) -> Result<Self, LoggingError> {
        let ml_engine = if config.analysis.enable_ml {
            Some(Arc::new(MLEngine::new().await?))
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(RwLock::new(AnalysisConfig::from(config.analysis.clone()))),
            patterns: Vec::new(),
            state: Arc::new(RwLock::new(AnalyzerState::new())),
            ml_engine,
        })
    }

    pub async fn initialize(&mut self) -> Result<(), LoggingError> {
        // Load analysis patterns
        self.load_patterns().await?;

        // Initialize ML engine if enabled
        if let Some(ml_engine) = &self.ml_engine {
            ml_engine.initialize().await?;
        }

        Ok(())
    }

    pub async fn analyze(&self, event: &LogEvent) -> Result<Analysis, LoggingError> {
        let mut state = self.state.write().await;
        let mut analysis = Analysis::new();

        // Update event history
        state.add_event(event);

        // Pattern matching
        let pattern_matches = self.check_patterns(event, &state).await?;
        analysis.patterns_matched = pattern_matches;

        // Anomaly detection
        if let Some(ml_engine) = &self.ml_engine {
            let anomalies = ml_engine
                .detect_anomalies(event, &state.event_history)
                .await?;
            analysis.anomalies_detected = anomalies;
        }

        // Generate suggestions
        analysis.suggestions = self.generate_suggestions(&state).await?;

        // Calculate risk score
        analysis.risk_score = self.calculate_risk_score(&analysis).await?;

        Ok(analysis)
    }

    async fn check_patterns(
        &self,
        event: &LogEvent,
        state: &AnalyzerState,
    ) -> Result<Vec<PatternMatch>, LoggingError> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            if pattern.matches(event, &state.event_history) {
                matches.push(PatternMatch {
                    pattern_name: pattern.name.clone(),
                    events: vec![event.clone()],
                    severity: pattern.severity.clone(),
                    timestamp: Utc::now(),
                    context: pattern.extract_context(event),
                });
            }
        }

        Ok(matches)
    }

    async fn generate_suggestions(
        &self,
        state: &AnalyzerState,
    ) -> Result<Vec<Suggestion>, LoggingError> {
        let mut suggestions = Vec::new();

        // Check error rates
        if self.check_error_rate(state) {
            suggestions.push(Suggestion {
                action: SuggestedAction::IncreaseLogLevel("application".to_string()),
                reason: "High error rate detected".to_string(),
                priority: Priority::High,
            });
        }

        // Check component health
        for (component, score) in &state.anomaly_scores {
            if *score > self.config.read().await.anomaly_threshold {
                suggestions.push(Suggestion {
                    action: SuggestedAction::InvestigateComponent(component.clone()),
                    reason: format!("Anomalous behavior detected in component {}", component),
                    priority: Priority::High,
                });
            }
        }

        // Check log patterns
        for (pattern_name, matches) in &state.pattern_matches {
            if matches.len() > self.config.read().await.pattern_threshold {
                suggestions.push(Suggestion {
                    action: SuggestedAction::EnableDebugging(pattern_name.clone()),
                    reason: format!("Frequent occurrences of pattern {}", pattern_name),
                    priority: Priority::Medium,
                });
            }
        }

        Ok(suggestions)
    }

    async fn calculate_risk_score(&self, analysis: &Analysis) -> Result<f64, LoggingError> {
        let mut score = 0.0;
        let config = self.config.read().await;

        // Factor in pattern matches
        for pattern in &analysis.patterns_matched {
            score += match pattern.severity {
                Severity::Critical => 1.0,
                Severity::High => 0.8,
                Severity::Medium => 0.5,
                Severity::Low => 0.2,
            };
        }

        // Factor in anomalies
        for anomaly in &analysis.anomalies_detected {
            score += anomaly.confidence
                * match anomaly.severity {
                    Severity::Critical => 1.0,
                    Severity::High => 0.8,
                    Severity::Medium => 0.5,
                    Severity::Low => 0.2,
                };
        }

        // Normalize score
        Ok((score / config.max_risk_score).min(1.0))
    }

    fn check_error_rate(&self, state: &AnalyzerState) -> bool {
        let error_count = state
            .event_history
            .iter()
            .filter(|e| matches!(e.level, LogLevel::Error | LogLevel::Critical))
            .count();

        let total_events = state.event_history.len();
        if total_events == 0 {
            return false;
        }

        (error_count as f64 / total_events as f64) > 0.1 // 10% threshold
    }

    async fn load_patterns(&mut self) -> Result<(), LoggingError> {
        // Add default patterns
        self.patterns.push(AnalysisPattern {
            name: "error_spike".to_string(),
            conditions: vec![
                PatternCondition::LevelMatch(vec![LogLevel::Error, LogLevel::Critical]),
                PatternCondition::FrequencyThreshold(5, Duration::minutes(1)),
            ],
            severity: Severity::High,
            context_extractors: vec![Box::new(|event| {
                let mut context = HashMap::new();
                context.insert("source".to_string(), event.source.clone());
                if let Some(user) = &event.metadata.user {
                    context.insert("user".to_string(), user.clone());
                }
                context
            })],
        });

        // Load custom patterns from configuration
        if let Some(custom_patterns) = &self.config.read().await.custom_patterns {
            self.patterns.extend(custom_patterns.clone());
        }

        Ok(())
    }
}

impl AnalyzerState {
    fn new() -> Self {
        Self {
            event_history: VecDeque::with_capacity(10000), // Keep last 10000 events
            pattern_matches: HashMap::new(),
            anomaly_scores: HashMap::new(),
            last_analysis: Utc::now(),
        }
    }

    fn add_event(&mut self, event: &LogEvent) {
        self.event_history.push_back(event.clone());
        while self.event_history.len() > 10000 {
            self.event_history.pop_front();
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisPattern {
    pub name: String,
    pub conditions: Vec<PatternCondition>,
    pub severity: Severity,
    pub context_extractors: Vec<Box<dyn Fn(&LogEvent) -> HashMap<String, String> + Send + Sync>>,
}

#[derive(Debug, Clone)]
pub enum PatternCondition {
    LevelMatch(Vec<LogLevel>),
    CategoryMatch(Vec<LogCategory>),
    SourceMatch(Vec<String>),
    MessagePattern(String),
    FrequencyThreshold(usize, Duration),
    Custom(Arc<dyn Fn(&LogEvent, &[LogEvent]) -> bool + Send + Sync>),
}

impl AnalysisPattern {
    fn matches(&self, event: &LogEvent, history: &VecDeque<LogEvent>) -> bool {
        self.conditions.iter().all(|condition| match condition {
            PatternCondition::LevelMatch(levels) => levels.contains(&event.level),
            PatternCondition::CategoryMatch(categories) => categories.contains(&event.category),
            PatternCondition::SourceMatch(sources) => sources.contains(&event.source),
            PatternCondition::MessagePattern(pattern) => event.message.contains(pattern),
            PatternCondition::FrequencyThreshold(count, duration) => {
                let threshold_time = Utc::now() - *duration;
                let matching_events = history
                    .iter()
                    .filter(|e| e.timestamp >= threshold_time)
                    .count();
                matching_events >= *count
            }
            PatternCondition::Custom(func) => func(event, history.make_contiguous()),
        })
    }

    fn extract_context(&self, event: &LogEvent) -> HashMap<String, String> {
        let mut context = HashMap::new();
        for extractor in &self.context_extractors {
            context.extend(extractor(event));
        }
        context
    }
}

impl Analysis {
    fn new() -> Self {
        Self {
            patterns_matched: Vec::new(),
            anomalies_detected: Vec::new(),
            suggestions: Vec::new(),
            risk_score: 0.0,
        }
    }

    pub fn requires_action(&self) -> bool {
        !self.patterns_matched.is_empty() || !self.anomalies_detected.is_empty()
    }

    pub fn has_critical_findings(&self) -> bool {
        self.patterns_matched
            .iter()
            .any(|p| p.severity == Severity::Critical)
            || self
                .anomalies_detected
                .iter()
                .any(|a| a.severity == Severity::Critical)
    }
}
