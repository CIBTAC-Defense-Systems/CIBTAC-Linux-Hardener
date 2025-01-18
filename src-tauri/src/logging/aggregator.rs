use super::{LogEvent, LoggingConfig, LoggingError};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct LogAggregator {
    config: AggregationConfig,
    patterns: Vec<AggregationPattern>,
    state: Arc<RwLock<AggregationState>>,
    recent_events: VecDeque<LogEvent>,
}

#[derive(Debug, Clone)]
pub struct AggregationPattern {
    pub name: String,
    pub conditions: Vec<AggregationCondition>,
    pub window: Duration,
    pub min_occurrences: usize,
    pub group_by: Vec<GroupByField>,
}

#[derive(Debug, Clone)]
pub enum AggregationCondition {
    LevelMatch(Vec<super::LogLevel>),
    CategoryMatch(Vec<super::LogCategory>),
    SourceMatch(Vec<String>),
    MessagePattern(String),
    Custom(Arc<dyn Fn(&LogEvent) -> bool + Send + Sync>),
}

#[derive(Debug, Clone)]
pub enum GroupByField {
    Level,
    Category,
    Source,
    User,
    Custom(String),
}

#[derive(Debug)]
struct AggregationState {
    active_groups: HashMap<String, AggregatedGroup>,
    last_cleanup: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedGroup {
    pub pattern_name: String,
    pub first_occurrence: DateTime<Utc>,
    pub last_occurrence: DateTime<Utc>,
    pub count: usize,
    pub events: Vec<LogEvent>,
    pub summary: GroupSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    pub message_template: String,
    pub variables: HashMap<String, Vec<String>>,
    pub metadata: HashMap<String, String>,
}

impl LogAggregator {
    pub fn new(config: AggregationConfig) -> Self {
        Self {
            config,
            patterns: Vec::new(),
            state: Arc::new(RwLock::new(AggregationState::new())),
            recent_events: VecDeque::with_capacity(1000),
        }
    }

    pub async fn initialize(&mut self) -> Result<(), LoggingError> {
        // Load aggregation patterns
        self.load_patterns().await?;

        // Initialize state
        self.state.write().await.initialize();

        Ok(())
    }

    pub async fn process_entry(&self, entry: &LogEvent) -> Result<AggregatedLogs, LoggingError> {
        let mut state = self.state.write().await;
        let mut aggregated = Vec::new();

        // Update recent events queue
        self.update_recent_events(entry);

        // Check against active patterns
        for pattern in &self.patterns {
            if pattern.matches(entry) {
                let group_key = self.generate_group_key(pattern, entry);

                if let Some(group) = state.active_groups.get_mut(&group_key) {
                    // Update existing group
                    group.update(entry);
                } else {
                    // Create new group
                    let group = AggregatedGroup::new(pattern, entry);
                    state.active_groups.insert(group_key, group);
                }
            }
        }

        // Cleanup expired groups
        self.cleanup_expired_groups(&mut state).await?;

        // Generate aggregated view
        Ok(AggregatedLogs {
            groups: state.active_groups.values().cloned().collect(),
        })
    }

    async fn cleanup_expired_groups(
        &self,
        state: &mut AggregationState,
    ) -> Result<(), LoggingError> {
        let now = Utc::now();
        state
            .active_groups
            .retain(|_, group| now - group.last_occurrence < self.config.group_timeout);
        state.last_cleanup = now;
        Ok(())
    }

    fn update_recent_events(&self, entry: &LogEvent) {
        let mut events = self.recent_events.write().expect("Lock poisoned");
        events.push_back(entry.clone());
        while events.len() > self.config.max_recent_events {
            events.pop_front();
        }
    }

    fn generate_group_key(&self, pattern: &AggregationPattern, event: &LogEvent) -> String {
        let mut key_parts = Vec::new();
        key_parts.push(pattern.name.clone());

        for field in &pattern.group_by {
            match field {
                GroupByField::Level => key_parts.push(format!("{:?}", event.level)),
                GroupByField::Category => key_parts.push(format!("{:?}", event.category)),
                GroupByField::Source => key_parts.push(event.source.clone()),
                GroupByField::User => {
                    if let Some(user) = &event.metadata.user {
                        key_parts.push(user.clone());
                    }
                }
                GroupByField::Custom(field) => {
                    if let Some(value) = event.context.get(field) {
                        key_parts.push(value.clone());
                    }
                }
            }
        }

        key_parts.join("::")
    }

    pub async fn get_current_view(&self) -> Result<AggregatedLogs, LoggingError> {
        let state = self.state.read().await;
        Ok(AggregatedLogs {
            groups: state.active_groups.values().cloned().collect(),
        })
    }

    async fn load_patterns(&mut self) -> Result<(), LoggingError> {
        // Load default patterns
        self.patterns.push(AggregationPattern {
            name: "error_burst".to_string(),
            conditions: vec![AggregationCondition::LevelMatch(vec![
                super::LogLevel::Error,
                super::LogLevel::Critical,
            ])],
            window: Duration::minutes(5),
            min_occurrences: 5,
            group_by: vec![GroupByField::Source],
        });

        // Load custom patterns from configuration
        if let Some(custom_patterns) = &self.config.custom_patterns {
            self.patterns.extend(custom_patterns.clone());
        }

        Ok(())
    }
}

impl AggregationPattern {
    pub fn matches(&self, event: &LogEvent) -> bool {
        self.conditions.iter().all(|condition| match condition {
            AggregationCondition::LevelMatch(levels) => levels.contains(&event.level),
            AggregationCondition::CategoryMatch(categories) => categories.contains(&event.category),
            AggregationCondition::SourceMatch(sources) => sources.contains(&event.source),
            AggregationCondition::MessagePattern(pattern) => event.message.contains(pattern),
            AggregationCondition::Custom(func) => func(event),
        })
    }
}

impl AggregatedGroup {
    fn new(pattern: &AggregationPattern, event: &LogEvent) -> Self {
        let now = Utc::now();
        Self {
            pattern_name: pattern.name.clone(),
            first_occurrence: now,
            last_occurrence: now,
            count: 1,
            events: vec![event.clone()],
            summary: GroupSummary::new(event),
        }
    }

    fn update(&mut self, event: &LogEvent) {
        self.last_occurrence = Utc::now();
        self.count += 1;
        self.events.push(event.clone());
        self.summary.update(event);
    }
}

impl GroupSummary {
    fn new(event: &LogEvent) -> Self {
        let mut summary = Self {
            message_template: event.message.clone(),
            variables: HashMap::new(),
            metadata: HashMap::new(),
        };
        summary.update(event);
        summary
    }

    fn update(&mut self, event: &LogEvent) {
        // Update message template and variables
        self.extract_variables(event);

        // Update metadata
        self.metadata
            .insert("last_source".to_string(), event.source.clone());
        if let Some(user) = &event.metadata.user {
            self.metadata.insert("last_user".to_string(), user.clone());
        }
    }

    fn extract_variables(&mut self, event: &LogEvent) {
        // Simple variable extraction from message
        // This could be enhanced with more sophisticated pattern matching
        for (key, value) in &event.context {
            self.variables
                .entry(key.clone())
                .or_insert_with(Vec::new)
                .push(value.clone());
        }
    }
}

impl AggregationState {
    fn new() -> Self {
        Self {
            active_groups: HashMap::new(),
            last_cleanup: Utc::now(),
        }
    }

    fn initialize(&mut self) {
        self.active_groups.clear();
        self.last_cleanup = Utc::now();
    }
}
