use super::core::{AuditEvent, AuditEventType};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;
use std::time;

#[derive(Debug)]
pub struct RetentionPolicy {
    pub time_based: Option<time::Duration>,
    pub count_based: Option<usize>,
    pub importance_based: Option<ImportancePolicy>,
}

#[derive(Debug)]
pub struct ImportancePolicy {
    pub min_importance: u32,
    pub factors: Vec<ImportanceFactor>,
}

#[derive(Debug)]
pub enum ImportanceFactor {
    SecurityLevel(u32),
    EventType(HashSet<AuditEventType>),
    SubjectRole(HashSet<String>),
    Custom(Box<dyn Fn(&AuditEvent) -> u32 + Send + Sync>),
}

impl RetentionPolicy {
    pub fn new() -> Self {
        Self {
            time_based: Some(time::Duration::from_secs(30 * 24 * 60 * 60)), // 30 days default
            count_based: Some(1_000_000), // 1 million events default
            importance_based: None,
        }
    }

    pub fn with_importance(mut self, importance_policy: ImportancePolicy) -> Self {
        self.importance_based = Some(importance_policy);
        self
    }

    pub fn should_retain(&self, event: &AuditEvent, current_time: DateTime<Utc>) -> bool {
        // Check time-based retention
        if let Some(duration) = self.time_based {
            if current_time.timestamp_millis() as u64 - event.timestamp.timestamp_millis() as u64
                > duration.as_millis() as u64
            {
                return false;
            }
        }

        // Check importance-based retention
        if let Some(ref importance_policy) = self.importance_based {
            if self.calculate_importance(event) < importance_policy.min_importance {
                return false;
            }
        }

        true
    }

    fn calculate_importance(&self, event: &AuditEvent) -> u32 {
        if let Some(ref importance_policy) = self.importance_based {
            let mut importance = 0;

            for factor in &importance_policy.factors {
                importance += match factor {
                    ImportanceFactor::SecurityLevel(weight) => {
                        weight * event.subject.level.as_u32()
                    }
                    ImportanceFactor::EventType(types) => {
                        if types.contains(&event.event_type) {
                            10
                        } else {
                            0
                        }
                    }
                    ImportanceFactor::SubjectRole(roles) => {
                        if roles.contains(&event.subject.role) {
                            15
                        } else {
                            0
                        }
                    }
                    ImportanceFactor::Custom(f) => f(event),
                };
            }

            importance
        } else {
            0
        }
    }
}

#[derive(Debug)]
pub struct RetentionManager {
    policy: RetentionPolicy,
    stats: RetentionStats,
}

#[derive(Debug)]
pub struct RetentionStats {
    total_events: usize,
    retained_events: usize,
    discarded_events: usize,
    last_cleanup: DateTime<Utc>,
}

impl RetentionManager {
    pub fn new(policy: RetentionPolicy) -> Self {
        Self {
            policy,
            stats: RetentionStats {
                total_events: 0,
                retained_events: 0,
                discarded_events: 0,
                last_cleanup: Utc::now(),
            },
        }
    }

    pub fn should_retain(&mut self, event: &AuditEvent) -> bool {
        self.stats.total_events += 1;
        let should_keep = self.policy.should_retain(event, Utc::now());

        if should_keep {
            self.stats.retained_events += 1;
        } else {
            self.stats.discarded_events += 1;
        }

        should_keep
    }

    pub fn cleanup_old_events<F>(&mut self, mut cleanup_fn: F)
    where
        F: FnMut(&AuditEvent) -> bool,
    {
        self.stats.last_cleanup = Utc::now();
        // Cleanup implementation would be provided by the caller
    }
}

// Helper types for retention policies
#[derive(Debug)]
pub struct RetentionRule {
    pub event_types: HashSet<AuditEventType>,
    pub duration: time::Duration,
    pub importance_threshold: Option<u32>,
}

#[derive(Debug)]
pub struct RetentionMetrics {
    pub event_count: usize,
    pub storage_size: u64,
    pub oldest_event: DateTime<Utc>,
    pub newest_event: DateTime<Utc>,
}
