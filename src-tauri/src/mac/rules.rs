use super::{AccessResult, AccessType, MACError, SecurityContext};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub id: String,
    pub subject_pattern: SubjectPattern,
    pub object_pattern: ObjectPattern,
    pub access_types: HashSet<AccessType>,
    pub conditions: Vec<AccessCondition>,
    pub action: AccessAction,
    pub priority: u32,
    pub metadata: RuleMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectPattern {
    pub user_patterns: Vec<String>,
    pub role_patterns: Vec<String>,
    pub level_requirement: Option<LevelRequirement>,
    pub required_categories: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPattern {
    pub name_patterns: Vec<String>,
    pub type_patterns: Vec<String>,
    pub level_constraint: Option<LevelConstraint>,
    pub required_categories: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessCondition {
    TimeRange(TimeRange),
    Location(LocationConstraint),
    SystemLoad(LoadConstraint),
    ResourceUsage(ResourceConstraint),
    CustomCondition {
        name: String,
        parameters: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days: HashSet<u8>, // 0 = Sunday, 1 = Monday, etc.
    pub timezone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationConstraint {
    pub allowed_locations: HashSet<String>,
    pub denied_locations: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadConstraint {
    pub max_cpu_load: f32,
    pub max_memory_usage: f32,
    pub check_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConstraint {
    pub resource_type: ResourceType,
    pub max_usage: u64,
    pub window_size: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    FileDescriptors,
    NetworkConnections,
    ProcessCount,
    MemoryAllocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub created_at: std::time::SystemTime,
    pub created_by: String,
    pub last_modified: std::time::SystemTime,
    pub description: Option<String>,
    pub enabled: bool,
    pub expiration: Option<std::time::SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelRequirement {
    pub minimum_level: u32,
    pub required_clearance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelConstraint {
    pub maximum_level: u32,
    pub restricted_categories: HashSet<String>,
}

impl AccessRule {
    pub fn new(
        id: String,
        subject_pattern: SubjectPattern,
        object_pattern: ObjectPattern,
        access_types: HashSet<AccessType>,
        action: AccessAction,
    ) -> Self {
        Self {
            id,
            subject_pattern,
            object_pattern,
            access_types,
            conditions: Vec::new(),
            action,
            priority: 0,
            metadata: RuleMetadata::new(),
        }
    }

    pub fn matches(
        &self,
        subject: &SecurityContext,
        object: &SecurityContext,
        access: &AccessType,
    ) -> bool {
        // Check if rule is enabled
        if !self.metadata.enabled || self.is_expired() {
            return false;
        }

        // Check if access type is covered by this rule
        if !self.access_types.contains(access) {
            return false;
        }

        // Check subject pattern
        if !self.subject_pattern.matches(subject) {
            return false;
        }

        // Check object pattern
        if !self.object_pattern.matches(object) {
            return false;
        }

        // Check conditions
        self.check_conditions(subject, object)
    }

    fn check_conditions(&self, subject: &SecurityContext, object: &SecurityContext) -> bool {
        for condition in &self.conditions {
            if !condition.evaluate(subject, object) {
                return false;
            }
        }
        true
    }

    pub fn get_action(&self) -> AccessResult {
        match &self.action {
            AccessAction::Allow => AccessResult::Allow,
            AccessAction::Deny(reason) => AccessResult::Deny(reason.clone()),
            AccessAction::Audit => AccessResult::Audit,
        }
    }

    fn is_expired(&self) -> bool {
        if let Some(expiration) = self.metadata.expiration {
            expiration < std::time::SystemTime::now()
        } else {
            false
        }
    }

    pub fn conflicts_with(&self, other: &AccessRule) -> bool {
        // Check for intersection in subjects, objects, and access types
        let subjects_overlap = self.subject_pattern.overlaps(&other.subject_pattern);
        let objects_overlap = self.object_pattern.overlaps(&other.object_pattern);
        let access_types_overlap = !self.access_types.is_disjoint(&other.access_types);

        // Rules conflict if they overlap and have different actions
        subjects_overlap && objects_overlap && access_types_overlap && self.action != other.action
    }
}

impl SubjectPattern {
    pub fn matches(&self, subject: &SecurityContext) -> bool {
        // Check user patterns
        let user_match = self.user_patterns.is_empty()
            || self
                .user_patterns
                .iter()
                .any(|pattern| pattern_matches(pattern, &subject.user));

        // Check role patterns
        let role_match = self.role_patterns.is_empty()
            || self
                .role_patterns
                .iter()
                .any(|pattern| pattern_matches(pattern, &subject.role));

        // Check level requirement
        let level_match = self
            .level_requirement
            .as_ref()
            .map_or(true, |req| req.matches(&subject.level));

        // Check required categories
        let categories_match = self.required_categories.is_subset(&subject.categories);

        user_match && role_match && level_match && categories_match
    }

    pub fn overlaps(&self, other: &SubjectPattern) -> bool {
        // Check for overlap in patterns
        let users_overlap = patterns_overlap(&self.user_patterns, &other.user_patterns);
        let roles_overlap = patterns_overlap(&self.role_patterns, &other.role_patterns);

        // If any patterns overlap, the subject patterns overlap
        users_overlap || roles_overlap
    }
}

impl ObjectPattern {
    pub fn matches(&self, object: &SecurityContext) -> bool {
        // Similar to SubjectPattern matching
        let name_match = self.name_patterns.is_empty()
            || self
                .name_patterns
                .iter()
                .any(|pattern| pattern_matches(pattern, &object.user));

        let type_match = self.type_patterns.is_empty()
            || self
                .type_patterns
                .iter()
                .any(|pattern| pattern_matches(pattern, &object.role));

        let level_match = self
            .level_constraint
            .as_ref()
            .map_or(true, |constraint| constraint.matches(&object.level));

        let categories_match = self.required_categories.is_subset(&object.categories);

        name_match && type_match && level_match && categories_match
    }

    pub fn overlaps(&self, other: &ObjectPattern) -> bool {
        patterns_overlap(&self.name_patterns, &other.name_patterns)
            || patterns_overlap(&self.type_patterns, &other.type_patterns)
    }
}

impl AccessCondition {
    pub fn evaluate(&self, subject: &SecurityContext, object: &SecurityContext) -> bool {
        match self {
            AccessCondition::TimeRange(range) => range.evaluate(),
            AccessCondition::Location(loc) => loc.evaluate(subject),
            AccessCondition::SystemLoad(load) => load.evaluate(),
            AccessCondition::ResourceUsage(resource) => resource.evaluate(subject),
            AccessCondition::CustomCondition { name, parameters } => {
                // Custom condition evaluation would be implemented here
                true
            }
        }
    }
}

impl TimeRange {
    pub fn evaluate(&self) -> bool {
        use chrono::{Datelike, Local, Timelike};

        let now = Local::now();
        let hour = now.hour() as u8;
        let day = now.weekday().num_days_from_sunday() as u8;

        self.days.contains(&day) && hour >= self.start_hour && hour < self.end_hour
    }
}

impl LocationConstraint {
    pub fn evaluate(&self, subject: &SecurityContext) -> bool {
        // This would integrate with a location service
        // For now, return true if no denied locations are specified
        self.denied_locations.is_empty()
    }
}

impl LoadConstraint {
    pub fn evaluate(&self) -> bool {
        // This would check system metrics
        // For now, return true
        true
    }
}

impl ResourceConstraint {
    pub fn evaluate(&self, subject: &SecurityContext) -> bool {
        // This would check resource usage
        // For now, return true
        true
    }
}

impl RuleMetadata {
    fn new() -> Self {
        let now = std::time::SystemTime::now();
        Self {
            created_at: now,
            created_by: String::from("system"),
            last_modified: now,
            description: None,
            enabled: true,
            expiration: None,
        }
    }
}

// Helper functions
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        let regex_pattern = pattern.replace('*', ".*");
        regex::Regex::new(&regex_pattern)
            .map(|re| re.is_match(value))
            .unwrap_or(false)
    } else {
        pattern == value
    }
}

fn patterns_overlap(patterns1: &[String], patterns2: &[String]) -> bool {
    // If either list is empty (meaning it matches everything), they overlap
    if patterns1.is_empty() || patterns2.is_empty() {
        return true;
    }

    // Check if any patterns intersect
    for p1 in patterns1 {
        for p2 in patterns2 {
            if could_patterns_overlap(p1, p2) {
                return true;
            }
        }
    }
    false
}

fn could_patterns_overlap(p1: &str, p2: &str) -> bool {
    if p1 == "*" || p2 == "*" {
        return true;
    }

    if !p1.contains('*') && !p2.contains('*') {
        return p1 == p2;
    }

    // For more complex pattern matching, we'd need a more sophisticated analysis
    // For now, conservatively assume they might overlap
    true
}
