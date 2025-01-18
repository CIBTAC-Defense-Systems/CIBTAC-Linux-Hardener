use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLabel {
    pub sensitivity: SensitivityLevel,
    pub categories: HashSet<String>,
    pub compartments: HashSet<String>,
    pub owner: Option<String>,
    pub caveats: Vec<SecurityCaveat>,
    pub metadata: LabelMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityLevel {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
    Custom(String, u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCaveat {
    pub name: String,
    pub conditions: Vec<CaveatCondition>,
    pub expiration: Option<SystemTime>,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaveatCondition {
    TimeRestriction {
        start_time: SystemTime,
        end_time: SystemTime,
    },
    LocationBased(Vec<String>),
    RoleBased(Vec<String>),
    Custom(String, HashMap<String, String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelMetadata {
    pub created_at: SystemTime,
    pub modified_at: SystemTime,
    pub created_by: String,
    pub version: u32,
    pub description: Option<String>,
}

impl SecurityLabel {
    pub fn new(
        sensitivity: SensitivityLevel,
        categories: HashSet<String>,
        owner: Option<String>,
    ) -> Self {
        Self {
            sensitivity,
            categories,
            compartments: HashSet::new(),
            owner,
            caveats: Vec::new(),
            metadata: LabelMetadata::new(),
        }
    }

    pub fn dominates(&self, other: &SecurityLabel) -> bool {
        // Check sensitivity level
        if !self.sensitivity_dominates(&other.sensitivity) {
            return false;
        }

        // Check categories (must have all categories of other label)
        if !self.categories.is_superset(&other.categories) {
            return false;
        }

        // Check compartments
        if !self.compartments.is_superset(&other.compartments) {
            return false;
        }

        // Check caveats
        self.verify_caveats(&other.caveats)
    }

    fn sensitivity_dominates(&self, other: &SensitivityLevel) -> bool {
        use SensitivityLevel::*;
        match (&self.sensitivity, other) {
            (TopSecret, _) => true,
            (Secret, Confidential | Unclassified) => true,
            (Confidential, Unclassified) => true,
            (Custom(_, level1), Custom(_, level2)) => level1 >= level2,
            (Custom(_, level), standard) => *level >= standard.to_numeric_level(),
            (standard1, standard2) => standard1 == standard2,
        }
    }

    fn verify_caveats(&self, other_caveats: &[SecurityCaveat]) -> bool {
        for caveat in other_caveats {
            if !self.satisfies_caveat(caveat) {
                return false;
            }
        }
        true
    }

    fn satisfies_caveat(&self, caveat: &SecurityCaveat) -> bool {
        // Check caveat expiration
        if let Some(expiration) = caveat.expiration {
            if SystemTime::now() > expiration {
                return false;
            }
        }

        // Check each condition
        for condition in &caveat.conditions {
            if !self.satisfies_condition(condition) {
                return false;
            }
        }

        true
    }

    fn satisfies_condition(&self, condition: &CaveatCondition) -> bool {
        match condition {
            CaveatCondition::TimeRestriction {
                start_time,
                end_time,
            } => {
                let now = SystemTime::now();
                now >= *start_time && now <= *end_time
            }
            CaveatCondition::LocationBased(locations) => {
                // This would typically integrate with a location service
                // For now, we'll assume all location restrictions are satisfied
                true
            }
            CaveatCondition::RoleBased(roles) => {
                // Check if any of the required roles are in our categories
                roles.iter().any(|role| self.categories.contains(role))
            }
            CaveatCondition::Custom(name, params) => {
                // Custom condition evaluation would be implemented here
                // For now, we'll return true
                true
            }
        }
    }

    pub fn add_caveat(&mut self, caveat: SecurityCaveat) {
        self.caveats.push(caveat);
        self.metadata.modified_at = SystemTime::now();
        self.metadata.version += 1;
    }

    pub fn add_compartment(&mut self, compartment: String) {
        self.compartments.insert(compartment);
        self.metadata.modified_at = SystemTime::now();
        self.metadata.version += 1;
    }

    pub fn validate(&self) -> bool {
        // Check for expired caveats
        let now = SystemTime::now();
        for caveat in &self.caveats {
            if let Some(expiration) = caveat.expiration {
                if now > expiration {
                    return false;
                }
            }
        }

        // Additional validation logic could be added here
        true
    }
}

impl SensitivityLevel {
    fn to_numeric_level(&self) -> u32 {
        match self {
            SensitivityLevel::Unclassified => 0,
            SensitivityLevel::Confidential => 1,
            SensitivityLevel::Secret => 2,
            SensitivityLevel::TopSecret => 3,
            SensitivityLevel::Custom(_, level) => *level,
        }
    }
}

impl LabelMetadata {
    fn new() -> Self {
        let now = SystemTime::now();
        Self {
            created_at: now,
            modified_at: now,
            created_by: String::from("system"),
            version: 1,
            description: None,
        }
    }
}
