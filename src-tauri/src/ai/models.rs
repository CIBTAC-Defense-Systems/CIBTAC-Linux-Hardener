use crate::ai::{AICapability, AIError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    PackageAnalysis,
    BehaviorAnalysis,
    NetworkAnalysis,
    IntegrityCheck,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysis {
    pub risk_score: f32,
    pub confidence: f32,
    pub detected_patterns: Vec<DetectedPattern>,
    pub recommendations: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub predictions: Vec<SecurityPrediction>,
    pub threat_assessment: Option<ThreatAssessment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_type: PatternType,
    pub confidence: f32,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<String>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    Malicious,
    Suspicious,
    Anomalous,
    Benign,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPrediction {
    pub category: SecurityCategory,
    pub probability: f32,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityCategory {
    MaliciousCode,
    UnauthorizedAccess,
    DataExfiltration,
    ResourceAbuse,
    SystemManipulation,
    IntegrityViolation,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub risk_level: f32,
    pub threat_type: ThreatType,
    pub impact_severity: Severity,
    pub indicators: Vec<ThreatIndicator>,
    pub recommendation: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub name: String,
    pub description: String,
    pub confidence: f32,
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Vulnerability,
    DataBreach,
    UnauthorizedAccess,
    AnomalousBehavior,
    SystemCompromise,
    Custom(String),
}

impl ModelType {
    pub fn get_capabilities(&self) -> Vec<AICapability> {
        match self {
            ModelType::PackageAnalysis => {
                vec![AICapability::PackageAnalysis, AICapability::CodeAnalysis]
            }
            ModelType::BehaviorAnalysis => vec![
                AICapability::BehaviorAnalysis,
                AICapability::AnomalyDetection,
            ],
            ModelType::NetworkAnalysis => vec![
                AICapability::ThreatDetection,
                AICapability::AnomalyDetection,
            ],
            ModelType::IntegrityCheck => {
                vec![AICapability::CodeAnalysis, AICapability::ThreatDetection]
            }
            ModelType::Custom(_) => vec![AICapability::Custom("custom".to_string())],
        }
    }
}

impl AIAnalysis {
    pub fn new() -> Self {
        Self {
            risk_score: 0.0,
            confidence: 0.0,
            detected_patterns: Vec::new(),
            recommendations: Vec::new(),
            metadata: HashMap::new(),
            predictions: Vec::new(),
            threat_assessment: None,
        }
    }

    pub fn merge(&mut self, other: AIAnalysis) {
        // Combine risk scores weighted by confidence
        let total_confidence = self.confidence + other.confidence;
        if total_confidence > 0.0 {
            self.risk_score = (self.risk_score * self.confidence
                + other.risk_score * other.confidence)
                / total_confidence;
            self.confidence = (self.confidence + other.confidence) / 2.0;
        }

        // Merge detected patterns
        self.detected_patterns.extend(other.detected_patterns);

        // Merge recommendations (deduplicate)
        self.recommendations.extend(other.recommendations);
        self.recommendations.sort();
        self.recommendations.dedup();

        // Merge metadata
        self.metadata.extend(other.metadata);

        // Merge predictions
        self.predictions.extend(other.predictions);

        // Update threat assessment if the new one has higher confidence
        if let Some(new_assessment) = other.threat_assessment {
            if let Some(current_assessment) = &self.threat_assessment {
                if new_assessment.confidence > current_assessment.confidence {
                    self.threat_assessment = Some(new_assessment);
                }
            } else {
                self.threat_assessment = Some(new_assessment);
            }
        }
    }

    pub fn is_safe(&self) -> bool {
        self.risk_score < 0.7
            && self.confidence > 0.6
            && !self.has_critical_patterns()
            && !self.has_high_risk_predictions()
    }

    fn has_critical_patterns(&self) -> bool {
        self.detected_patterns
            .iter()
            .any(|p| matches!(p.severity, Severity::Critical))
    }

    fn has_high_risk_predictions(&self) -> bool {
        self.predictions.iter().any(|p| {
            p.confidence > 0.8
                && matches!(
                    p.category,
                    SecurityCategory::MaliciousCode
                        | SecurityCategory::UnauthorizedAccess
                        | SecurityCategory::SystemManipulation
                )
        })
    }

    pub fn get_risk_details(&self) -> String {
        let mut details = Vec::new();

        // Add high-risk patterns
        for pattern in &self.detected_patterns {
            if matches!(pattern.severity, Severity::High | Severity::Critical) {
                details.push(format!(
                    "Detected {}: {}",
                    pattern.pattern_type.to_string(),
                    pattern.description
                ));
            }
        }

        // Add critical predictions
        for prediction in &self.predictions {
            if prediction.confidence > 0.8 {
                details.push(format!(
                    "Predicted {}: {:.1}% confidence",
                    prediction.category.to_string(),
                    prediction.confidence * 100.0
                ));
            }
        }

        // Add threat assessment if available
        if let Some(assessment) = &self.threat_assessment {
            details.push(format!(
                "Threat Assessment: {} (Risk Level: {:.1}%)",
                assessment.threat_type.to_string(),
                assessment.risk_level * 100.0
            ));
        }

        details.join("\n")
    }
}

impl ToString for PatternType {
    fn to_string(&self) -> String {
        match self {
            PatternType::Malicious => "Malicious Pattern".to_string(),
            PatternType::Suspicious => "Suspicious Pattern".to_string(),
            PatternType::Anomalous => "Anomalous Pattern".to_string(),
            PatternType::Benign => "Benign Pattern".to_string(),
        }
    }
}

impl ToString for SecurityCategory {
    fn to_string(&self) -> String {
        match self {
            SecurityCategory::MaliciousCode => "Malicious Code".to_string(),
            SecurityCategory::UnauthorizedAccess => "Unauthorized Access".to_string(),
            SecurityCategory::DataExfiltration => "Data Exfiltration".to_string(),
            SecurityCategory::ResourceAbuse => "Resource Abuse".to_string(),
            SecurityCategory::SystemManipulation => "System Manipulation".to_string(),
            SecurityCategory::IntegrityViolation => "Integrity Violation".to_string(),
            SecurityCategory::Custom(s) => s.clone(),
        }
    }
}

impl ToString for ThreatType {
    fn to_string(&self) -> String {
        match self {
            ThreatType::Malware => "Malware".to_string(),
            ThreatType::Vulnerability => "Vulnerability".to_string(),
            ThreatType::DataBreach => "Data Breach".to_string(),
            ThreatType::UnauthorizedAccess => "Unauthorized Access".to_string(),
            ThreatType::AnomalousBehavior => "Anomalous Behavior".to_string(),
            ThreatType::SystemCompromise => "System Compromise".to_string(),
            ThreatType::Custom(s) => s.clone(),
        }
    }
}

impl Default for ModelType {
    fn default() -> Self {
        ModelType::PackageAnalysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_merge() {
        let mut analysis1 = AIAnalysis::new();
        analysis1.risk_score = 0.5;
        analysis1.confidence = 0.8;

        let mut analysis2 = AIAnalysis::new();
        analysis2.risk_score = 0.8;
        analysis2.confidence = 0.6;

        analysis1.merge(analysis2);

        assert!(analysis1.confidence > 0.0);
        assert!(analysis1.risk_score > 0.5);
    }

    #[test]
    fn test_is_safe() {
        let mut analysis = AIAnalysis::new();
        analysis.risk_score = 0.5;
        analysis.confidence = 0.9;
        assert!(analysis.is_safe());

        analysis.risk_score = 0.8;
        assert!(!analysis.is_safe());
    }
}
