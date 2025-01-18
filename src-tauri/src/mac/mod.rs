mod audit;
mod enforcement;
mod labels;
mod policy;
mod rules;

pub use audit::{AccessAuditor, AuditEvent};
pub use enforcement::MACEnforcer;
pub use labels::SecurityLabel;
pub use policy::MACPolicy;
pub use rules::AccessRule;

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

pub struct MACSystem {
    enforcer: Arc<RwLock<MACEnforcer>>,
    policy: Arc<RwLock<MACPolicy>>,
    auditor: Arc<RwLock<AccessAuditor>>,
}

#[derive(Error, Debug)]
pub enum MACError {
    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Policy error: {0}")]
    PolicyError(String),

    #[error("Label error: {0}")]
    LabelError(String),

    #[error("Enforcement error: {0}")]
    EnforcementError(String),

    #[error("Audit error: {0}")]
    AuditError(String),
}

impl MACSystem {
    pub async fn new() -> Result<Self, MACError> {
        let policy = Arc::new(RwLock::new(MACPolicy::new()));
        let enforcer = Arc::new(RwLock::new(MACEnforcer::new(Arc::clone(&policy)).await?));
        let auditor = Arc::new(RwLock::new(AccessAuditor::new().await?));

        Ok(Self {
            enforcer,
            policy,
            auditor,
        })
    }

    pub async fn start_enforcement(&self) -> Result<(), MACError> {
        // Initialize and start enforcer
        let mut enforcer = self.enforcer.write().await;
        enforcer.initialize().await?;

        // Initialize auditing
        let mut auditor = self.auditor.write().await;
        auditor.initialize().await?;

        // Load initial policy
        self.load_initial_policy().await?;

        Ok(())
    }

    pub async fn enforce_access(
        &self,
        subject: &SecurityContext,
        object: &SecurityContext,
        access_type: AccessType,
    ) -> Result<(), MACError> {
        // Check policy
        let policy = self.policy.read().await;
        let decision = policy.check_access(subject, object, &access_type);

        // Audit the access attempt
        let mut auditor = self.auditor.write().await;
        auditor
            .log_access_attempt(subject, object, &access_type)
            .await?;

        match decision {
            AccessResult::Allow => {
                // Enforce the access
                let enforcer = self.enforcer.read().await;
                enforcer
                    .enforce_access(subject, object, &access_type)
                    .await?;

                // Log successful access
                auditor
                    .log_access_success(subject, object, &access_type)
                    .await?;
                Ok(())
            }
            AccessResult::Deny(reason) => {
                // Log denied access
                auditor
                    .log_access_denial(subject, object, &access_type, &reason)
                    .await?;
                Err(MACError::AccessDenied(reason))
            }
            AccessResult::Audit => {
                // Handle audit requirement
                self.handle_audit_requirement(subject, object, &access_type)
                    .await
            }
        }
    }

    async fn handle_audit_requirement(
        &self,
        subject: &SecurityContext,
        object: &SecurityContext,
        access_type: &AccessType,
    ) -> Result<(), MACError> {
        let mut auditor = self.auditor.write().await;

        // Perform extended auditing
        if auditor
            .should_allow_access(subject, object, access_type)
            .await?
        {
            // Allow access with enhanced monitoring
            let enforcer = self.enforcer.read().await;
            enforcer
                .enforce_access_with_monitoring(subject, object, access_type)
                .await?;
            auditor
                .log_audited_access(subject, object, access_type)
                .await?;
            Ok(())
        } else {
            // Deny due to audit requirements
            Err(MACError::AccessDenied("Audit requirements not met".into()))
        }
    }

    pub async fn update_policy(&self, new_policy: MACPolicy) -> Result<(), MACError> {
        // Verify the new policy
        new_policy.validate()?;

        // Log policy update
        let mut auditor = self.auditor.write().await;
        auditor.log_policy_update(&new_policy).await?;

        // Update the policy
        let mut policy = self.policy.write().await;
        *policy = new_policy;

        Ok(())
    }

    async fn load_initial_policy(&self) -> Result<(), MACError> {
        // Load policy from secure storage
        let policy_data = std::fs::read("/etc/cibtac/security/mac_policy.db")
            .map_err(|e| MACError::PolicyError(format!("Failed to load policy: {}", e)))?;

        let policy: MACPolicy = bincode::deserialize(&policy_data)
            .map_err(|e| MACError::PolicyError(format!("Failed to parse policy: {}", e)))?;

        // Update the policy
        self.update_policy(policy).await
    }

    pub async fn get_security_context(
        &self,
        identifier: &str,
    ) -> Result<SecurityContext, MACError> {
        // Get security context for a subject or object
        let policy = self.policy.read().await;
        policy.get_security_context(identifier).ok_or_else(|| {
            MACError::LabelError(format!("Security context not found for {}", identifier))
        })
    }

    pub async fn get_audit_log(&self) -> Result<Vec<AuditEvent>, MACError> {
        let auditor = self.auditor.read().await;
        Ok(auditor.get_recent_events().await?)
    }
}

#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub user: String,
    pub role: String,
    pub level: SecurityLevel,
    pub categories: HashSet<String>,
}

#[derive(Debug, Clone)]
pub enum AccessType {
    Read,
    Write,
    Execute,
    Create,
    Delete,
    Admin,
}

#[derive(Debug, Clone)]
pub enum AccessResult {
    Allow,
    Deny(String),
    Audit,
}
