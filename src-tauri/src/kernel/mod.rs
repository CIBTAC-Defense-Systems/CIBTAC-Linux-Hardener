mod memory;
mod module_verifier;
mod runtime_integrity;
mod secure_boot;
mod syscalls;
mod uefi;

pub use memory::MemoryProtection;
pub use module_verifier::KernelModuleVerifier;
pub use runtime_integrity::RuntimeIntegrityChecker;
pub use secure_boot::SecureBoot;
pub use syscalls::SyscallMonitor;
pub use uefi::UEFIProtection;

use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct KernelConfig {
    pub aslr_enabled: bool,
    pub stack_protection: bool,
    pub syscall_filtering: bool,
    pub secure_boot_required: bool,
    pub memory_restrictions: MemoryRestrictions,
    pub allowed_syscalls: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct MemoryRestrictions {
    pub exec_protection: bool,
    pub strict_page_permissions: bool,
    pub heap_randomization: bool,
    pub stack_canaries: bool,
}

#[derive(Debug, Clone)]
pub struct EarlyBootStatus {
    pub secure_boot_active: bool,
    pub kernel_parameters_verified: bool,
    pub memory_protection_active: bool,
    pub syscall_monitoring_active: bool,
    pub aslr_active: bool,
    pub stack_protection_active: bool,
    pub boot_time: std::time::SystemTime,
    pub initialization_messages: Vec<String>,
}

pub struct KernelSecurity {
    memory_protection: Arc<MemoryProtection>,
    syscall_monitor: Arc<SyscallMonitor>,
    uefi_protection: Arc<UEFIProtection>,
    module_verifier: Arc<KernelModuleVerifier>,
    runtime_integrity: Arc<RuntimeIntegrityChecker>,
    secure_boot: Arc<SecureBoot>,
    config: Arc<RwLock<KernelConfig>>,
    early_boot_status: Arc<RwLock<EarlyBootStatus>>,
}

#[derive(Error, Debug)]
pub enum KernelError {
    #[error("Memory protection error: {0}")]
    MemoryError(#[from] memory::MemoryError),

    #[error("Syscall monitoring error: {0}")]
    SyscallError(#[from] syscalls::SyscallError),

    #[error("UEFI protection error: {0}")]
    UEFIError(#[from] uefi::SecurityError),

    #[error("Module verification error: {0}")]
    ModuleError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Runtime integrity error: {0}")]
    IntegrityError(String),

    #[error("Security policy violation: {0}")]
    SecurityViolation(String),
}

impl KernelSecurity {
    pub async fn new() -> Result<Self, KernelError> {
        let early_boot_status = Arc::new(RwLock::new(EarlyBootStatus::new()));

        // Record boot start
        early_boot_status.write().await.boot_time = std::time::SystemTime::now();

        let instance = Self {
            memory_protection: Arc::new(MemoryProtection::new().await?),
            syscall_monitor: Arc::new(SyscallMonitor::new().await?),
            uefi_protection: Arc::new(UEFIProtection::new()),
            module_verifier: Arc::new(KernelModuleVerifier::new()),
            runtime_integrity: Arc::new(RuntimeIntegrityChecker::new()),
            secure_boot: Arc::new(SecureBoot::new().await?),
            config: Arc::new(RwLock::new(KernelConfig::default())),
            early_boot_status,
        };

        Ok(instance)
    }

    pub async fn initialize(&self) -> Result<(), KernelError> {
        let mut status = self.early_boot_status.write().await;
        let config = self.config.read().await;

        // 1. Verify UEFI/Secure Boot status
        self.secure_boot.verify_boot_chain().await?;
        status.secure_boot_active = true;
        status.add_message("Secure boot verified successfully");

        // 2. Initialize memory protections
        self.memory_protection.initialize().await?;

        // 3. Enable ASLR if configured
        if config.aslr_enabled {
            self.memory_protection.enable_aslr().await?;
            status.aslr_active = true;
            status.add_message("ASLR enabled successfully");
        }

        // 4. Enable stack protection if configured
        if config.stack_protection {
            self.memory_protection.enable_stack_protection().await?;
            status.stack_protection_active = true;
            status.add_message("Stack protection enabled");
        }

        // 5. Initialize syscall monitoring
        self.syscall_monitor.initialize().await?;
        status.syscall_monitoring_active = true;
        status.add_message("Syscall monitoring active");

        // 6. Start runtime integrity checking
        self.runtime_integrity.start_monitoring().await?;
        status.add_message("Runtime integrity monitoring started");

        Ok(())
    }

    pub async fn enforce_security_policy(&self, policy: SecurityPolicy) -> Result<(), KernelError> {
        let mut config = self.config.write().await;

        config.aslr_enabled = policy.aslr_enabled;
        config.stack_protection = policy.stack_protection;
        config.syscall_filtering = policy.syscall_filtering;
        config.secure_boot_required = policy.secure_boot_required;
        config.memory_restrictions = policy.memory_restrictions;
        config.allowed_syscalls = policy.allowed_syscalls;

        // Apply the new configuration
        self.apply_config(&config).await?;

        Ok(())
    }

    async fn apply_config(&self, config: &KernelConfig) -> Result<(), KernelError> {
        if config.aslr_enabled {
            self.memory_protection.enable_aslr().await?;
        }

        if config.stack_protection {
            self.memory_protection.enable_stack_protection().await?;
        }

        if config.syscall_filtering {
            self.syscall_monitor
                .set_allowed_syscalls(&config.allowed_syscalls)
                .await?;
        }

        Ok(())
    }

    pub async fn get_security_status(&self) -> Result<KernelSecurityStatus, KernelError> {
        let status = self.early_boot_status.read().await;
        let config = self.config.read().await;

        Ok(KernelSecurityStatus {
            boot_time: status.boot_time,
            secure_boot_active: status.secure_boot_active,
            aslr_enabled: config.aslr_enabled,
            stack_protection_enabled: config.stack_protection,
            memory_protection_active: status.memory_protection_active,
            syscall_monitoring_active: status.syscall_monitoring_active,
            initialization_messages: status.initialization_messages.clone(),
        })
    }
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            aslr_enabled: true,
            stack_protection: true,
            syscall_filtering: true,
            secure_boot_required: true,
            memory_restrictions: MemoryRestrictions {
                exec_protection: true,
                strict_page_permissions: true,
                heap_randomization: true,
                stack_canaries: true,
            },
            allowed_syscalls: Vec::new(), // Will be populated with default allowed syscalls
        }
    }
}

impl EarlyBootStatus {
    pub fn new() -> Self {
        Self {
            secure_boot_active: false,
            kernel_parameters_verified: false,
            memory_protection_active: false,
            syscall_monitoring_active: false,
            aslr_active: false,
            stack_protection_active: false,
            boot_time: std::time::SystemTime::now(),
            initialization_messages: Vec::new(),
        }
    }

    pub fn add_message(&mut self, message: impl Into<String>) {
        self.initialization_messages.push(message.into());
    }
}

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub aslr_enabled: bool,
    pub stack_protection: bool,
    pub syscall_filtering: bool,
    pub secure_boot_required: bool,
    pub allowed_syscalls: Vec<u32>,
    pub memory_restrictions: MemoryRestrictions,
}
