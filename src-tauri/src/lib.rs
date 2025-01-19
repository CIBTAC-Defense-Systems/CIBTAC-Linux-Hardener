mod ai;
mod behavior;
mod config;
mod integrity;
mod kernel;
mod logging;
mod mac;
mod package;
mod sandbox;
mod ui;

use std::sync::Arc;
use tokio::sync::RwLock;

pub use ai::AIEngine;
pub use behavior::{BehaviorEngine, SystemEvent};
pub use config::ConfigurationManager;
pub use integrity::IntegrityMonitor;
pub use kernel::{KernelSecurity, SecurityPolicy};
pub use logging::Logger;
pub use mac::MACSystem;
pub use package::analyzers::PackageAnalyzer;
pub use sandbox::Sandbox;

#[tauri::command]
async fn check_initialization_status() -> Result<String, String> {
    let config_manager = ConfigurationManager::new()
        .await
        .map_err(|e| e.to_string())?;

    config_manager.initialize().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn complete_initial_setup(config: SystemConfiguration) -> Result<(), String> {
    let mut config_manager = ConfigurationManager::new()
        .await
        .map_err(|e| e.to_string())?;

    config_manager
        .complete_initial_setup(config)
        .await
        .map_err(|e| e.to_string())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            check_initialization_status,
            complete_initial_setup,
            initialize_security
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn initialize_security() -> Result<(), String> {
    let config_manager = ConfigurationManager::new()
        .await
        .map_err(|e| format!("Failed to initialize configuration: {}", e))?;

    let security_system = SecuritySystem::new_with_config(config_manager)
        .await
        .map_err(|e| format!("Failed to initialize security system: {}", e))?;

    security_system
        .start()
        .await
        .map_err(|e| format!("Failed to start security system: {}", e))
}

impl SecuritySystem {
    pub async fn new_with_config(
        config_manager: ConfigurationManager,
    ) -> Result<Self, SecurityError> {
        let config = Arc::new(RwLock::new(SecurityConfig::default()));
        let system_config = config_manager.get_current_config().await?;

        // Initialize all security components with configuration
        let kernel_security = Arc::new(KernelSecurity::new().await?);
        let behavior_engine = Arc::new(BehaviorEngine::new().await?);
        let sandbox = Arc::new(Sandbox::new().await?);
        let mac = Arc::new(MACSystem::new().await?);
        let integrity = Arc::new(IntegrityMonitor::new().await?);
        let logger = Arc::new(Logger::new().await?);

        // Initialize AI engine only if LLM is configured
        let ai_engine = if system_config.llm_config.enabled {
            Arc::new(AIEngine::new().await?)
        } else {
            Arc::new(AIEngine::new_disabled().await?)
        };

        // Initialize package analyzer with AI capabilities if available
        let package_monitor = Arc::new(
            PackageAnalyzer::new(ai_engine.clone(), system_config.package_analysis_config).await?,
        );

        Ok(Self {
            kernel_security,
            behavior_engine,
            sandbox,
            mac,
            integrity,
            logger,
            ai_engine,
            package_analyzer,
            config,
        })
    }

    pub async fn start(&self) -> Result<(), SecurityError> {
        // Start kernel security measures
        self.kernel_security.initialize().await?;

        // Start behavior monitoring
        self.behavior_engine.start_monitoring().await?;

        // Initialize sandbox environment
        self.sandbox.initialize().await?;

        // Start MAC enforcement
        self.mac.start_enforcement().await?;

        // Begin integrity monitoring
        self.integrity.start_monitoring().await?;

        // Start AI analysis engine if enabled
        if self.ai_engine.is_enabled() {
            self.ai_engine.start().await?;
        }

        // Start package analyzer
        self.package_monitor.initialize().await?;

        // Initialize logging system
        self.logger.initialize().await?;

        Ok(())
    }
}
