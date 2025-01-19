use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

use super::{
    analyzer::BehaviorAnalyzer, patterns::PatternMatcher, BehaviorConfig, BehaviorError, EventType,
    SystemEvent,
};

pub struct BehaviorMonitor {
    config: Arc<RwLock<BehaviorConfig>>,
    analyzer: Arc<BehaviorAnalyzer>,
    pattern_matcher: Arc<PatternMatcher>,
    event_history: Arc<RwLock<VecDeque<SystemEvent>>>,
    alert_tx: mpsc::Sender<SecurityAlert>,
}

#[derive(Debug)]
pub struct MonitoringSession {
    session_id: String,
    start_time: chrono::DateTime<chrono::Utc>,
    context: MonitoringContext,
    events: Vec<SystemEvent>,
    alerts: Vec<SecurityAlert>,
}

#[derive(Debug)]
pub struct MonitoringContext {
    pub process_id: Option<u32>,
    pub user_id: Option<u32>,
    pub package_name: Option<String>,
    pub monitoring_type: MonitoringType,
    pub security_level: SecurityLevel,
}

#[derive(Debug)]
pub enum MonitoringType {
    Process,
    Package,
    System,
    Custom(String),
}

impl BehaviorMonitor {
    pub fn new(config: Arc<RwLock<BehaviorConfig>>) -> Self {
        let (alert_tx, _) = mpsc::channel(1000);

        Self {
            config,
            analyzer: Arc::new(BehaviorAnalyzer::new()),
            pattern_matcher: Arc::new(PatternMatcher::new()),
            event_history: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            alert_tx,
        }
    }

    pub async fn start_monitoring(&self) -> Result<(), BehaviorError> {
        let (event_tx, mut event_rx) = mpsc::channel(1000);
        let config = self.config.read().await.clone();

        // Start event processing loop
        let analyzer = self.analyzer.clone();
        let pattern_matcher = self.pattern_matcher.clone();
        let event_history = self.event_history.clone();
        let alert_tx = self.alert_tx.clone();

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                // Add to event history
                let mut history = event_history.write().await;
                history.push_back(event.clone());
                while history.len() > 10000 {
                    history.pop_front();
                }
                drop(history);

                // Match patterns
                if let Ok(matches) = pattern_matcher.match_patterns(&event).await {
                    for pattern_match in matches {
                        if pattern_match.requires_alert() {
                            let alert = SecurityAlert::from_pattern_match(pattern_match);
                            let _ = alert_tx.send(alert).await;
                        }
                    }
                }

                // Analyze behavior
                if let Ok(analysis) = analyzer.analyze_event(&event).await {
                    if analysis.risk_level >= config.analysis_config.alert_threshold {
                        let alert = SecurityAlert::from_analysis(analysis);
                        let _ = alert_tx.send(alert).await;
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn create_monitoring_session(
        &self,
        context: MonitoringContext,
    ) -> Result<MonitoringSession, BehaviorError> {
        Ok(MonitoringSession {
            session_id: generate_session_id(),
            start_time: chrono::Utc::now(),
            context,
            events: Vec::new(),
            alerts: Vec::new(),
        })
    }

    pub async fn monitor_process(&self, pid: u32) -> Result<MonitoringSession, BehaviorError> {
        let context = MonitoringContext {
            process_id: Some(pid),
            user_id: get_process_user(pid)?,
            package_name: get_process_package(pid)?,
            monitoring_type: MonitoringType::Process,
            security_level: SecurityLevel::Standard,
        };

        let mut session = self.create_monitoring_session(context).await?;
        self.start_process_monitoring(pid, &mut session).await?;

        Ok(session)
    }

    pub async fn analyze_session(
        &self,
        session: &MonitoringSession,
    ) -> Result<BehaviorAnalysis, BehaviorError> {
        // Get analysis config
        let config = self.config.read().await;

        // Perform basic analysis
        let mut analysis = self.analyzer.analyze_events(&session.events).await?;

        // Use AI for enhanced analysis if available and enabled
        if config.analysis_config.use_ai {
            if let Some(ai_analysis) = self.analyzer.perform_ai_analysis(&session.events).await? {
                analysis.combine(ai_analysis);
            }
        }

        // Add pattern matching results
        let patterns = self.pattern_matcher.analyze_session(session).await?;
        analysis.add_pattern_matches(patterns);

        Ok(analysis)
    }

    pub async fn handle_security_alert(
        &self,
        alert: SecurityAlert,
        session: &mut MonitoringSession,
    ) -> Result<(), BehaviorError> {
        // Add alert to session
        session.alerts.push(alert.clone());

        // Check if action needed
        if alert.severity >= AlertSeverity::High {
            self.handle_high_severity_alert(&alert, session).await?;
        }

        // Update monitoring if needed
        self.adjust_monitoring_for_alert(&alert, session).await?;

        Ok(())
    }

    async fn handle_high_severity_alert(
        &self,
        alert: &SecurityAlert,
        session: &MonitoringSession,
    ) -> Result<(), BehaviorError> {
        match session.context.monitoring_type {
            MonitoringType::Process => {
                if let Some(pid) = session.context.process_id {
                    self.handle_process_violation(pid, alert).await?;
                }
            }
            MonitoringType::Package => {
                if let Some(package) = &session.context.package_name {
                    self.handle_package_violation(package, alert).await?;
                }
            }
            MonitoringType::System => {
                self.handle_system_violation(alert).await?;
            }
            MonitoringType::Custom(_) => {
                self.handle_custom_violation(alert, session).await?;
            }
        }

        Ok(())
    }

    async fn adjust_monitoring_for_alert(
        &self,
        alert: &SecurityAlert,
        session: &mut MonitoringSession,
    ) -> Result<(), BehaviorError> {
        // Increase monitoring intensity if needed
        if alert.severity >= AlertSeverity::Medium {
            session.context.security_level = session.context.security_level.increase();
        }

        // Add additional monitoring patterns
        if let Some(patterns) = alert.recommended_patterns.as_ref() {
            self.pattern_matcher.add_patterns(patterns.clone()).await?;
        }

        Ok(())
    }
}

fn generate_session_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}
