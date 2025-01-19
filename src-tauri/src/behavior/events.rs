#[derive(Debug, Clone)]
pub struct SystemEvent {
    pub event_type: EventType,
    pub context: EventContext,
    pub timestamp: Instant,
    pub process_info: ProcessInfo,
    pub resource_info: Option<ResourceInfo>,
    pub metadata: EventMetadata,
}

#[derive(Debug, Clone)]
pub struct EventContext {
    pub user_id: u32,
    pub group_id: u32,
    pub parent_process: Option<ProcessInfo>,
    pub environment: HashMap<String, String>,
    pub security_context: SecurityContext,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    ProcessStart(ProcessStartInfo),
    ProcessExit(ProcessExitInfo),
    FileAccess(FileAccessInfo),
    NetworkAccess(NetworkAccessInfo),
    ResourceUsage(ResourceUsageInfo),
    SecurityViolation(SecurityViolationInfo),
    SystemStateChange(SystemStateInfo),
    IntegrityViolation(IntegrityViolationInfo),
}

#[derive(Debug, Clone)]
pub struct EventMetadata {
    pub source_module: String,
    pub severity: EventSeverity,
    pub correlation_id: Option<String>,
    pub tags: HashSet<String>,
    pub additional_data: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SecurityViolationInfo {
    pub violation_type: ViolationType,
    pub resource: String,
    pub description: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    UnauthorizedAccess,
    PolicyViolation,
    IntegrityBreach,
    AnomalousBehavior,
    MaliciousActivity,
}

impl SystemEvent {
    pub fn new(
        event_type: EventType,
        process_info: ProcessInfo,
        resource_info: Option<ResourceInfo>,
        context: EventContext,
    ) -> Self {
        Self {
            event_type,
            context,
            timestamp: Instant::now(),
            process_info,
            resource_info,
            metadata: EventMetadata::default(),
        }
    }

    pub fn with_metadata(mut self, metadata: EventMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self.event_type,
            EventType::SecurityViolation(_)
                | EventType::IntegrityViolation(_)
                | EventType::ProcessStart(_)
        ) || self.metadata.severity >= EventSeverity::High
    }

    pub fn should_alert(&self) -> bool {
        self.is_security_relevant() && self.metadata.severity >= EventSeverity::High
    }
}

impl EventMetadata {
    pub fn new(source_module: String, severity: EventSeverity) -> Self {
        Self {
            source_module,
            severity,
            correlation_id: None,
            tags: HashSet::new(),
            additional_data: HashMap::new(),
        }
    }

    pub fn with_correlation_id(mut self, id: String) -> Self {
        self.correlation_id = Some(id);
        self
    }

    pub fn add_tag(&mut self, tag: String) {
        self.tags.insert(tag);
    }

    pub fn add_data(&mut self, key: String, value: String) {
        self.additional_data.insert(key, value);
    }
}

// Event information structs
#[derive(Debug, Clone)]
pub struct ProcessStartInfo {
    pub command: String,
    pub arguments: Vec<String>,
    pub environment: HashMap<String, String>,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProcessExitInfo {
    pub exit_code: i32,
    pub exit_reason: String,
    pub runtime_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct FileAccessInfo {
    pub path: PathBuf,
    pub access_type: AccessType,
    pub result: AccessResult,
}

#[derive(Debug, Clone)]
pub struct NetworkAccessInfo {
    pub protocol: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ResourceUsageInfo {
    pub resource_type: ResourceType,
    pub usage_amount: u64,
    pub threshold: u64,
}

#[derive(Debug, Clone)]
pub struct SystemStateInfo {
    pub component: String,
    pub previous_state: String,
    pub new_state: String,
    pub change_reason: String,
}

#[derive(Debug, Clone)]
pub struct IntegrityViolationInfo {
    pub path: PathBuf,
    pub expected_hash: String,
    pub actual_hash: String,
    pub violation_type: IntegrityViolationType,
}
