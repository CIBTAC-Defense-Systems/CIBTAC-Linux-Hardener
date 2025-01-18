use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};

pub struct SyscallMonitor {
    filters: Arc<RwLock<SyscallFilters>>,
    monitor: Arc<RwLock<Monitor>>,
    event_sender: mpsc::Sender<SyscallEvent>,
    whitelist: Arc<RwLock<HashSet<u32>>>,
    pattern_matcher: Arc<RwLock<PatternMatcher>>,
}

#[derive(Debug)]
struct SyscallStatistics {
    total_calls: usize,
    blocked_calls: usize,
    suspicious_calls: usize,
    violations_by_syscall: HashMap<u32, usize>,
    last_violation: Option<SystemTime>,
    statistics_window: Duration,
}

pub struct FilterRule {
    pub action: FilterAction,
    pub conditions: Vec<Condition>,
}

#[derive(Debug)]
struct SyscallFilters {
    enabled_filters: HashMap<u32, FilterRule>,
    default_action: FilterAction,
}

#[derive(Debug)]
struct Monitor {
    active: bool,
    suspicious_patterns: HashMap<String, PatternMatcher>,
    statistics: SyscallStatistics,
}

#[derive(Debug)]
struct PatternMatcher {
    patterns: Vec<SyscallPattern>,
    window: VecDeque<Syscall>,
    window_duration: Duration,
}

#[derive(Debug, Clone)]
enum SyscallPattern {
    Sequence(Vec<u32>),               // Sequence of syscall numbers
    Frequency(u32, usize),            // (syscall_number, max_count)
    TimeWindow(u32, Duration, usize), // (syscall_number, duration, max_count)
    Custom(Arc<dyn Fn(&[Syscall]) -> bool + Send + Sync>),
}

#[derive(Debug)]
pub enum SyscallError {
    FilterError(String),
    MonitoringError(String),
    UnauthorizedCall(String),
    PatternViolation(String),
    ConfigurationError(String),
}

#[derive(Debug)]
enum SyscallEvent {
    Normal(Syscall),
    Suspicious(Syscall),
    Blocked(Syscall),
}

#[derive(Debug)]
enum FilterAction {
    Allow,
    Deny,
    Log,
    Alert,
}

enum Condition {
    ArgMatch(usize, usize), // (arg_index, expected_value)
    ProcessMatch(u32),      // process_id
    Custom(Box<dyn Fn(&Syscall) -> bool + Send + Sync>),
}

#[derive(Debug, Clone)]
struct Syscall {
    number: u32,
    args: Vec<usize>,
    process_id: u32,
    timestamp: SystemTime,
    context: SyscallContext,
}

#[derive(Debug, Clone)]
struct SyscallContext {
    user_id: u32,
    group_id: u32,
    executable_path: String,
    is_privileged: bool,
}

impl SyscallMonitor {
    pub async fn new() -> Result<Self, SyscallError> {
        let (tx, rx) = mpsc::channel(1000);

        let monitor = Self {
            filters: Arc::new(RwLock::new(SyscallFilters::new())),
            monitor: Arc::new(RwLock::new(Monitor::new())),
            event_sender: tx,
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            pattern_matcher: Arc::new(RwLock::new(PatternMatcher::new())),
        };

        monitor.start_monitoring_task(rx).await?;
        Ok(monitor)
    }

    pub async fn initialize(&self) -> Result<(), SyscallError> {
        // Set up syscall monitoring
        self.setup_filters().await?;
        self.enable_monitoring().await?;
        self.start_monitoring().await?;

        Ok(())
    }

    pub async fn setup_filters(&self) -> Result<(), SyscallError> {
        let mut filters = self.filters.write().await;

        // Essential system calls - carefully restricted
        filters.add_safe_syscall(0); // read
        filters.add_safe_syscall(1); // write
        filters.add_safe_syscall(3); // close
        filters.add_safe_syscall(60); // exit

        // Restricted file operations
        filters.add_restricted_syscall(
            2,
            vec![
                // open
                Condition::ArgMatch(1, 0o444), // read-only flag
            ],
        );

        filters.add_restricted_syscall(
            257,
            vec![
                // openat
                Condition::ArgMatch(2, 0o444), // read-only flag
            ],
        );

        // Process management (restricted)
        filters.add_restricted_syscall(
            59,
            vec![
                // execve
                Condition::Custom(Box::new(|syscall| {
                    // Custom validation of executable path
                    syscall.context.is_privileged == false
                })),
            ],
        );

        // Memory management
        filters.add_restricted_syscall(
            9,
            vec![
                // mmap
                Condition::Custom(Box::new(|syscall| {
                    // Prevent executable memory allocation
                    let prot = syscall.args[2];
                    (prot & 0x4) == 0 // PROT_EXEC not allowed
                })),
            ],
        );

        // Network syscalls (heavily restricted)
        filters.add_restricted_syscall(
            41,
            vec![
                // socket
                Condition::ArgMatch(0, 2), // AF_INET only
                Condition::ArgMatch(1, 1), // SOCK_STREAM only
            ],
        );

        // Set default action for unspecified syscalls
        filters.default_action = FilterAction::Deny;

        Ok(())
    }

    async fn initialize_patterns(&self) -> Result<(), SyscallError> {
        let mut matcher = self.pattern_matcher.write().await;

        // Add known malicious patterns
        matcher.patterns.push(SyscallPattern::Sequence(vec![
            59, // execve
            96, // ptrace
            62, // kill
        ]));

        // Add frequency-based patterns
        matcher.patterns.push(SyscallPattern::Frequency(
            62, // kill
            10, // max 10 kills in window
        ));

        Ok(())
    }

    async fn handle_syscall(&self, syscall: &Syscall) -> Result<(), SyscallError> {
        // Check whitelist
        let whitelist = self.whitelist.read().await;
        if !whitelist.contains(&syscall.number) {
            return Err(SyscallError::UnauthorizedCall(format!(
                "Syscall {} not in whitelist",
                syscall.number
            )));
        }

        // Check patterns
        let matcher = self.pattern_matcher.read().await;
        if matcher.matches_pattern(syscall).await? {
            self.event_sender
                .send(SyscallEvent::Suspicious(syscall.clone()))
                .await
                .map_err(|e| SyscallError::MonitoringError(e.to_string()))?;
        }

        // Apply filters
        let filters = self.filters.read().await;
        if let Some(rule) = filters.enabled_filters.get(&syscall.number) {
            self.apply_filter_rule(rule, syscall).await?;
        }

        Ok(())
    }

    async fn start_monitoring(&self) -> Result<(), SyscallError> {
        // Enable monitoring in the Monitor
        let mut monitor = self.monitor.write().await;
        monitor.active = true;
        monitor.initialize().await?;

        // Initialize whitelist with allowed syscalls
        let mut whitelist = self.whitelist.write().await;
        let filters = self.filters.read().await;

        for syscall_num in filters.enabled_filters.keys() {
            whitelist.insert(*syscall_num);
        }

        Ok(())
    }

    async fn start_monitoring_task(
        &self,
        mut rx: mpsc::Receiver<SyscallEvent>,
    ) -> Result<(), SyscallError> {
        let monitor = Arc::clone(&self.monitor);
        let filters = Arc::clone(&self.filters);

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let mut monitor = monitor.write().await;
                if !monitor.active {
                    continue;
                }

                // Process the event
                if let Err(e) = monitor.process_event(event).await {
                    eprintln!("Error processing syscall event: {}", e);
                    // Continue processing other events even if one fails
                    continue;
                }
            }
            Ok::<(), SyscallError>(())
        });

        Ok(())
    }
}

impl PatternMatcher {
    fn new() -> Self {
        Self {
            patterns: Vec::new(),
            window: VecDeque::new(),
            window_duration: Duration::from_secs(60),
        }
    }

    async fn matches_pattern(&self, syscall: &Syscall) -> Result<bool, SyscallError> {
        // Update window
        self.update_window(syscall);

        // Check each pattern
        for pattern in &self.patterns {
            match pattern {
                SyscallPattern::Sequence(seq) => {
                    if self.matches_sequence(seq) {
                        return Ok(true);
                    }
                }
                SyscallPattern::Frequency(number, max_count) => {
                    if self.exceeds_frequency(*number, *max_count) {
                        return Ok(true);
                    }
                }
                SyscallPattern::TimeWindow(number, duration, max_count) => {
                    if self.exceeds_time_window(*number, duration, *max_count) {
                        return Ok(true);
                    }
                }
                SyscallPattern::Custom(checker) => {
                    if checker(&self.window.make_contiguous()) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn update_window(&mut self, syscall: &Syscall) {
        let now = SystemTime::now();

        // Remove old entries
        while let Some(old) = self.window.front() {
            if now
                .duration_since(old.timestamp)
                .unwrap_or(Duration::from_secs(0))
                > self.window_duration
            {
                self.window.pop_front();
            } else {
                break;
            }
        }

        // Add new syscall
        self.window.push_back(syscall.clone());
    }

    fn matches_sequence(&self, sequence: &[u32]) -> bool {
        if sequence.len() > self.window.len() {
            return false;
        }

        let window_slice = &self.window.make_contiguous()[self.window.len() - sequence.len()..];
        sequence
            .iter()
            .zip(window_slice.iter())
            .all(|(seq, call)| seq == &call.number)
    }

    fn exceeds_frequency(&self, number: u32, max_count: usize) -> bool {
        self.window
            .iter()
            .filter(|call| call.number == number)
            .count()
            > max_count
    }

    fn exceeds_time_window(&self, number: u32, duration: &Duration, max_count: usize) -> bool {
        let now = SystemTime::now();
        self.window
            .iter()
            .filter(|call| {
                call.number == number
                    && now
                        .duration_since(call.timestamp)
                        .unwrap_or(Duration::from_secs(0))
                        <= *duration
            })
            .count()
            > max_count
    }
}

impl SyscallFilters {
    fn new() -> Self {
        Self {
            enabled_filters: HashMap::new(),
            default_action: FilterAction::Deny,
        }
    }

    fn set_default_rules(&mut self) -> Result<(), SyscallError> {
        // Allow basic process management
        self.add_safe_syscall(1); // exit
        self.add_safe_syscall(60); // exit_group
        self.add_safe_syscall(231); // exit_group with error

        // Allow basic file operations with restrictions
        self.add_restricted_syscall(
            2,
            vec![
                // open
                Condition::ArgMatch(1, 0o444), // read-only
            ],
        );

        // Add more default rules...
        Ok(())
    }

    fn add_safe_syscall(&mut self, syscall_num: u32) {
        self.enabled_filters.insert(
            syscall_num,
            FilterRule {
                action: FilterAction::Allow,
                conditions: Vec::new(),
            },
        );
    }

    fn add_restricted_syscall(&mut self, syscall_num: u32, conditions: Vec<Condition>) {
        self.enabled_filters.insert(
            syscall_num,
            FilterRule {
                action: FilterAction::Allow,
                conditions,
            },
        );
    }
}

impl Monitor {
    fn new() -> Self {
        Self {
            active: false,
            suspicious_patterns: HashMap::new(),
            statistics: SyscallStatistics::new(),
        }
    }

    async fn initialize(&mut self) -> Result<(), SyscallError> {
        self.active = true;
        self.statistics = SyscallStatistics::new();

        // Initialize suspicious patterns map
        self.suspicious_patterns.clear();
        self.setup_default_patterns()?;

        Ok(())
    }

    fn setup_default_patterns(&mut self) -> Result<(), SyscallError> {
        let default_patterns = [
            // Process injection pattern
            (
                "process_injection",
                PatternMatcher {
                    patterns: vec![SyscallPattern::Sequence(vec![
                        57,  // fork
                        101, // ptrace
                        250, // mmap
                    ])],
                    window: VecDeque::new(),
                    window_duration: Duration::from_secs(5),
                },
            ),
            // File system tampering pattern
            (
                "fs_tampering",
                PatternMatcher {
                    patterns: vec![
                        SyscallPattern::Frequency(87, 10), // unlink
                        SyscallPattern::Frequency(82, 10), // rename
                    ],
                    window: VecDeque::new(),
                    window_duration: Duration::from_secs(10),
                },
            ),
            // Network abuse pattern
            (
                "network_abuse",
                PatternMatcher {
                    patterns: vec![SyscallPattern::TimeWindow(
                        41, // socket
                        Duration::from_secs(60),
                        100,
                    )],
                    window: VecDeque::new(),
                    window_duration: Duration::from_secs(60),
                },
            ),
        ];

        for (name, matcher) in default_patterns.iter() {
            self.suspicious_patterns
                .insert(name.to_string(), matcher.clone());
        }

        Ok(())
    }

    async fn process_event(&mut self, event: SyscallEvent) -> Result<(), SyscallError> {
        if !self.active {
            return Ok(());
        }

        match event {
            SyscallEvent::Normal(syscall) => {
                self.statistics.total_calls += 1;

                // Check against all suspicious patterns
                for matcher in self.suspicious_patterns.values_mut() {
                    if matcher.matches_pattern(&syscall).await? {
                        return self.handle_suspicious_syscall(&syscall).await;
                    }
                }

                self.update_statistics(&syscall);
            }
            SyscallEvent::Suspicious(syscall) => {
                self.statistics.suspicious_calls += 1;
                self.handle_suspicious_syscall(&syscall).await?;
            }
            SyscallEvent::Blocked(syscall) => {
                self.statistics.blocked_calls += 1;
                self.handle_blocked_syscall(&syscall).await?;
            }
        }

        Ok(())
    }

    async fn handle_suspicious_syscall(&mut self, syscall: &Syscall) -> Result<(), SyscallError> {
        self.statistics.last_violation = Some(SystemTime::now());
        // Implement suspicious syscall handling logic
        Ok(())
    }

    async fn handle_blocked_syscall(&mut self, syscall: &Syscall) -> Result<(), SyscallError> {
        // Implement blocked syscall handling logic
        Ok(())
    }

    fn update_statistics(&mut self, syscall: &Syscall) {
        // Clean old statistics based on window
        let now = SystemTime::now();
        if let Some(last) = self.statistics.last_violation {
            if now.duration_since(last).unwrap_or(Duration::from_secs(0))
                > self.statistics.statistics_window
            {
                self.statistics.reset();
            }
        }
    }
}

impl SyscallMonitor {
    pub async fn enable_monitoring(&self) -> Result<(), SyscallError> {
        let mut monitor = self.monitor.write().await;
        monitor.active = true;
        Ok(())
    }

    async fn apply_filter_rule(
        &self,
        rule: &FilterRule,
        syscall: &Syscall,
    ) -> Result<(), SyscallError> {
        // Check all conditions
        for condition in &rule.conditions {
            match condition {
                Condition::ArgMatch(index, expected) => {
                    if syscall.args.get(*index) != Some(expected) {
                        return Err(SyscallError::FilterError("Argument mismatch".into()));
                    }
                }
                Condition::ProcessMatch(pid) => {
                    if &syscall.process_id != pid {
                        return Err(SyscallError::FilterError("Process ID mismatch".into()));
                    }
                }
                Condition::Custom(checker) => {
                    if !checker(syscall) {
                        return Err(SyscallError::FilterError("Custom condition failed".into()));
                    }
                }
            }
        }

        // Apply action
        match &rule.action {
            FilterAction::Allow => Ok(()),
            FilterAction::Deny => {
                self.event_sender
                    .send(SyscallEvent::Blocked(syscall.clone()))
                    .await
                    .map_err(|e| SyscallError::MonitoringError(e.to_string()))?;
                Err(SyscallError::FilterError(
                    "Syscall blocked by filter".into(),
                ))
            }
            FilterAction::Log => {
                self.event_sender
                    .send(SyscallEvent::Normal(syscall.clone()))
                    .await
                    .map_err(|e| SyscallError::MonitoringError(e.to_string()))?;
                Ok(())
            }
            FilterAction::Alert => {
                self.event_sender
                    .send(SyscallEvent::Suspicious(syscall.clone()))
                    .await
                    .map_err(|e| SyscallError::MonitoringError(e.to_string()))?;
                Ok(())
            }
        }
    }
}

impl SyscallStatistics {
    fn new() -> Self {
        Self {
            total_calls: 0,
            blocked_calls: 0,
            suspicious_calls: 0,
            violations_by_syscall: HashMap::new(),
            last_violation: None,
            statistics_window: Duration::from_secs(3600), // 1 hour window
        }
    }

    fn reset(&mut self) {
        self.total_calls = 0;
        self.blocked_calls = 0;
        self.suspicious_calls = 0;
        self.violations_by_syscall.clear();
        self.last_violation = None;
    }
}
