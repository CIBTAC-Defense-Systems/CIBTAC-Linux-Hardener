pub struct ResourceController {
    cpu_controller: CpuController,
    memory_controller: MemoryController,
    io_controller: IoController,
    limits: ResourceLimits,
    usage: ResourceUsage,
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    cpu_quota: f32,            // CPU usage quota (0.0 - 1.0)
    memory_limit: usize,       // Memory limit in bytes
    io_bandwidth: usize,       // I/O bandwidth in bytes/sec
    max_processes: u32,        // Maximum number of processes
    max_file_descriptors: u32, // Maximum number of open file descriptors
}

#[derive(Debug)]
pub struct ResourceUsage {
    cpu_usage: f32,
    memory_usage: usize,
    io_usage: IoUsage,
    process_count: u32,
    fd_count: u32,
}

#[derive(Debug)]
struct CpuController {
    cgroup_path: PathBuf,
    quota_us: i64,
    period_us: i64,
    current_usage: Arc<AtomicF32>,
}

#[derive(Debug)]
struct MemoryController {
    cgroup_path: PathBuf,
    limit_bytes: usize,
    current_usage: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct IoController {
    cgroup_path: PathBuf,
    bandwidth_limit: usize,
    current_usage: Arc<RwLock<IoUsage>>,
}

#[derive(Debug, Clone)]
struct IoUsage {
    read_bytes: u64,
    write_bytes: u64,
    read_iops: u64,
    write_iops: u64,
}

impl ResourceController {
    pub fn new(config: &ResourceLimits) -> Result<Self, SandboxError> {
        Ok(Self {
            cpu_controller: CpuController::new(config.cpu_quota)?,
            memory_controller: MemoryController::new(config.memory_limit)?,
            io_controller: IoController::new(config.io_bandwidth)?,
            limits: config.clone(),
            usage: ResourceUsage::default(),
        })
    }

    async fn initialize_with_config(
        &mut self,
        limits: &ResourceLimits,
    ) -> Result<(), SandboxError> {
        self.initialize().await?; // Base initialization
        self.apply_limits(limits).await?; // Apply specific config
        Ok(())
    }

    pub async fn initialize(&mut self) -> Result<(), SandboxError> {
        // Set up cgroup controllers
        self.setup_cgroups().await?;

        // Initialize resource monitoring
        self.start_monitoring().await?;

        Ok(())
    }

    pub async fn enforce_limits(&self, process: &Process) -> Result<(), SandboxError> {
        // Enforce CPU limits
        self.cpu_controller.enforce_quota(process).await?;

        // Enforce memory limits
        self.memory_controller.enforce_limits(process).await?;

        // Enforce I/O limits
        self.io_controller.enforce_bandwidth(process).await?;

        Ok(())
    }

    pub async fn update_usage(&mut self) -> Result<ResourceUsage, SandboxError> {
        self.usage = ResourceUsage {
            cpu_usage: self.cpu_controller.get_usage().await?,
            memory_usage: self.memory_controller.get_usage().await?,
            io_usage: self.io_controller.get_usage().await?,
            process_count: self.get_process_count().await?,
            fd_count: self.get_fd_count().await?,
        };

        Ok(self.usage.clone())
    }

    async fn setup_cgroups(&mut self) -> Result<(), SandboxError> {
        // Create cgroup hierarchy
        self.create_cgroup_hierarchy().await?;

        // Set up CPU controller
        self.cpu_controller.setup().await?;

        // Set up memory controller
        self.memory_controller.setup().await?;

        // Set up I/O controller
        self.io_controller.setup().await?;

        Ok(())
    }

    async fn start_monitoring(&self) -> Result<(), SandboxError> {
        let cpu_monitor = Arc::clone(&self.cpu_controller.current_usage);
        let memory_monitor = Arc::clone(&self.memory_controller.current_usage);
        let io_monitor = Arc::clone(&self.io_controller.current_usage);

        tokio::spawn(async move {
            loop {
                // Update CPU usage
                if let Ok(usage) = get_cpu_usage().await {
                    cpu_monitor.store(usage, Ordering::Release);
                }

                // Update memory usage
                if let Ok(usage) = get_memory_usage().await {
                    memory_monitor.store(usage, Ordering::Release);
                }

                // Update I/O usage
                if let Ok(usage) = get_io_usage().await {
                    *io_monitor.write().await = usage;
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    async fn apply_limits(&mut self, limits: &ResourceLimits) -> Result<(), SandboxError> {
        // Set CPU limits
        self.set_cpu_quota(limits.cpu_quota).await?;

        // Set memory limits
        self.set_memory_limit(limits.memory_limit).await?;

        // Set I/O limits
        self.set_io_bandwidth(limits.io_bandwidth).await?;

        // Set process limits
        self.set_process_limit(limits.max_processes).await?;

        Ok(())
    }
}

impl CpuController {
    async fn enforce_quota(&self, process: &Process) -> Result<(), SandboxError> {
        let cgroup_path = self.cgroup_path.join("cpu.cfs_quota_us");
        fs::write(&cgroup_path, self.quota_us.to_string())
            .await
            .map_err(|e| SandboxError::ResourceError(format!("Failed to set CPU quota: {}", e)))?;

        // Add process to cgroup
        let tasks_path = self.cgroup_path.join("tasks");
        fs::write(&tasks_path, process.pid.to_string())
            .await
            .map_err(|e| {
                SandboxError::ResourceError(format!("Failed to add process to cgroup: {}", e))
            })?;

        Ok(())
    }

    async fn get_usage(&self) -> Result<f32, SandboxError> {
        let usage_path = self.cgroup_path.join("cpu.stat");
        let content = fs::read_to_string(&usage_path)
            .await
            .map_err(|e| SandboxError::ResourceError(format!("Failed to read CPU usage: {}", e)))?;

        // Parse CPU usage from cgroup stats
        parse_cpu_usage(&content)
            .ok_or_else(|| SandboxError::ResourceError("Failed to parse CPU usage".into()))
    }
}

impl MemoryController {
    async fn enforce_limits(&self, process: &Process) -> Result<(), SandboxError> {
        let limit_path = self.cgroup_path.join("memory.limit_in_bytes");
        fs::write(&limit_path, self.limit_bytes.to_string())
            .await
            .map_err(|e| {
                SandboxError::ResourceError(format!("Failed to set memory limit: {}", e))
            })?;

        // Add process to cgroup
        let tasks_path = self.cgroup_path.join("tasks");
        fs::write(&tasks_path, process.pid.to_string())
            .await
            .map_err(|e| {
                SandboxError::ResourceError(format!("Failed to add process to cgroup: {}", e))
            })?;

        Ok(())
    }

    async fn get_usage(&self) -> Result<usize, SandboxError> {
        let usage_path = self.cgroup_path.join("memory.usage_in_bytes");
        let content = fs::read_to_string(&usage_path).await.map_err(|e| {
            SandboxError::ResourceError(format!("Failed to read memory usage: {}", e))
        })?;

        content.trim().parse().map_err(|e| {
            SandboxError::ResourceError(format!("Failed to parse memory usage: {}", e))
        })
    }
}

impl IoController {
    async fn enforce_bandwidth(&self, process: &Process) -> Result<(), SandboxError> {
        let limit_path = self.cgroup_path.join("io.max");
        let limit = format!("{}:{}", process.pid, self.bandwidth_limit);

        fs::write(&limit_path, limit)
            .await
            .map_err(|e| SandboxError::ResourceError(format!("Failed to set I/O limit: {}", e)))?;

        Ok(())
    }

    async fn get_usage(&self) -> Result<IoUsage, SandboxError> {
        let stat_path = self.cgroup_path.join("io.stat");
        let content = fs::read_to_string(&stat_path)
            .await
            .map_err(|e| SandboxError::ResourceError(format!("Failed to read I/O stats: {}", e)))?;

        parse_io_stats(&content)
            .ok_or_else(|| SandboxError::ResourceError("Failed to parse I/O stats".into()))
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_quota: 1.0,
            memory_limit: 512 * 1024 * 1024, // 512MB
            io_bandwidth: 10 * 1024 * 1024,  // 10MB/s
            max_processes: 10,
            max_file_descriptors: 1024,
        }
    }
}

// CPU usage parsing
fn parse_cpu_usage(stat_content: &str) -> Option<f32> {
    let mut cpu_usage = None;

    for line in stat_content.lines() {
        if line.starts_with("usage_usec") {
            if let Some(value) = line.split_whitespace().nth(1) {
                if let Ok(usage_usec) = value.parse::<u64>() {
                    // Convert microseconds to percentage based on period
                    cpu_usage = Some((usage_usec as f32) / 1_000_000.0);
                    break;
                }
            }
        }
    }

    cpu_usage
}

// I/O stats parsing
fn parse_io_stats(content: &str) -> Option<IoUsage> {
    let mut usage = IoUsage {
        read_bytes: 0,
        write_bytes: 0,
        read_iops: 0,
        write_iops: 0,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        match parts[0] {
            "rbytes" => {
                usage.read_bytes = parts[1].parse().ok()?;
            }
            "wbytes" => {
                usage.write_bytes = parts[1].parse().ok()?;
            }
            "rios" => {
                usage.read_iops = parts[1].parse().ok()?;
            }
            "wios" => {
                usage.write_iops = parts[1].parse().ok()?;
            }
            _ => continue,
        }
    }

    Some(usage)
}

// Helper function to read cgroup values
async fn read_cgroup_value(path: &Path) -> Result<String, SandboxError> {
    fs::read_to_string(path)
        .await
        .map_err(|e| SandboxError::ResourceError(format!("Failed to read cgroup value: {}", e)))
}

// Helper function to write cgroup values
async fn write_cgroup_value(path: &Path, value: &str) -> Result<(), SandboxError> {
    fs::write(path, value)
        .await
        .map_err(|e| SandboxError::ResourceError(format!("Failed to write cgroup value: {}", e)))
}

// CPU Usage calculation helpers
struct CpuStat {
    user: u64,
    system: u64,
    total: u64,
}

fn get_cpu_stats(stat_content: &str) -> Option<CpuStat> {
    for line in stat_content.lines() {
        if line.starts_with("cpu ") {
            let values: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .map(|x| x.parse().unwrap_or(0))
                .collect();

            if values.len() >= 7 {
                return Some(CpuStat {
                    user: values[0],
                    system: values[2],
                    total: values.iter().take(7).sum(),
                });
            }
        }
    }
    None
}

fn calculate_cpu_percentage(prev: &CpuStat, curr: &CpuStat) -> f32 {
    let total_diff = curr.total.saturating_sub(prev.total) as f32;
    if total_diff == 0.0 {
        return 0.0;
    }

    let used_diff =
        (curr.user.saturating_sub(prev.user) + curr.system.saturating_sub(prev.system)) as f32;

    (used_diff / total_diff) * 100.0
}

// Memory usage helpers
fn parse_memory_stat(content: &str) -> HashMap<String, u64> {
    let mut stats = HashMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            if let Ok(value) = parts[1].parse() {
                stats.insert(parts[0].to_string(), value);
            }
        }
    }

    stats
}

// Process count helper
async fn count_processes_in_cgroup(cgroup_path: &Path) -> Result<u32, SandboxError> {
    let tasks_path = cgroup_path.join("cgroup.procs");
    let content = read_cgroup_value(&tasks_path).await?;

    Ok(content.lines().count() as u32)
}

// File descriptor count helper
async fn count_open_fds(pid: u32) -> Result<u32, SandboxError> {
    let fd_path = PathBuf::from("/proc").join(pid.to_string()).join("fd");

    let entries = fs::read_dir(fd_path)
        .await
        .map_err(|e| SandboxError::ResourceError(format!("Failed to read fd directory: {}", e)))?;

    let mut count = 0;
    for _ in entries {
        count += 1;
    }

    Ok(count)
}
