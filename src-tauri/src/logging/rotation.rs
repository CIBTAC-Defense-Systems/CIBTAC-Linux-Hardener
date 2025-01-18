use super::{LogStorage, LoggingError};
use chrono::{DateTime, Duration, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

pub struct LogRotator {
    config: RotationConfig,
    state: Arc<RwLock<RotationState>>,
}

#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub max_size: Option<u64>,               // Maximum file size in bytes
    pub max_files: Option<usize>,            // Maximum number of rotated files to keep
    pub rotation_interval: Option<Duration>, // Time-based rotation
    pub compression_enabled: bool,           // Whether to compress rotated logs
    pub rotation_format: RotationFormat,     // Format for rotated file names
}

#[derive(Debug, Clone)]
pub enum RotationFormat {
    Timestamp,
    Sequential,
    DateBased,
    Custom(String),
}

#[derive(Debug)]
struct RotationState {
    current_file_size: u64,
    last_rotation: DateTime<Utc>,
    rotation_count: usize,
}

impl LogRotator {
    pub fn new(config: RotationConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(RotationState::new())),
        }
    }

    pub async fn initialize(&self) -> Result<(), LoggingError> {
        // Initialize rotation state
        let mut state = self.state.write().await;
        state.current_file_size = self.get_current_log_size().await?;
        state.last_rotation = Utc::now();
        state.rotation_count = self.count_existing_rotated_files().await?;

        Ok(())
    }

    pub async fn should_rotate(&self) -> Result<bool, LoggingError> {
        let state = self.state.read().await;
        let now = Utc::now();

        // Check size-based rotation
        if let Some(max_size) = self.config.max_size {
            if state.current_file_size >= max_size {
                return Ok(true);
            }
        }

        // Check time-based rotation
        if let Some(interval) = self.config.rotation_interval {
            if now - state.last_rotation >= interval {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub async fn rotate_logs(&self, storage: &LogStorage) -> Result<(), LoggingError> {
        let mut state = self.state.write().await;

        // Create new log file path
        let new_log_path = self.generate_rotated_filename().await?;

        // Rotate current log
        self.perform_rotation(&new_log_path).await?;

        // Update state
        state.current_file_size = 0;
        state.last_rotation = Utc::now();
        state.rotation_count += 1;

        // Clean up old logs if needed
        if let Some(max_files) = self.config.max_files {
            self.cleanup_old_logs(max_files).await?;
        }

        Ok(())
    }

    async fn perform_rotation(&self, new_path: &PathBuf) -> Result<(), LoggingError> {
        let current_log = storage.get_current_log_path();

        // Ensure target directory exists
        if let Some(parent) = new_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                LoggingError::RotationError(format!("Failed to create directory: {}", e))
            })?;
        }

        // Rotate the file
        fs::rename(current_log, new_path)
            .await
            .map_err(|e| LoggingError::RotationError(format!("Failed to rotate log: {}", e)))?;

        // Compress if enabled
        if self.config.compression_enabled {
            self.compress_log(new_path).await?;
        }

        Ok(())
    }

    async fn compress_log(&self, path: &PathBuf) -> Result<(), LoggingError> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use tokio::io::AsyncReadExt;

        let mut file = fs::File::open(path).await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to open file for compression: {}", e))
        })?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .await
            .map_err(|e| LoggingError::RotationError(format!("Failed to read file: {}", e)))?;

        let gz_path = path.with_extension("gz");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&content)
            .map_err(|e| LoggingError::RotationError(format!("Failed to compress: {}", e)))?;

        let compressed = encoder.finish().map_err(|e| {
            LoggingError::RotationError(format!("Failed to finish compression: {}", e))
        })?;

        fs::write(&gz_path, compressed).await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to write compressed file: {}", e))
        })?;

        // Remove original file
        fs::remove_file(path).await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to remove original file: {}", e))
        })?;

        Ok(())
    }

    async fn generate_rotated_filename(&self) -> Result<PathBuf, LoggingError> {
        let base_path = storage::get_log_directory()?;
        let filename = match &self.config.rotation_format {
            RotationFormat::Timestamp => {
                format!("log.{}.log", Utc::now().timestamp())
            }
            RotationFormat::Sequential => {
                let state = self.state.read().await;
                format!("log.{}.log", state.rotation_count + 1)
            }
            RotationFormat::DateBased => {
                format!("log.{}.log", Utc::now().format("%Y%m%d-%H%M%S"))
            }
            RotationFormat::Custom(format) => format
                .replace("{timestamp}", &Utc::now().timestamp().to_string())
                .replace(
                    "{count}",
                    &self.state.read().await.rotation_count.to_string(),
                )
                .replace("{date}", &Utc::now().format("%Y%m%d").to_string()),
        };

        Ok(base_path.join(filename))
    }

    async fn cleanup_old_logs(&self, max_files: usize) -> Result<(), LoggingError> {
        let log_dir = storage::get_log_directory()?;
        let mut entries = fs::read_dir(&log_dir).await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to read log directory: {}", e))
        })?;

        let mut log_files = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to read directory entry: {}", e))
        })? {
            if let Ok(file_type) = entry.file_type().await {
                if file_type.is_file() {
                    log_files.push(entry.path());
                }
            }
        }

        // Sort by modification time
        log_files.sort_by_key(|path| {
            fs::metadata(path)
                .and_then(|meta| meta.modified())
                .unwrap_or_else(|_| std::time::SystemTime::now())
        });

        // Remove excess files
        if log_files.len() > max_files {
            for file in log_files.iter().take(log_files.len() - max_files) {
                fs::remove_file(file).await.map_err(|e| {
                    LoggingError::RotationError(format!("Failed to remove old log file: {}", e))
                })?;
            }
        }

        Ok(())
    }

    async fn get_current_log_size(&self) -> Result<u64, LoggingError> {
        let current_log = storage::get_current_log_path();
        let metadata = fs::metadata(current_log).await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to get log file metadata: {}", e))
        })?;

        Ok(metadata.len())
    }

    async fn count_existing_rotated_files(&self) -> Result<usize, LoggingError> {
        let log_dir = storage::get_log_directory()?;
        let mut count = 0;

        let mut entries = fs::read_dir(&log_dir).await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to read log directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            LoggingError::RotationError(format!("Failed to read directory entry: {}", e))
        })? {
            if let Ok(file_type) = entry.file_type().await {
                if file_type.is_file() && entry.path() != storage::get_current_log_path() {
                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

impl RotationState {
    fn new() -> Self {
        Self {
            current_file_size: 0,
            last_rotation: Utc::now(),
            rotation_count: 0,
        }
    }
}
