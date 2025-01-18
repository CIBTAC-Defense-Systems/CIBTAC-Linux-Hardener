use super::{LogCategory, LogEvent, LogLevel, LoggingError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

pub struct LogStorage {
    config: StorageConfig,
    current_file: Arc<RwLock<Option<fs::File>>>,
    index: Arc<RwLock<LogIndex>>,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub storage_path: PathBuf,
    pub index_enabled: bool,
    pub compression_enabled: bool,
    pub batch_size: usize,
    pub storage_format: StorageFormat,
}

#[derive(Debug, Clone)]
pub enum StorageFormat {
    JSON,
    CSV,
    Binary,
    Custom(String),
}

#[derive(Debug)]
struct LogIndex {
    level_index: HashMap<LogLevel, Vec<u64>>, // Offset by log level
    category_index: HashMap<LogCategory, Vec<u64>>, // Offset by category
    time_index: BTreeMap<DateTime<Utc>, u64>, // Offset by timestamp
    source_index: HashMap<String, Vec<u64>>,  // Offset by source
}

#[derive(Debug, Clone)]
pub struct LogQuery {
    pub level: Option<LogLevel>,
    pub category: Option<LogCategory>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub message_contains: Option<String>,
    pub limit: Option<usize>,
}

impl LogStorage {
    pub async fn new(config: StorageConfig) -> Result<Self, LoggingError> {
        // Ensure storage directory exists
        if let Some(parent) = config.storage_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                LoggingError::StorageError(format!("Failed to create directory: {}", e))
            })?;
        }

        let storage = Self {
            config,
            current_file: Arc::new(RwLock::new(None)),
            index: Arc::new(RwLock::new(LogIndex::new())),
        };

        Ok(storage)
    }

    pub async fn initialize(&mut self) -> Result<(), LoggingError> {
        // Open or create log file
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.storage_path)
            .await
            .map_err(|e| LoggingError::StorageError(format!("Failed to open log file: {}", e)))?;

        *self.current_file.write().await = Some(file);

        // Build index if enabled
        if self.config.index_enabled {
            self.rebuild_index().await?;
        }

        Ok(())
    }

    pub async fn store(&self, event: &LogEvent) -> Result<(), LoggingError> {
        let serialized = match self.config.storage_format {
            StorageFormat::JSON => serde_json::to_string(event).map_err(|e| {
                LoggingError::StorageError(format!("Failed to serialize event: {}", e))
            })?,
            StorageFormat::CSV => self.format_as_csv(event)?,
            StorageFormat::Binary => self.serialize_binary(event)?,
            StorageFormat::Custom(ref format) => self.custom_format(event, format)?,
        };

        // Get current position for indexing
        let position = self.get_current_position().await?;

        // Write to file
        if let Some(ref mut file) = *self.current_file.write().await {
            file.write_all(serialized.as_bytes())
                .await
                .map_err(|e| LoggingError::StorageError(format!("Failed to write log: {}", e)))?;
            file.write_all(b"\n").await.map_err(|e| {
                LoggingError::StorageError(format!("Failed to write newline: {}", e))
            })?;
        }

        // Update index
        if self.config.index_enabled {
            self.update_index(event, position).await?;
        }

        Ok(())
    }

    pub async fn query(&self, query: &LogQuery) -> Result<Vec<LogEvent>, LoggingError> {
        let mut events = Vec::new();

        if self.config.index_enabled {
            // Use index for efficient querying
            let positions = self.find_matching_positions(query).await?;
            for position in positions {
                if let Some(event) = self.read_event_at_position(position).await? {
                    events.push(event);
                }
            }
        } else {
            // Full scan if no index
            events = self.full_scan_query(query).await?;
        }

        Ok(events)
    }

    async fn full_scan_query(&self, query: &LogQuery) -> Result<Vec<LogEvent>, LoggingError> {
        let mut events = Vec::new();

        if let Some(ref file) = *self.current_file.read().await {
            use tokio::io::AsyncBufReadExt;
            let reader = tokio::io::BufReader::new(file);
            let mut lines = reader.lines();

            while let Some(line) = lines
                .next_line()
                .await
                .map_err(|e| LoggingError::StorageError(format!("Failed to read line: {}", e)))?
            {
                if let Ok(event) = self.parse_event(&line) {
                    if query.matches(&event) {
                        events.push(event);
                    }
                }
            }
        }

        Ok(events)
    }

    async fn update_index(&self, event: &LogEvent, position: u64) -> Result<(), LoggingError> {
        let mut index = self.index.write().await;

        // Update level index
        index
            .level_index
            .entry(event.level.clone())
            .or_insert_with(Vec::new)
            .push(position);

        // Update category index
        index
            .category_index
            .entry(event.category.clone())
            .or_insert_with(Vec::new)
            .push(position);

        // Update time index
        index.time_index.insert(event.timestamp, position);

        // Update source index
        index
            .source_index
            .entry(event.source.clone())
            .or_insert_with(Vec::new)
            .push(position);

        Ok(())
    }

    async fn rebuild_index(&self) -> Result<(), LoggingError> {
        let mut index = self.index.write().await;
        *index = LogIndex::new();

        let mut position = 0u64;
        let mut buffer = String::new();

        if let Some(ref mut file) = *self.current_file.write().await {
            use tokio::io::AsyncBufReadExt;
            let reader = tokio::io::BufReader::new(file);
            let mut lines = reader.lines();

            while let Some(line) = lines
                .next_line()
                .await
                .map_err(|e| LoggingError::StorageError(format!("Failed to read line: {}", e)))?
            {
                if let Ok(event) = self.parse_event(&line) {
                    // Update all indices
                    index
                        .level_index
                        .entry(event.level.clone())
                        .or_insert_with(Vec::new)
                        .push(position);

                    index
                        .category_index
                        .entry(event.category.clone())
                        .or_insert_with(Vec::new)
                        .push(position);

                    index.time_index.insert(event.timestamp, position);

                    index
                        .source_index
                        .entry(event.source.clone())
                        .or_insert_with(Vec::new)
                        .push(position);
                }

                position += line.len() as u64 + 1; // +1 for newline
            }
        }

        Ok(())
    }

    async fn find_matching_positions(&self, query: &LogQuery) -> Result<Vec<u64>, LoggingError> {
        let index = self.index.read().await;
        let mut positions = HashSet::new();
        let mut is_first = true;

        // Find matching positions from level index
        if let Some(level) = &query.level {
            let level_positions = index.level_index.get(level).cloned().unwrap_or_default();
            if is_first {
                positions.extend(level_positions);
                is_first = false;
            } else {
                positions.retain(|pos| level_positions.contains(pos));
            }
        }

        // Find matching positions from category index
        if let Some(category) = &query.category {
            let category_positions = index
                .category_index
                .get(category)
                .cloned()
                .unwrap_or_default();
            if is_first {
                positions.extend(category_positions);
                is_first = false;
            } else {
                positions.retain(|pos| category_positions.contains(pos));
            }
        }

        // Time range matching
        if let Some(start) = query.start_time {
            positions.retain(|pos| {
                if let Some(timestamp) = index
                    .time_index
                    .iter()
                    .find(|(_, &p)| p == *pos)
                    .map(|(t, _)| t)
                {
                    timestamp >= &start
                } else {
                    false
                }
            });
        }

        Ok(positions.into_iter().collect())
    }

    async fn read_event_at_position(
        &self,
        position: u64,
    ) -> Result<Option<LogEvent>, LoggingError> {
        if let Some(ref mut file) = *self.current_file.write().await {
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(position))
                .await
                .map_err(|e| LoggingError::StorageError(format!("Failed to seek: {}", e)))?;

            let mut line = String::new();
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(file);
            reader
                .read_line(&mut line)
                .await
                .map_err(|e| LoggingError::StorageError(format!("Failed to read line: {}", e)))?;

            Ok(Some(self.parse_event(&line)?))
        } else {
            Ok(None)
        }
    }

    async fn get_current_position(&self) -> Result<u64, LoggingError> {
        if let Some(ref file) = *self.current_file.read().await {
            use tokio::io::AsyncSeekExt;
            Ok(file
                .seek(std::io::SeekFrom::Current(0))
                .await
                .map_err(|e| {
                    LoggingError::StorageError(format!("Failed to get position: {}", e))
                })?)
        } else {
            Ok(0)
        }
    }

    fn format_as_csv(&self, event: &LogEvent) -> Result<String, LoggingError> {
        use csv::WriterBuilder;
        let mut writer = WriterBuilder::new().has_headers(false).from_writer(vec![]);
        writer
            .serialize(event)
            .map_err(|e| LoggingError::StorageError(format!("Failed to format CSV: {}", e)))?;

        let data =
            String::from_utf8(writer.into_inner().map_err(|e| {
                LoggingError::StorageError(format!("Failed to get CSV data: {}", e))
            })?)
            .map_err(|e| LoggingError::StorageError(format!("Invalid UTF-8: {}", e)))?;

        Ok(data)
    }

    fn serialize_binary(&self, event: &LogEvent) -> Result<String, LoggingError> {
        let binary = bincode::serialize(event).map_err(|e| {
            LoggingError::StorageError(format!("Failed to serialize binary: {}", e))
        })?;
        Ok(base64::encode(&binary))
    }

    fn custom_format(&self, event: &LogEvent, format: &str) -> Result<String, LoggingError> {
        // Implement custom formatting based on the format string
        Ok(format!("{}", event.message))
    }

    fn parse_event(&self, line: &str) -> Result<LogEvent, LoggingError> {
        match self.config.storage_format {
            StorageFormat::JSON => serde_json::from_str(line)
                .map_err(|e| LoggingError::StorageError(format!("Failed to parse JSON: {}", e))),
            StorageFormat::CSV => {
                let mut reader = csv::ReaderBuilder::new()
                    .has_headers(false)
                    .from_reader(line.as_bytes());
                reader
                    .deserialize()
                    .next()
                    .ok_or_else(|| LoggingError::StorageError("Empty CSV line".into()))?
                    .map_err(|e| LoggingError::StorageError(format!("Failed to parse CSV: {}", e)))
            }
            StorageFormat::Binary => {
                let bytes = base64::decode(line).map_err(|e| {
                    LoggingError::StorageError(format!("Failed to decode base64: {}", e))
                })?;
                bincode::deserialize(&bytes).map_err(|e| {
                    LoggingError::StorageError(format!("Failed to deserialize binary: {}", e))
                })
            }
            StorageFormat::Custom(_) => {
                // Implement custom parsing
                Err(LoggingError::StorageError(
                    "Custom format parsing not implemented".into(),
                ))
            }
        }
    }

    pub async fn store_batch(&self, events: &[LogEvent]) -> Result<(), LoggingError> {
        let mut batch = Vec::with_capacity(events.len());
        let mut positions = Vec::with_capacity(events.len());
        let current_pos = self.get_current_position().await?;
        let mut running_pos = current_pos;

        for event in events {
            let serialized = match self.config.storage_format {
                StorageFormat::JSON => serde_json::to_string(event)?,
                StorageFormat::CSV => self.format_as_csv(event)?,
                StorageFormat::Binary => self.serialize_binary(event)?,
                StorageFormat::Custom(ref format) => self.custom_format(event, format)?,
            };

            positions.push(running_pos);
            running_pos += (serialized.len() + 1) as u64; // +1 for newline
            batch.push(serialized);
        }

        // Write batch
        if let Some(ref mut file) = *self.current_file.write().await {
            for line in batch {
                file.write_all(line.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }
            file.flush().await?;
        }

        // Update indices if enabled
        if self.config.index_enabled {
            let mut index = self.index.write().await;
            for (event, position) in events.iter().zip(positions) {
                index
                    .level_index
                    .entry(event.level.clone())
                    .or_insert_with(Vec::new)
                    .push(position);

                index
                    .category_index
                    .entry(event.category.clone())
                    .or_insert_with(Vec::new)
                    .push(position);

                index.time_index.insert(event.timestamp, position);

                index
                    .source_index
                    .entry(event.source.clone())
                    .or_insert_with(Vec::new)
                    .push(position);
            }
        }

        Ok(())
    }

    pub async fn search(&self, query: &str) -> Result<Vec<LogEvent>, LoggingError> {
        let mut results = Vec::new();
        let query = query.to_lowercase();

        if let Some(ref file) = *self.current_file.read().await {
            use tokio::io::AsyncBufReadExt;
            let reader = tokio::io::BufReader::new(file);
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await? {
                if line.to_lowercase().contains(&query) {
                    if let Ok(event) = self.parse_event(&line) {
                        results.push(event);
                    }
                }
            }
        }

        Ok(results)
    }
}

impl LogIndex {
    fn new() -> Self {
        Self {
            level_index: HashMap::new(),
            category_index: HashMap::new(),
            time_index: BTreeMap::new(),
            source_index: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        self.level_index.clear();
        self.category_index.clear();
        self.time_index.clear();
        self.source_index.clear();
    }
}

impl LogQuery {
    pub fn new() -> Self {
        Self {
            level: None,
            category: None,
            start_time: None,
            end_time: None,
            source: None,
            message_contains: None,
            limit: None,
        }
    }

    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
    }

    pub fn with_category(mut self, category: LogCategory) -> Self {
        self.category = Some(category);
        self
    }

    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    pub fn matches(&self, event: &LogEvent) -> bool {
        // Level check
        if let Some(level) = &self.level {
            if &event.level != level {
                return false;
            }
        }

        // Category check
        if let Some(category) = &self.category {
            if &event.category != category {
                return false;
            }
        }

        // Time range check
        if let Some(start) = self.start_time {
            if event.timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.end_time {
            if event.timestamp > end {
                return false;
            }
        }

        // Source check
        if let Some(source) = &self.source {
            if !event.source.contains(source) {
                return false;
            }
        }

        // Message content check
        if let Some(message_contains) = &self.message_contains {
            if !event.message.contains(message_contains) {
                return false;
            }
        }

        true
    }
}
