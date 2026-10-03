use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

use crate::error::Result;

/// Maximum number of historical execution logs retained.
pub const MAX_HISTORY_RECORDS: usize = 50;

/// Categorical execution outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum RunStatus {
    /// Complete exploit and `KernelSU` loading success.
    Pass,
    /// Temporary root success but skipped or failed `KernelSU`.
    Partial,
    /// Exploit failed to achieve root.
    Fail,
    /// Exploit is currently in progress.
    Running,
}

impl RunStatus {
    /// Returns the uppercase string representation of the status.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Partial => "PARTIAL",
            Self::Fail => "FAIL",
            Self::Running => "RUNNING",
        }
    }
}

/// Serialized execution history log record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunRecord {
    /// Unique run identifier.
    pub id: String,
    /// ISO-like timestamp string.
    pub timestamp: String,
    /// Target device marketing model name.
    pub device_model: String,
    /// Target device internal board code.
    pub device_code: String,
    /// Full kernel release version string.
    pub kernel: String,
    /// Applied exploit payload path or name.
    pub payload: String,
    /// Configured `KernelSU` variant.
    pub ksu_variant: String,
    /// Backward-compatible boolean success indicator.
    pub success: bool,
    /// Strongly-typed run status.
    #[serde(default)]
    pub status: Option<RunStatus>,
    /// Terminal outcome or failure explanation.
    pub message: String,
    /// Captured console output lines.
    #[serde(default)]
    pub logs: Vec<String>,
}

impl RunRecord {
    /// Resolves the effective run status, falling back to legacy `success` flag if `status` is absent.
    #[must_use]
    pub fn resolved_status(&self) -> RunStatus {
        if let Some(s) = self.status {
            s
        } else if self.success {
            RunStatus::Pass
        } else {
            RunStatus::Fail
        }
    }
}

/// Persistent execution history file manager.
pub struct HistoryManager;

impl HistoryManager {
    /// Returns default history directory path.
    #[must_use]
    pub fn default_dir() -> PathBuf {
        crate::paths::history_dir()
    }

    /// Saves a run record JSON file and prunes records exceeding capacity.
    ///
    /// # Errors
    /// Returns an error if filesystem directory creation or write fails.
    pub async fn save_record(dir: &Path, record: &RunRecord) -> Result<PathBuf> {
        fs::create_dir_all(dir).await?;
        let filename = format!(
            "{}_{}.json",
            record.timestamp.replace([':', ' '], "-"),
            record.id
        );
        let path = dir.join(filename);
        let json = serde_json::to_string_pretty(record)?;
        fs::write(&path, json).await?;

        // 自动执行老化淘汰，保持目录干净
        let _ = Self::prune_records(dir, MAX_HISTORY_RECORDS).await;

        Ok(path)
    }

    /// Lists all historical run records sorted newest-first.
    ///
    /// # Errors
    /// Returns an error if directory read fails.
    pub async fn list_records(dir: &Path) -> Result<Vec<RunRecord>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(dir).await?;
        let mut records = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path).await {
                    if let Ok(rec) = serde_json::from_str::<RunRecord>(&content) {
                        records.push(rec);
                    }
                }
            }
        }

        records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(records)
    }

    /// Retrieves a single record by exact ID or prefix.
    ///
    /// # Errors
    /// Returns an error if reading history directory fails.
    pub async fn get_record(dir: &Path, id: &str) -> Result<Option<RunRecord>> {
        let records = Self::list_records(dir).await?;
        let target = id.to_lowercase();
        // 支持完整 ID 或前缀缩写查询
        for rec in records {
            if rec.id.to_lowercase() == target || rec.id.to_lowercase().starts_with(&target) {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    /// Prunes older records keeping at most `max_keep` latest entries.
    ///
    /// # Errors
    /// Returns an error if reading history directory fails.
    pub async fn prune_records(dir: &Path, max_keep: usize) -> Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(dir).await?;
        let mut files = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(meta) = entry.metadata().await {
                    if let Ok(modified) = meta.modified() {
                        files.push((path, modified));
                    }
                }
            }
        }

        if files.len() <= max_keep {
            return Ok(0);
        }

        // 按最后修改时间降序排序
        files.sort_by_key(|a| std::cmp::Reverse(a.1));

        let mut removed = 0;
        for (path, _) in files.iter().skip(max_keep) {
            if fs::remove_file(path).await.is_ok() {
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Deletes all history records from the given directory.
    ///
    /// # Errors
    /// Returns an error if reading history directory fails.
    pub async fn clear_records(dir: &Path) -> Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(dir).await?;
        let mut count = 0;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json")
                && fs::remove_file(&path).await.is_ok()
            {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Returns current formatted timestamp.
    #[must_use]
    pub fn current_timestamp() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format_epoch_seconds(secs)
    }

    /// Generates a unique record ID: millisecond timestamp mixed with a process-wide
    /// atomic counter so concurrent fleet workers never collide within the same ms.
    #[must_use]
    pub fn new_record_id() -> String {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let millis = u32::try_from(duration.as_millis()).unwrap_or(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{:08x}", millis ^ seq.rotate_left(16))
    }
}

/// Formats Unix epoch seconds into an ISO-like UTC timestamp string (`YYYY-MM-DD HH:MM:SS`).
#[must_use]
pub fn format_epoch_seconds(epoch_secs: u64) -> String {
    let secs = epoch_secs % 60;
    let mins = (epoch_secs / 60) % 60;
    let hours = (epoch_secs / 3600) % 24;
    let mut days = epoch_secs / 86400;

    let mut year = 1970u32;
    loop {
        let leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let days_in_year: u64 = if leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1;
    for &m_days in &month_days {
        if days >= m_days {
            days -= m_days;
            month += 1;
        } else {
            break;
        }
    }
    let day = days + 1;

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}:{secs:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_epoch_seconds() {
        assert_eq!(format_epoch_seconds(0), "1970-01-01 00:00:00");
        // 2026-09-27 00:00:00 UTC = 1790467200
        let s = format_epoch_seconds(1_790_467_200);
        assert!(s.starts_with("2026-09-27"));
    }

    #[tokio::test]
    async fn test_history_save_get_prune() {
        let dir = std::env::temp_dir().join("rmv-test-hist");
        let _ = HistoryManager::clear_records(&dir).await;

        let rec = RunRecord {
            id: "a1b2c3d4".to_string(),
            timestamp: "2026-09-27 01:00:00".to_string(),
            device_model: "V2408A".to_string(),
            device_code: "PD2408".to_string(),
            kernel: "6.6.89".to_string(),
            payload: "preload.so".to_string(),
            ksu_variant: "sukisu".to_string(),
            success: true,
            status: Some(RunStatus::Pass),
            message: "ok".to_string(),
            logs: vec!["line 1".to_string(), "line 2".to_string()],
        };

        HistoryManager::save_record(&dir, &rec).await.unwrap();

        // 精确匹配
        let fetched = HistoryManager::get_record(&dir, "a1b2c3d4").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().logs.len(), 2);

        // 前缀匹配
        let fetched_short = HistoryManager::get_record(&dir, "a1b2").await.unwrap();
        assert!(fetched_short.is_some());

        let _ = HistoryManager::clear_records(&dir).await;
    }
}
