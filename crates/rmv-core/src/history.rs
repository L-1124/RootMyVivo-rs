use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    pub timestamp: String,
    pub device_model: String,
    pub device_code: String,
    pub kernel: String,
    pub payload: String,
    pub ksu_variant: String,
    pub success: bool,
    pub message: String,
    pub logs: Vec<String>,
}

pub struct HistoryManager;

impl HistoryManager {
    pub fn default_dir() -> PathBuf {
        let base = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join(".rmv").join("history")
    }

    pub async fn save_record(dir: &Path, record: &RunRecord) -> Result<PathBuf> {
        fs::create_dir_all(dir).await?;
        let filename = format!("{}_{}.json", record.timestamp.replace([':', ' '], "-"), record.id);
        let path = dir.join(filename);
        let json = serde_json::to_string_pretty(record)?;
        fs::write(&path, json).await?;
        Ok(path)
    }

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

    pub async fn clear_records(dir: &Path) -> Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(dir).await?;
        let mut count = 0;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if fs::remove_file(&path).await.is_ok() {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    pub fn current_timestamp() -> String {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = duration.as_secs();
        // 格式化为基本的 UTC 时间戳字符串
        format!("{}-epoch", secs)
    }

    pub fn new_record_id() -> String {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        format!("{:08x}", duration.subsec_millis())
    }
}
