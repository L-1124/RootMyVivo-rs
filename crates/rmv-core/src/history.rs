use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

use crate::error::Result;

pub const MAX_HISTORY_RECORDS: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default)]
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
        files.sort_by(|a, b| b.1.cmp(&a.1));

        let mut removed = 0;
        for (path, _) in files.iter().skip(max_keep) {
            if fs::remove_file(path).await.is_ok() {
                removed += 1;
            }
        }

        Ok(removed)
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
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format_epoch_seconds(secs)
    }

    pub fn new_record_id() -> String {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let millis = duration.as_millis();
        format!("{:08x}", (millis & 0xffff_ffff) as u32)
    }
}

pub fn format_epoch_seconds(epoch_secs: u64) -> String {
    let secs = epoch_secs % 60;
    let mins = (epoch_secs / 60) % 60;
    let hours = (epoch_secs / 3600) % 24;
    let mut days = (epoch_secs / 86400) as i64;

    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
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

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, mins, secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_epoch_seconds() {
        assert_eq!(format_epoch_seconds(0), "1970-01-01 00:00:00");
        // 2026-09-27 00:00:00 UTC = 1790467200
        let s = format_epoch_seconds(1790467200);
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
