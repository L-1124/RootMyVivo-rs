use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// 失败提权留下的脏 boot：载荷劫持过内核 boot_id 缓冲区且未还原。
/// 同一 boot 内重试会导致新启动的应用崩溃，故失败后必须重启。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirtyBoot {
    pub boot_id: String,
    pub reason: String,
    pub at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootVerdict {
    Clean,
    Poisoned(String),
}

pub fn default_state_path() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(".rmv").join("state.json")
}

pub fn load_at(path: &Path) -> Option<DirtyBoot> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save_at(path: &Path, dirty: &DirtyBoot) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(dirty)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn clear_at(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// 当前 boot 是否已被上一次失败的提权污染。
pub fn check_at(path: &Path, current_boot_id: &str) -> BootVerdict {
    match load_at(path) {
        Some(d) if !current_boot_id.is_empty() && d.boot_id == current_boot_id => {
            BootVerdict::Poisoned(d.reason)
        }
        _ => BootVerdict::Clean,
    }
}

pub fn check(current_boot_id: &str) -> BootVerdict {
    check_at(&default_state_path(), current_boot_id)
}

pub fn save(dirty: &DirtyBoot) -> Result<()> {
    save_at(&default_state_path(), dirty)
}

pub fn clear() {
    clear_at(&default_state_path())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 载荷运行前后 boot_id 不一致：内核缓冲区被改写且未还原。
pub fn boot_id_tampered(before: &str, after: &str) -> bool {
    !before.is_empty() && !after.is_empty() && before != after
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rmv-guard-{}.json", tag))
    }

    #[test]
    fn round_trip_and_poison_detection() {
        let path = tmp_path("roundtrip");
        clear_at(&path);

        // 未记录 → 干净
        assert_eq!(check_at(&path, "boot-A"), BootVerdict::Clean);

        save_at(
            &path,
            &DirtyBoot {
                boot_id: "boot-A".to_string(),
                reason: "exploit failed".to_string(),
                at_unix: 1,
            },
        )
        .unwrap();

        // 同一 boot → 判定为污染
        assert_eq!(
            check_at(&path, "boot-A"),
            BootVerdict::Poisoned("exploit failed".to_string())
        );
        // 换 boot（已重启）→ 干净
        assert_eq!(check_at(&path, "boot-B"), BootVerdict::Clean);

        clear_at(&path);
        assert_eq!(load_at(&path), None);
    }

    #[test]
    fn empty_boot_id_is_never_poisoned() {
        let path = tmp_path("empty");
        clear_at(&path);
        save_at(
            &path,
            &DirtyBoot {
                boot_id: "boot-A".to_string(),
                reason: "x".to_string(),
                at_unix: 0,
            },
        )
        .unwrap();
        assert_eq!(check_at(&path, ""), BootVerdict::Clean);
        clear_at(&path);
    }

    #[test]
    fn tamper_detection() {
        assert!(boot_id_tampered(
            "68ba44e3-ef9f-4187-9bc2-6dad2b24bdd7",
            "682230d3-d7ff-ffff-c088-222a80ffffff"
        ));
        assert!(!boot_id_tampered("same", "same"));
        assert!(!boot_id_tampered("", "anything"));
    }
}
