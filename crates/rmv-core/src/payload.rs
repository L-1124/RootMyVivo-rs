use regex::bytes::Regex;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};

/// 载荷二进制内部可提取的身份信息。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PayloadIdentity {
    /// 是否内嵌了本机内核的 abogki 构建指纹（最强的“这是本机载荷”证据）。
    pub has_device_fingerprint: bool,
    /// 二进制内出现的全部 abogki 构建指纹。
    pub abogki: Vec<String>,
    /// 二进制内出现的机型构建标签（如 pd2520-bp2a.250605.031.a3）。
    pub labels: Vec<String>,
}

impl PayloadIdentity {
    /// 载荷是否自称属于别的机型（存在标签，但不含本机指纹）。
    pub fn foreign_labels(&self, device: &DeviceInfo) -> Vec<String> {
        let own = device.device.to_lowercase();
        let own_stripped = own.strip_prefix('d').unwrap_or(&own);
        self.labels
            .iter()
            .filter(|l| {
                let lower = l.to_lowercase();
                let lower_stripped = lower.strip_prefix('d').unwrap_or(&lower);
                !lower.starts_with(&own) && !lower_stripped.starts_with(own_stripped)
            })
            .cloned()
            .collect()
    }
}

/// 在载荷字节流中扫描身份特征。全部按 ASCII 子串处理，天然容忍二进制噪声。
pub fn inspect_payload(bytes: &[u8]) -> PayloadIdentity {
    let re_abogki = Regex::new(r"abogki[0-9]{6,12}").expect("static pattern");
    let re_label = Regex::new(r"(?:d?pd)[0-9]{4}[a-z0-9._-]{4,40}").expect("static pattern");

    let mut abogki: Vec<String> = re_abogki
        .find_iter(bytes)
        .filter_map(|m| std::str::from_utf8(m.as_bytes()).ok())
        .map(|s| s.to_string())
        .collect();
    abogki.sort();
    abogki.dedup();

    let mut labels: Vec<String> = re_label
        .find_iter(bytes)
        .filter_map(|m| std::str::from_utf8(m.as_bytes()).ok())
        .map(|s| s.to_string())
        .collect();
    labels.sort();
    labels.dedup();

    PayloadIdentity {
        has_device_fingerprint: false,
        abogki,
        labels,
    }
}

/// 读取载荷文件并与目标设备比对身份。
///
/// 判定：
/// - 含本机 abogki 指纹时通过（`has_device_fingerprint = true`）。
/// - 否则若含其它设备的构建标签或其它内核指纹，则拒绝下发。
/// - 两者都没有（静态库被剥离）时无法判定，放行但标记未确认。
pub fn verify_payload_file(path: &Path, device: &DeviceInfo) -> Result<PayloadIdentity> {
    let bytes = std::fs::read(path).map_err(|e| {
        RmvError::ExploitFailed(
            t!(
                "error.read_payload_failed",
                path = path.display().to_string(),
                error = e.to_string()
            )
            .to_string(),
        )
    })?;

    let mut identity = inspect_payload(&bytes);

    if let Some(own) = &device.abogki_fingerprint {
        identity.has_device_fingerprint = identity.abogki.iter().any(|a| a == own);
        if identity.has_device_fingerprint {
            return Ok(identity);
        }
        // 本机可识别指纹，但载荷内写的是别的内核构建
        if !identity.abogki.is_empty() {
            return Err(RmvError::PayloadDeviceMismatch {
                expected: own.clone(),
                found: identity.abogki.join(", "),
                labels: identity.labels.join(", "),
            });
        }
    }

    // 无指纹可依据时，退一步看机型标签是否指向别的机型
    let foreign = identity.foreign_labels(device);
    if !foreign.is_empty() {
        let expected = match &device.abogki_fingerprint {
            Some(fp) => format!("{} (内核指纹 {})", device.device, fp),
            None => device.device.clone(),
        };
        return Err(RmvError::PayloadDeviceMismatch {
            expected,
            found: foreign.join(", "),
            labels: identity.labels.join(", "),
        });
    }

    Ok(identity)
}

/// 扫描体积上限，避免误扫大型无关二进制。
const MAX_SCAN_BYTES: u64 = 32 * 1024 * 1024;

/// 目录递归深度上限。
const MAX_SCAN_DEPTH: usize = 6;

/// 归一化：只保留字母数字并转小写，用于宽松的机型名比对。
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn collect_so_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect_so_files(&path, depth + 1, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("so"))
        {
            out.push(path);
        }
    }
}

fn contains_fingerprint(path: &Path, fingerprint: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() == 0 || meta.len() > MAX_SCAN_BYTES {
        return false;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    inspect_payload(&bytes)
        .abogki
        .iter()
        .any(|a| a == fingerprint)
}

/// 在本地载荷库中查找与目标设备匹配的载荷。
///
/// 同一内核构建指纹可能对应多个机型的二进制，命中多个时按以下优先级选择：
/// 路径含机型名（market_name）> 路径含设备代号或型号 > 路径字典序最前。
pub fn find_local_payload(
    dirs: &[PathBuf],
    device: &DeviceInfo,
    market_name: Option<&str>,
) -> Option<PathBuf> {
    let fingerprint = device.abogki_fingerprint.as_deref()?;

    let mut candidates = Vec::new();
    for dir in dirs {
        collect_so_files(dir, 0, &mut candidates);
    }
    candidates.sort();
    candidates.dedup();

    let matched: Vec<PathBuf> = candidates
        .into_iter()
        .filter(|path| contains_fingerprint(path, fingerprint))
        .collect();

    if let Some(market) = market_name.map(normalize).filter(|m| !m.is_empty()) {
        if let Some(hit) = matched
            .iter()
            .find(|p| normalize(&p.to_string_lossy()).contains(&market))
        {
            return Some(hit.clone());
        }
    }

    let code = normalize(&device.device);
    let model = normalize(&device.model);
    if let Some(hit) = matched.iter().find(|p| {
        let path = normalize(&p.to_string_lossy());
        (!code.is_empty() && path.contains(&code)) || (!model.is_empty() && path.contains(&model))
    }) {
        return Some(hit.clone());
    }

    matched.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceInfo {
        DeviceInfo::parse(
            "V2408A",
            "PD2408",
            "vivo",
            "Linux version 6.6.89-android15-8-g1f71897ac249-abogki467805059-4k #1 SMP",
            "boot-x",
        )
        .unwrap()
    }

    #[test]
    fn detects_matching_fingerprint() {
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(b"...abogki467805059...");
        let id = inspect_payload(&blob);
        assert_eq!(id.abogki, vec!["abogki467805059".to_string()]);
        assert!(id.labels.is_empty());
    }

    #[test]
    fn detects_foreign_device_label() {
        let blob = b"\x00\x01pd2520-bp2a.250605.031.a3\xff".to_vec();
        let id = inspect_payload(&blob);
        assert_eq!(id.labels, vec!["pd2520-bp2a.250605.031.a3".to_string()]);
        assert_eq!(id.foreign_labels(&dev()).len(), 1);
    }

    #[test]
    fn own_device_label_is_not_foreign() {
        let blob = b"pd2408-bp2a.250605.031.a3".to_vec();
        let id = inspect_payload(&blob);
        assert!(id.foreign_labels(&dev()).is_empty());
    }

    #[test]
    fn dpd_tablet_device_label_is_not_foreign() {
        let raw = "Linux version 6.1.145-android14-11-maybe-dirty (build-user@build-host) (clang version 17.0.2) #1 SMP PREEMPT";
        let tablet = DeviceInfo::parse("iPA2556", "DPD2437", "vivo", raw, "boot-0").unwrap();
        let blob1 = b"pd2437-6.1.145-android14-11-mcast".to_vec();
        let id1 = inspect_payload(&blob1);
        assert!(id1.foreign_labels(&tablet).is_empty());

        let blob2 = b"dpd2437-6.1.145-android14-11-mcast".to_vec();
        let id2 = inspect_payload(&blob2);
        assert!(id2.foreign_labels(&tablet).is_empty());
    }

    #[test]
    fn picks_payload_by_market_name() {
        let root = std::env::temp_dir().join("rmv-payload-resolve-test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("IQOO 13")).unwrap();
        std::fs::create_dir_all(root.join("IQOO Neo11")).unwrap();

        let blob = b"pad abogki467805059 pad".to_vec();
        std::fs::write(root.join("IQOO Neo11").join("preload.so"), &blob).unwrap();
        std::fs::write(root.join("IQOO 13").join("preload.so"), &blob).unwrap();
        std::fs::write(root.join("unrelated.so"), b"pad abogki111111111 pad").unwrap();

        let found = find_local_payload(&[root.clone()], &dev(), Some("iQOO 13")).unwrap();
        assert!(
            found.to_string_lossy().contains("IQOO 13"),
            "got {}",
            found.display()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolver_returns_none_without_fingerprint_match() {
        let root = std::env::temp_dir().join("rmv-payload-resolve-none");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.so"), b"pad abogki111111111 pad").unwrap();

        assert!(find_local_payload(&[root.clone()], &dev(), Some("iQOO 13")).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }
}
