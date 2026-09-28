use rust_i18n::t;
use crate::error::{Result, RmvError};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub model: String,
    pub device: String,
    pub brand: String,
    pub kernel_full: String,
    pub kernel_version: (u32, u32, u32),
    pub gki_git_id: Option<String>,
    pub abogki_fingerprint: Option<String>,
    pub boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateStatus {
    Vulnerable,
    Patched {
        version: String,
        reason: String,
    },
    UnsupportedVersion(String),
}

impl DeviceInfo {
    pub fn parse(
        model: &str,
        device: &str,
        brand: &str,
        proc_version: &str,
        boot_id: &str,
    ) -> Result<Self> {
        let (kernel_version, gki_git_id, abogki_fingerprint) =
            parse_kernel_details(proc_version)?;

        Ok(Self {
            model: model.trim().to_string(),
            device: device.trim().to_string(),
            brand: brand.trim().to_string(),
            kernel_full: proc_version.trim().to_string(),
            kernel_version,
            gki_git_id,
            abogki_fingerprint,
            boot_id: boot_id.trim().to_string(),
        })
    }

    pub fn evaluate_gate(&self) -> GateStatus {
        let (major, minor, patch) = self.kernel_version;
        let ver_str = format!("{}.{}.{}", major, minor, patch);

        match (major, minor) {
            (6, 6) => {
                if patch >= 140 {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_6_6").to_string(),
                    }
                } else if self
                    .gki_git_id
                    .as_deref()
                    .map_or(false, |g| g == "g24b70dd1cb81")
                {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_backport").to_string(),
                    }
                } else {
                    GateStatus::Vulnerable
                }
            }
            (6, 1) => {
                if patch >= 145 {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_6_1").to_string(),
                    }
                } else {
                    GateStatus::Vulnerable
                }
            }
            (6, 12) => {
                if patch >= 86 {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_6_12").to_string(),
                    }
                } else {
                    GateStatus::Vulnerable
                }
            }
            _ => GateStatus::UnsupportedVersion(ver_str),
        }
    }
}

pub fn parse_kernel_details(
    proc_version: &str,
) -> Result<((u32, u32, u32), Option<String>, Option<String>)> {
    let re_ver = Regex::new(r"Linux version (\d+)\.(\d+)\.(\d+)").unwrap();
    let caps = re_ver
        .captures(proc_version)
        .ok_or_else(|| RmvError::UnsupportedKernel {
            version: proc_version.to_string(),
            reason: "无法从 /proc/version 中提取主次版本号".to_string(),
        })?;

    let major: u32 = caps[1].parse().unwrap_or(0);
    let minor: u32 = caps[2].parse().unwrap_or(0);
    let patch: u32 = caps[3].parse().unwrap_or(0);

    let re_gki = Regex::new(r"-(g[0-9a-f]{10,14})(?:[-_\s]|$)").unwrap();
    let gki_git_id = re_gki.captures(proc_version).map(|c| c[1].to_string());

    let re_abogki = Regex::new(r"(abogki\d+)").unwrap();
    let abogki_fingerprint = re_abogki.captures(proc_version).map(|c| c[1].to_string());

    Ok(((major, minor, patch), gki_git_id, abogki_fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iqoo13_proc_version() {
        let raw = "Linux version 6.6.89-android15-8-g1f71897ac249-abogki467805059-4k (build-user@build-host) (clang version 18.0.1) #1 SMP PREEMPT Fri Aug 1 12:00:00 CST 2026";
        let dev = DeviceInfo::parse("V2408A", "pd2408", "vivo", raw, "abc-123").unwrap();

        assert_eq!(dev.kernel_version, (6, 6, 89));
        assert_eq!(dev.gki_git_id.as_deref(), Some("g1f71897ac249"));
        assert_eq!(dev.abogki_fingerprint.as_deref(), Some("abogki467805059"));
        assert_eq!(dev.evaluate_gate(), GateStatus::Vulnerable);
    }

    #[test]
    fn test_parse_patched_kernel() {
        let raw = "Linux version 6.6.140-android15-8-gabcdef123456-abogki999999999-4k (build-user@build-host) #1 SMP";
        let dev = DeviceInfo::parse("V2408A", "pd2408", "vivo", raw, "boot-0").unwrap();

        assert_eq!(dev.kernel_version, (6, 6, 140));
        match dev.evaluate_gate() {
            GateStatus::Patched { version, .. } => assert_eq!(version, "6.6.140"),
            _ => panic!("Expected GateStatus::Patched"),
        }
    }

    #[test]
    fn test_parse_backport_patched_kernel() {
        let raw = "Linux version 6.6.127-android15-8-g24b70dd1cb81 (build-user@build-host) #1 SMP";
        let dev = DeviceInfo::parse("PD2520", "pd2520", "vivo", raw, "boot-0").unwrap();

        assert_eq!(dev.kernel_version, (6, 6, 127));
        assert_eq!(dev.gki_git_id.as_deref(), Some("g24b70dd1cb81"));
        match dev.evaluate_gate() {
            GateStatus::Patched { version, reason } => {
                assert_eq!(version, "6.6.127");
                assert!(reason.contains("CVE-2026-43499"));
            }
            _ => panic!("Expected GateStatus::Patched for backported g24b70dd1cb81"),
        }
    }
}
