use crate::error::{Result, RmvError};
use crate::transport::Transport;
use regex::Regex;
use rust_i18n::t;
use serde::{Deserialize, Serialize};

/// Parsed hardware and kernel metadata for target device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Marketing model name (e.g. `V2324A`).
    pub model: String,
    /// Internal board device code (e.g. `PD2324`).
    pub device: String,
    /// Device manufacturer brand (e.g. `vivo` or `iQOO`).
    pub brand: String,
    /// Full raw `/proc/version` banner.
    pub kernel_full: String,
    /// Parsed semantic kernel version `(major, minor, patch)`.
    pub kernel_version: (u32, u32, u32),
    /// GKI git commit hash identifier if present.
    pub gki_git_id: Option<String>,
    /// ABOGKI Android kernel fingerprint if present.
    pub abogki_fingerprint: Option<String>,
    /// Unique kernel random boot session ID.
    pub boot_id: String,
}

/// Vulnerability assessment status for CVE-2026-43499.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GateStatus {
    /// Kernel version is vulnerable and supported.
    Vulnerable,
    /// Kernel version is patched against the vulnerability.
    Patched {
        /// Detected kernel release version.
        version: String,
        /// Patch rationale or CVE reference.
        reason: String,
    },
    /// Kernel version falls outside the target vulnerability range.
    UnsupportedVersion(String),
}

/// Current privilege escalation and root runtime status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RootStatus {
    /// 设备未获得 root 权限
    NotRooted {
        /// 是否检测到后台正在运行注入进程 (preload.so)
        exploit_running: bool,
    },
    /// 临时提权已生效 (基于漏洞 daemon 套接字 / 临时 su 客户端)
    TempRoot {
        /// 响应 uid=0 的有效 su 路径 (/data/local/tmp/su, /apex/com.android.virt/bin/su 或 su)
        su_path: String,
        /// 是否检测到后台仍有运行中的注入探测进程
        exploit_running: bool,
    },
    /// KernelSU/SukiSU 内核模块已加载并激活 (Live)
    KernelSu {
        /// 响应 uid=0 的 su 路径 (通常为 /system/bin/su)
        su_path: String,
    },
}

impl RootStatus {
    /// Returns true if either temporary root or `KernelSU` is active.
    #[must_use]
    pub fn is_rooted(&self) -> bool {
        matches!(self, Self::TempRoot { .. } | Self::KernelSu { .. })
    }

    /// Returns true if `KernelSU` kernel driver is active.
    #[must_use]
    pub fn is_kernelsu(&self) -> bool {
        matches!(self, Self::KernelSu { .. })
    }

    /// Returns true if the background exploit daemon is actively running.
    #[must_use]
    pub fn is_exploit_running(&self) -> bool {
        match self {
            Self::NotRooted { exploit_running }
            | Self::TempRoot {
                exploit_running, ..
            } => *exploit_running,
            Self::KernelSu { .. } => false,
        }
    }
    /// Returns the active working `su` path if rooted.
    #[must_use]
    pub fn su_path(&self) -> Option<&str> {
        match self {
            Self::NotRooted { .. } => None,
            Self::TempRoot { su_path, .. } | Self::KernelSu { su_path } => Some(su_path.as_str()),
        }
    }
}

/// Shell script snippet executed on device to probe root status and active daemons.
pub const ROOT_PROBE_CMD: &str = "\
    echo __RMV_KSU__; cat /proc/modules 2>/dev/null | grep -i kernelsu; \
    echo __RMV_SYS_SU__; /system/bin/su -c id 2>/dev/null; \
    echo __RMV_TMP_SU__; [ -e /data/local/tmp/rmv/temp_su.sock ] && [ ! -e /data/local/tmp/temp_su.sock ] && ln -sf /data/local/tmp/rmv/temp_su.sock /data/local/tmp/temp_su.sock 2>/dev/null; [ -e /data/local/tmp/rmv/su ] && [ ! -e /data/local/tmp/su ] && ln -sf /data/local/tmp/rmv/su /data/local/tmp/su 2>/dev/null; if [ -x /data/local/tmp/rmv/su ]; then RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c id 2>/dev/null && echo RMV_PATH_RMV; elif [ -x /data/local/tmp/su ]; then /data/local/tmp/su -c id 2>/dev/null && echo RMV_PATH_TMP; fi; \
    echo __RMV_BARE_SU__; su -c id 2>/dev/null; \
    echo __RMV_MAPS__; p=/data/local/tmp/rmv/daemon.pid; [ -f $p ] && kill -0 $(cat $p) 2>/dev/null && echo alive; \
    echo __RMV_DONE__; cat /data/local/tmp/rmv/DONE /data/local/tmp/rmv/rmv/DONE 2>/dev/null | head -n 1; \
    echo __RMV_END__";

/// Parses raw output from `ROOT_PROBE_CMD` into strongly-typed `RootStatus`.
#[must_use]
pub fn parse_root_probe(probe_output: &str) -> RootStatus {
    let ksu_part = probe_output
        .split("__RMV_KSU__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_SYS_SU__")
        .next()
        .unwrap_or("")
        .trim();

    let sys_su_part = probe_output
        .split("__RMV_SYS_SU__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_TMP_SU__")
        .next()
        .unwrap_or("")
        .trim();

    let tmp_su_part = probe_output
        .split("__RMV_TMP_SU__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_BARE_SU__")
        .next()
        .unwrap_or("")
        .trim();
    let bare_su_part = probe_output
        .split("__RMV_BARE_SU__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_MAPS__")
        .next()
        .unwrap_or("")
        .trim();

    let maps_part = probe_output
        .split("__RMV_MAPS__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_DONE__")
        .next()
        .unwrap_or("")
        .trim();

    let done_part = probe_output
        .split("__RMV_DONE__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_END__")
        .next()
        .unwrap_or("")
        .trim();

    let has_ksu_module = ksu_part.to_lowercase().contains("kernelsu");
    let sys_su_ok = sys_su_part.contains("uid=0");
    let tmp_su_ok = tmp_su_part.contains("uid=0");
    let bare_su_ok = bare_su_part.contains("uid=0");

    let has_preload_mapped = !maps_part.is_empty();
    let has_done_sentinel = done_part.contains('1') || done_part.contains("RMV_DONE");
    let exploit_running = has_preload_mapped && !has_done_sentinel;

    if sys_su_ok {
        RootStatus::KernelSu {
            su_path: "/system/bin/su".to_string(),
        }
    } else if has_ksu_module && bare_su_ok {
        RootStatus::KernelSu {
            su_path: "su".to_string(),
        }
    } else if tmp_su_ok {
        let su_path = if tmp_su_part.contains("RMV_PATH_RMV") {
            "/data/local/tmp/rmv/su".to_string()
        } else {
            "/data/local/tmp/su".to_string()
        };
        RootStatus::TempRoot {
            su_path,
            exploit_running,
        }
    } else if bare_su_ok {
        RootStatus::TempRoot {
            su_path: "su".to_string(),
            exploit_running,
        }
    } else {
        RootStatus::NotRooted { exploit_running }
    }
}

/// Probes connected device for active root status.
///
/// # Errors
/// Returns an error if transport execution fails.
pub async fn check_root_status<T: Transport>(transport: &T) -> Result<RootStatus> {
    let out = transport.exec(ROOT_PROBE_CMD).await?;
    Ok(parse_root_probe(&out.combined()))
}

impl DeviceInfo {
    /// Parses device metadata from property queries and kernel banner.
    ///
    /// # Errors
    /// Returns an error if `/proc/version` cannot be parsed.
    pub fn parse(
        model: &str,
        device: &str,
        brand: &str,
        proc_version: &str,
        boot_id: &str,
    ) -> Result<Self> {
        let (kernel_version, gki_git_id, abogki_fingerprint) = parse_kernel_details(proc_version)?;

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

    /// Evaluates device kernel against CVE-2026-43499 patch criteria.
    #[must_use]
    pub fn evaluate_gate(&self) -> GateStatus {
        let (major, minor, patch) = self.kernel_version;
        let ver_str = format!("{major}.{minor}.{patch}");

        match (major, minor) {
            (6, 6) => {
                if patch >= 140 {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_6_6").to_string(),
                    }
                } else if self.gki_git_id.as_deref() == Some("g24b70dd1cb81") {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_backport").to_string(),
                    }
                } else {
                    GateStatus::Vulnerable
                }
            }
            (6, 1) => {
                if patch >= 145 && self.gki_git_id.is_some() {
                    GateStatus::Patched {
                        version: ver_str,
                        reason: t!("gate.cve_patched_6_1").to_string(),
                    }
                } else {
                    // 6.1.145+ OEM non-GKI / "-maybe-dirty" builds (e.g. DPD2437
                    // 6.1.145-android14-11-maybe-dirty without GKI git-id) keep the
                    // vulnerable remove_waiter: verified by boot.img disassembly.
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
/// Tuple of semantic kernel version and optional commit/fingerprint tags.
pub type KernelDetails = ((u32, u32, u32), Option<String>, Option<String>);

#[expect(clippy::expect_used, reason = "Known compile-time regex literal")]
static RE_VER: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"Linux version (\d+)\.(\d+)\.(\d+)").expect("valid Linux version regex")
});
#[expect(clippy::expect_used, reason = "Known compile-time regex literal")]
static RE_GKI: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"-(g[0-9a-f]{10,14})(?:[-_\s]|$)").expect("valid GKI regex")
});
#[expect(clippy::expect_used, reason = "Known compile-time regex literal")]
static RE_ABOGKI: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(abogki\d+)").expect("valid abogki regex"));

/// Parses semantic kernel version and optional GKI/ABOGKI identifiers from `/proc/version`.
///
/// # Errors
/// Returns an error if kernel version integers cannot be parsed.
pub fn parse_kernel_details(proc_version: &str) -> Result<KernelDetails> {
    let caps = RE_VER
        .captures(proc_version)
        .ok_or_else(|| RmvError::UnsupportedKernel {
            version: proc_version.to_string(),
            reason: t!("error.kernel_version_unparseable").to_string(),
        })?;

    let major: u32 = caps[1].parse().unwrap_or(0);
    let minor: u32 = caps[2].parse().unwrap_or(0);
    let patch: u32 = caps[3].parse().unwrap_or(0);

    let gki_git_id = RE_GKI.captures(proc_version).map(|c| c[1].to_string());
    let abogki_fingerprint = RE_ABOGKI.captures(proc_version).map(|c| c[1].to_string());

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

    #[test]
    fn test_parse_dpd2437_6_1_145_vulnerable() {
        let raw = "Linux version 6.1.145-android14-11-maybe-dirty (build-user@build-host) (clang version 17.0.2) #1 SMP PREEMPT Sat Aug 1 12:00:00 CST 2026";
        let dev = DeviceInfo::parse("iPA2556", "DPD2437", "vivo", raw, "boot-0").unwrap();

        assert_eq!(dev.kernel_version, (6, 1, 145));
        assert_eq!(dev.gki_git_id, None);
        assert_eq!(dev.evaluate_gate(), GateStatus::Vulnerable);
    }

    #[test]
    fn test_parse_6_1_145_gki_patched() {
        let raw = "Linux version 6.1.145-android14-11-gabcdef123456 (build-user@build-host) #1 SMP PREEMPT";
        let dev = DeviceInfo::parse("test", "test", "test", raw, "boot-0").unwrap();

        assert_eq!(dev.kernel_version, (6, 1, 145));
        assert_eq!(dev.gki_git_id.as_deref(), Some("gabcdef123456"));
        match dev.evaluate_gate() {
            GateStatus::Patched { version, .. } => assert_eq!(version, "6.1.145"),
            _ => panic!("Expected GateStatus::Patched for canonical GKI 6.1.145+"),
        }
    }

    #[test]
    fn test_parse_root_probe_clean() {
        let raw = "\
__RMV_KSU__\n\
__RMV_SYS_SU__\n/system/bin/sh: /system/bin/su: inaccessible or not found\n\
__RMV_TMP_SU__\n/system/bin/sh: /data/local/tmp/su: not found\n\
__RMV_BARE_SU__\n/system/bin/sh: su: not found\n\
__RMV_MAPS__\n\
__RMV_DONE__\n\
__RMV_END__\n";
        let status = parse_root_probe(raw);
        assert_eq!(
            status,
            RootStatus::NotRooted {
                exploit_running: false
            }
        );
        assert!(!status.is_rooted());
        assert!(!status.is_kernelsu());
        assert!(!status.is_exploit_running());
        assert_eq!(status.su_path(), None);
    }

    #[test]
    fn test_parse_root_probe_kernelsu() {
        let raw = "\
__RMV_KSU__\nkernelsu 12345 0 - Live 0xffffff8000000000\n\
__RMV_SYS_SU__\nuid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0\n\
__RMV_TMP_SU__\nuid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0\n\
__RMV_BARE_SU__\nuid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0\n\
__RMV_MAPS__\n\
__RMV_DONE__\nRMV_DONE\n\
__RMV_END__\n";
        let status = parse_root_probe(raw);
        assert_eq!(
            status,
            RootStatus::KernelSu {
                su_path: "/system/bin/su".to_string()
            }
        );
        assert!(status.is_rooted());
        assert!(status.is_kernelsu());
        assert_eq!(status.su_path(), Some("/system/bin/su"));
    }

    #[test]
    fn test_parse_root_probe_temp_root_daemon() {
        let raw = "\
__RMV_KSU__\n\
__RMV_SYS_SU__\n\
__RMV_TMP_SU__\nuid=0(root) gid=0(root) groups=0(root) context=u:r:shell:s0\nRMV_PATH_RMV\n\
__RMV_BARE_SU__\nsu: connect daemon: Permission denied\n\
__RMV_MAPS__\n/proc/18422/maps\n\
__RMV_DONE__\n\
__RMV_END__\n";
        let status = parse_root_probe(raw);
        assert_eq!(
            status,
            RootStatus::TempRoot {
                su_path: "/data/local/tmp/rmv/su".to_string(),
                exploit_running: true,
            }
        );
        assert!(status.is_rooted());
        assert!(!status.is_kernelsu());
        assert!(status.is_exploit_running());
        assert_eq!(status.su_path(), Some("/data/local/tmp/rmv/su"));
    }

    #[test]
    fn test_parse_root_probe_exploit_running_not_rooted() {
        let raw = "\
__RMV_KSU__\n\
__RMV_SYS_SU__\n\
__RMV_TMP_SU__\n\
__RMV_BARE_SU__\n\
__RMV_MAPS__\n/proc/19321/maps\n\
__RMV_DONE__\n\
__RMV_END__\n";
        let status = parse_root_probe(raw);
        assert_eq!(
            status,
            RootStatus::NotRooted {
                exploit_running: true
            }
        );
        assert!(!status.is_rooted());
        assert!(status.is_exploit_running());
    }
}
