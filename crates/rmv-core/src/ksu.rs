use rust_i18n::t;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

use crate::error::{Result, RmvError};
use crate::quote::sh_quote;
use crate::transport::Transport;

/// Supported `KernelSU` variants and forks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KsuVariant {
    /// Official `KernelSU` by tiann.
    KernelSU,
    /// `KernelSU Next` fork with enhanced hooking.
    KernelSuNext,
    /// `SukiSU Ultra` fork for advanced patch sets.
    SukiSuUltra,
    /// `ReSukiSU` fork.
    ReSukiSu,
}

impl KsuVariant {
    /// Returns the human-readable display name.
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::KernelSU => "KernelSU",
            Self::KernelSuNext => "KernelSU Next",
            Self::SukiSuUltra => "SukiSU Ultra",
            Self::ReSukiSu => "ReSukiSU",
        }
    }

    /// Returns Android application package identifier.
    #[must_use]
    pub fn package_name(&self) -> &'static str {
        match self {
            Self::KernelSU => "me.weishu.kernelsu",
            Self::KernelSuNext => "com.rifsxd.ksunext",
            Self::SukiSuUltra => "com.sukisu.ultra",
            Self::ReSukiSu => "com.resukisu.resukisu",
        }
    }

    /// Parses a variant from a short identifier.
    #[must_use]
    pub fn from_id(id: &str) -> Self {
        match id.to_lowercase().as_str() {
            "kernelsu" | "ksu" => Self::KernelSU,
            "ksunext" | "next" => Self::KernelSuNext,
            "resukisu" => Self::ReSukiSu,
            _ => Self::SukiSuUltra,
        }
    }

    /// Returns the canonical variant identifier.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::KernelSU => "kernelsu",
            Self::KernelSuNext => "ksunext",
            Self::SukiSuUltra => "sukisu",
            Self::ReSukiSu => "resukisu",
        }
    }

    /// Returns the GitHub repository owner and repository name.
    #[must_use]
    pub fn github_repo(&self) -> (&'static str, &'static str) {
        match self {
            Self::KernelSU => ("tiann", "KernelSU"),
            Self::KernelSuNext => ("KernelSU-Next", "KernelSU-Next"),
            Self::SukiSuUltra => ("SukiSU-Ultra", "SukiSU-Ultra"),
            Self::ReSukiSu => ("ReSukiSU", "ReSukiSU"),
        }
    }

    /// Returns slice of all supported variants.
    #[must_use]
    pub fn all_variants() -> &'static [Self] {
        &[
            Self::SukiSuUltra,
            Self::KernelSuNext,
            Self::KernelSU,
            Self::ReSukiSu,
        ]
    }
}

/// `KernelSU` deployment, late-loading, and module inspection orchestrator.
pub struct KsuOrchestrator;

impl KsuOrchestrator {
    /// Checks whether `KernelSU` driver is listed in `/proc/modules`.
    ///
    /// # Errors
    /// Returns an error if transport execution fails.
    pub async fn is_module_loaded<T: Transport>(transport: &T) -> Result<bool> {
        // /proc/modules 受 SELinux 限制，需通过 root 读取
        let cmd = "sh -c 'if [ -x /data/local/tmp/rmv/su ]; then RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c \"cat /proc/modules\" 2>/dev/null; elif [ -x /data/local/tmp/su ]; then /data/local/tmp/su -c \"cat /proc/modules\" 2>/dev/null; elif [ -x /system/bin/su ]; then /system/bin/su -c \"cat /proc/modules\" 2>/dev/null; else cat /proc/modules 2>/dev/null; fi' | grep -i kernelsu";
        let out = transport.exec(cmd).await?;
        Ok(out.combined().to_lowercase().contains("kernelsu"))
    }

    /// Verifies if `KernelSU` su binary is functional and returns root context.
    ///
    /// # Errors
    /// Returns an error if transport execution fails.
    pub async fn is_ksu_functional<T: Transport>(transport: &T) -> Result<bool> {
        let cmd = "sh -c 'if [ -x /system/bin/su ]; then /system/bin/su -c id 2>/dev/null; elif command -v su >/dev/null 2>&1; then su -c id 2>/dev/null; else exit 1; fi'";
        let out = transport.exec(cmd).await?;
        Ok(out.success() && out.stdout.contains("uid=0") && out.stdout.contains("context=u:r:ksu"))
    }

    /// Ensures `/data/adb` directory exists with root ownership.
    ///
    /// # Errors
    /// Returns an error if transport execution fails.
    pub async fn ensure_data_adb_dir<T: Transport>(transport: &T) -> Result<()> {
        let cmd = r#"sh -c '
            MKDIR_CMD="mkdir -p /data/adb && chmod 700 /data/adb && chown root:root /data/adb"
            if [ -x /system/bin/su ]; then
                /system/bin/su -c "$MKDIR_CMD" 2>/dev/null
            elif [ -x /data/local/tmp/rmv/su ]; then
                RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c "$MKDIR_CMD" 2>/dev/null
            elif [ -x /data/local/tmp/su ]; then
                /data/local/tmp/su -c "$MKDIR_CMD" 2>/dev/null
            elif [ -x /apex/com.android.virt/bin/su ]; then
                /apex/com.android.virt/bin/su -c "$MKDIR_CMD" 2>/dev/null
            else
                su -c "$MKDIR_CMD" 2>/dev/null
            fi
        '"#;
        let _ = transport.exec(cmd).await;
        Ok(())
    }

    /// Enables su compatibility mode via ksud.
    ///
    /// # Errors
    /// Returns an error if transport execution fails.
    pub async fn enable_su_compat<T: Transport>(transport: &T) -> Result<bool> {
        let cmd = r#"sh -c '
            SET_CMD="if [ -x /data/adb/ksud ]; then /data/adb/ksud feature set su_compat 1; elif [ -x /data/adb/ksu/bin/ksud ]; then /data/adb/ksu/bin/ksud feature set su_compat 1; elif [ -x /data/local/tmp/rmv/ksud ]; then /data/local/tmp/rmv/ksud feature set su_compat 1; elif command -v ksud >/dev/null 2>&1; then ksud feature set su_compat 1; fi"
            if [ -x /system/bin/su ]; then
                /system/bin/su -c "$SET_CMD" 2>/dev/null
            elif command -v su >/dev/null 2>&1; then
                su -c "$SET_CMD" 2>/dev/null
            elif [ -x /data/local/tmp/rmv/su ]; then
                RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c "$SET_CMD" 2>/dev/null
            fi
        '"#;
        let _ = transport.exec(cmd).await;
        Ok(Self::is_ksu_functional(transport).await.unwrap_or(false))
    }
    /// Lists active `KernelSU` modules in `/data/adb/modules`.
    ///
    /// # Errors
    /// Returns an error if transport execution fails.
    pub async fn list_modules<T: Transport>(transport: &T) -> Result<Vec<String>> {
        if !Self::is_module_loaded(transport).await.unwrap_or(false) {
            return Ok(Vec::new());
        }

        let cmd = "sh -c 'if [ -x /system/bin/su ]; then /system/bin/su -c \"ls -1 /data/adb/modules 2>/dev/null\"; elif [ -x /data/local/tmp/rmv/su ]; then RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c \"ls -1 /data/adb/modules 2>/dev/null\"; elif [ -x /data/local/tmp/su ]; then /data/local/tmp/su -c \"ls -1 /data/adb/modules 2>/dev/null\"; else ls -1 /data/adb/modules 2>/dev/null; fi'";
        let out = transport.exec(cmd).await?;
        let modules: Vec<String> = out
            .stdout
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| {
                !s.is_empty() && !s.contains("No such file") && !s.contains("Permission denied")
            })
            .collect();
        Ok(modules)
    }
    /// Waits for Android `PackageManager` framework to become ready.
    ///
    /// # Errors
    /// Returns an error if transport execution fails.
    pub async fn wait_for_framework_ready<T: Transport>(
        transport: &T,
        timeout_sec: u64,
    ) -> Result<bool> {
        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_secs(timeout_sec);
        while start.elapsed() < timeout_dur {
            if let Ok(out) = transport.exec("pm path android 2>/dev/null").await {
                if out.success() && out.stdout.contains("package:") {
                    return Ok(true);
                }
            }
            sleep(Duration::from_millis(1500)).await;
        }
        Ok(false)
    }

    /// Ensures ksud binary is deployed and available on device.
    ///
    /// # Errors
    /// Returns an error if transport execution or extraction fails.
    pub async fn ensure_ksud_deployed<T: Transport>(
        transport: &T,
        variant: KsuVariant,
        host_manager_apk: Option<&Path>,
    ) -> Result<(String, String)> {
        // ksud 与载荷同置于 /data/local/tmp/rmv，便于 `rmv clean` 一次性清掉
        let work_dir = "/data/local/tmp/rmv";
        let default_ksud = "/data/local/tmp/rmv/ksud";

        let _ = transport
            .exec(&format!("mkdir -p {}", sh_quote(work_dir)))
            .await?;

        let check_out = transport
            .exec(&format!(
                "test -x {} && {} --version",
                sh_quote(default_ksud),
                sh_quote(default_ksud)
            ))
            .await?;
        if check_out.success() && check_out.stdout.contains("ksud") {
            return Ok((default_ksud.to_string(), variant.package_name().to_string()));
        }

        let primary_pkg = variant.package_name();

        // 1. 首选：从设备上已安装的用户指定变种 APK 中提取
        let script = format!(
            "APK=$(pm path {} 2>/dev/null | head -n 1 | cut -d: -f2); if [ -n \"$APK\" ] && [ -f \"$APK\" ]; then unzip -p \"$APK\" lib/arm64-v8a/libksud.so > {} 2>/dev/null; chmod 755 {}; test -x {} && echo \"KSUD_OK\"; fi",
            sh_quote(primary_pkg),
            sh_quote(default_ksud),
            sh_quote(default_ksud),
            sh_quote(default_ksud)
        );
        let out = transport.exec(&script).await?;
        if out.success() && out.stdout.contains("KSUD_OK") {
            return Ok((default_ksud.to_string(), primary_pkg.to_string()));
        }

        // 2. 次选：从 PC 传入或由 GitHub 下载的用户指定变种 APK 中提取
        if let Some(apk_path) = host_manager_apk {
            if apk_path.exists() {
                let remote_apk = "/data/local/tmp/rmv/manager_temp.apk";
                if transport.push(apk_path, remote_apk).await.is_ok() {
                    let extract_script = format!(
                        "unzip -p {} lib/arm64-v8a/libksud.so > {} 2>/dev/null; rm -f {}; chmod 755 {}; test -x {} && echo KSUD_OK",
                        sh_quote(remote_apk),
                        sh_quote(default_ksud),
                        sh_quote(remote_apk),
                        sh_quote(default_ksud),
                        sh_quote(default_ksud)
                    );
                    let out = transport.exec(&extract_script).await?;
                    if out.success() && out.stdout.contains("KSUD_OK") {
                        return Ok((default_ksud.to_string(), primary_pkg.to_string()));
                    }
                }
            }
        }

        // 3. 保底：指定变种在设备与本地均无，作为最后回退扫描设备其他已安装变种
        let fallback_candidates = [
            "com.rifsxd.ksunext",
            "com.sukisu.ultra",
            "me.weishu.kernelsu",
            "com.resukisu.resukisu",
        ];
        for pkg in fallback_candidates {
            if pkg != primary_pkg {
                let script = format!(
                    "APK=$(pm path {} 2>/dev/null | head -n 1 | cut -d: -f2); if [ -n \"$APK\" ] && [ -f \"$APK\" ]; then unzip -p \"$APK\" lib/arm64-v8a/libksud.so > {} 2>/dev/null; chmod 755 {}; test -x {} && echo \"KSUD_OK\"; fi",
                    sh_quote(pkg),
                    sh_quote(default_ksud),
                    sh_quote(default_ksud),
                    sh_quote(default_ksud)
                );
                let out = transport.exec(&script).await?;
                if out.success() && out.stdout.contains("KSUD_OK") {
                    return Ok((default_ksud.to_string(), pkg.to_string()));
                }
            }
        }

        Err(RmvError::KsuFailed(
            t!("error.cannot_extract_ksud", name = variant.display_name()).to_string(),
        ))
    }

    /// Performs `KernelSU` late-loading into running kernel.
    ///
    /// # Errors
    /// Returns an error if deployment, execution, or module validation fails.
    pub async fn late_load<T: Transport>(
        transport: &T,
        variant: KsuVariant,
        custom_ksud: Option<&str>,
        host_manager_apk: Option<&Path>,
    ) -> Result<()> {
        if Self::is_module_loaded(transport).await.unwrap_or(false)
            && Self::is_ksu_functional(transport).await.unwrap_or(false)
        {
            return Ok(());
        }

        let _ = Self::wait_for_framework_ready(transport, 30).await;

        let _ = Self::ensure_data_adb_dir(transport).await;

        let (ksud, pkg) = if let Some(path) = custom_ksud {
            (path.to_string(), variant.package_name().to_string())
        } else {
            Self::ensure_ksud_deployed(transport, variant, host_manager_apk).await?
        };

        let cmd = format!(
            r#"sh -c '
                [ -e /data/local/tmp/rmv/temp_su.sock ] && [ ! -e /data/local/tmp/temp_su.sock ] && ln -sf /data/local/tmp/rmv/temp_su.sock /data/local/tmp/temp_su.sock 2>/dev/null
                [ -e /data/local/tmp/rmv/su ] && [ ! -e /data/local/tmp/su ] && ln -sf /data/local/tmp/rmv/su /data/local/tmp/su 2>/dev/null

                RUN_CMD="$1 late-load --allow-shell --package-name $2"
                if [ -x /system/bin/su ]; then
                    /system/bin/su -c "$RUN_CMD"
                elif [ -x /data/local/tmp/rmv/su ]; then
                    RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c "$RUN_CMD"
                elif [ -x /data/local/tmp/su ]; then
                    /data/local/tmp/su -c "$RUN_CMD"
                elif [ -x /apex/com.android.virt/bin/su ]; then
                    /apex/com.android.virt/bin/su -c "$RUN_CMD"
                else
                    su -c "$RUN_CMD"
                fi
                echo "__RMV_RC=$?"
            ' _ {} {}"#,
            sh_quote(&ksud),
            sh_quote(&pkg)
        );
        let raw_exec = transport.exec(&cmd).await?;
        let raw_code = raw_exec.code.unwrap_or(-1);
        let raw_out = raw_exec.combined();

        let (real_code, out) = if let Some(pos) = raw_out.rfind("__RMV_RC=") {
            let rc_str = raw_out[pos + 9..].trim();
            let parsed_rc = rc_str
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .parse::<i32>()
                .unwrap_or(raw_code);
            let cleaned = raw_out[..pos].trim().to_string();
            (parsed_rc, cleaned)
        } else {
            (raw_code, raw_out.trim().to_string())
        };

        if (real_code != 0
            || out.contains("Error: Failed to install ksud")
            || out.contains("inaccessible or not found"))
            && !out.contains("already loaded")
            && !Self::is_module_loaded(transport).await.unwrap_or(false)
        {
            return Err(RmvError::KsuFailed(
                t!(
                    "error.late_load_failed",
                    code = real_code.to_string(),
                    error = out
                )
                .to_string(),
            ));
        }

        let mut loaded = false;
        for _ in 0..15 {
            sleep(Duration::from_secs(1)).await;
            if Self::is_module_loaded(transport).await.unwrap_or(false) {
                loaded = true;
                break;
            }
        }

        if !loaded {
            let out_info = if out.is_empty() {
                "none".to_string()
            } else {
                out
            };
            return Err(RmvError::KsuFailed(format!(
                "{} (late-load output: {})",
                t!("error.ksu_module_not_detected"),
                out_info
            )));
        }

        let _ = Self::enable_su_compat(transport).await;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ksu_variant_id_and_package() {
        assert_eq!(KsuVariant::from_id("sukisu"), KsuVariant::SukiSuUltra);
        assert_eq!(KsuVariant::SukiSuUltra.package_name(), "com.sukisu.ultra");

        assert_eq!(KsuVariant::from_id("kernelsu"), KsuVariant::KernelSU);
        assert_eq!(KsuVariant::KernelSU.package_name(), "me.weishu.kernelsu");
        assert_eq!(KsuVariant::KernelSU.display_name(), "KernelSU");
        assert_eq!(KsuVariant::from_id("next"), KsuVariant::KernelSuNext);
        assert_eq!(
            KsuVariant::KernelSuNext.package_name(),
            "com.rifsxd.ksunext"
        );
    }
}
