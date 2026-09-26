use std::path::Path;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

use crate::error::{Result, RmvError};
use crate::transport::Transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KsuVariant {
    KernelSU,
    KernelSuNext,
    SukiSuUltra,
    ReSukiSu,
}

impl KsuVariant {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::KernelSU => "KernelSU (官方版)",
            Self::KernelSuNext => "KernelSU Next",
            Self::SukiSuUltra => "SukiSU Ultra",
            Self::ReSukiSu => "ReSukiSU",
        }
    }

    pub fn package_name(&self) -> &'static str {
        match self {
            Self::KernelSU => "me.weishu.kernelsu",
            Self::KernelSuNext => "com.rifsxd.ksunext",
            Self::SukiSuUltra => "com.sukisu.ultra",
            Self::ReSukiSu => "com.resukisu.resukisu",
        }
    }

    pub fn from_id(id: &str) -> Self {
        match id.to_lowercase().as_str() {
            "kernelsu" | "ksu" => Self::KernelSU,
            "ksunext" | "next" => Self::KernelSuNext,
            "resukisu" => Self::ReSukiSu,
            _ => Self::SukiSuUltra,
        }
    }
}

pub struct KsuOrchestrator;

impl KsuOrchestrator {
    pub async fn is_module_loaded<T: Transport>(transport: &T) -> Result<bool> {
        let (_, out) = transport
            .exec("cat /proc/modules 2>/dev/null | grep -i kernelsu")
            .await?;
        Ok(out.to_lowercase().contains("kernelsu"))
    }
    pub async fn wait_for_framework_ready<T: Transport>(
        transport: &T,
        timeout_sec: u64,
    ) -> Result<bool> {
        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_secs(timeout_sec);
        while start.elapsed() < timeout_dur {
            if let Ok((code, out)) = transport.exec("pm path android 2>/dev/null").await {
                if code == 0 && out.contains("package:") {
                    return Ok(true);
                }
            }
            sleep(Duration::from_millis(1500)).await;
        }
        Ok(false)
    }

    pub async fn ensure_ksud_deployed<T: Transport>(
        transport: &T,
        variant: KsuVariant,
        host_manager_apk: Option<&Path>,
    ) -> Result<String> {
        let default_ksud = "/data/local/tmp/ksud";

        let (check_code, _) = transport
            .exec(&format!("test -x {} && {} --version", default_ksud, default_ksud))
            .await?;
        if check_code == 0 {
            return Ok(default_ksud.to_string());
        }

        let primary_pkg = variant.package_name();
        let mut candidates = vec![primary_pkg];

        let all_known = [
            "com.rifsxd.ksunext",
            "com.sukisu.ultra",
            "me.weishu.kernelsu",
            "com.resukisu.resukisu",
        ];
        for k in all_known {
            if k != primary_pkg {
                candidates.push(k);
            }
        }

        for pkg in candidates {
            let script = format!(
                r#"
                APK=$(pm path {} 2>/dev/null | head -n 1 | cut -d: -f2)
                if [ -n "$APK" ] && [ -f "$APK" ]; then
                    unzip -p "$APK" lib/arm64-v8a/libksud.so > {} 2>/dev/null
                    chmod 755 {}
                    test -x {} && echo "KSUD_OK"
                fi
                "#,
                pkg, default_ksud, default_ksud, default_ksud
            );

            let (code, out) = transport.exec(&script).await?;
            if code == 0 && out.contains("KSUD_OK") {
                return Ok(default_ksud.to_string());
            }
        }

        if let Some(apk_path) = host_manager_apk {
            if apk_path.exists() {
                let remote_apk = "/data/local/tmp/manager_temp.apk";
                if transport.push(apk_path, remote_apk).await.is_ok() {
                    let extract_script = format!(
                        "unzip -p {} lib/arm64-v8a/libksud.so > {} 2>/dev/null; rm -f {}; chmod 755 {}; test -x {} && echo KSUD_OK",
                        remote_apk, default_ksud, remote_apk, default_ksud, default_ksud
                    );
                    let (code, out) = transport.exec(&extract_script).await?;
                    if code == 0 && out.contains("KSUD_OK") {
                        return Ok(default_ksud.to_string());
                    }
                }
            }
        }

        Err(RmvError::KsuFailed(format!(
            "无法在设备上定位或提取 ksud，请确认手机已安装 {} 或通过 --manager-apk 提供安装包",
            variant.display_name()
        )))
    }

    pub async fn late_load<T: Transport>(
        transport: &T,
        variant: KsuVariant,
        custom_ksud: Option<&str>,
        host_manager_apk: Option<&Path>,
    ) -> Result<()> {
        let _ = Self::wait_for_framework_ready(transport, 30).await;

        let ksud = if let Some(path) = custom_ksud {
            path.to_string()
        } else {
            Self::ensure_ksud_deployed(transport, variant, host_manager_apk).await?
        };
        let pkg = variant.package_name();

        let cmd = format!(
            r#"sh -c '
                SU_BIN="/data/local/tmp/su"
                if [ -x /apex/com.android.virt/bin/su ]; then
                    SU_BIN="/apex/com.android.virt/bin/su"
                fi
                $SU_BIN -c "{} late-load --allow-shell --package-name {}"
            '"#,
            ksud, pkg
        );
        let (code, out) = transport.exec(&cmd).await?;
        if code != 0 && !out.contains("already loaded") {
            return Err(RmvError::KsuFailed(format!(
                "执行 late-load 失败 (code {}): {}",
                code,
                out.trim()
            )));
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
            return Err(RmvError::KsuFailed(
                "late-load 命令执行完毕，但 /proc/modules 中未检测到 kernelsu 模块".to_string(),
            ));
        }

        Self::apply_su_wrapper_fix(transport).await?;

        Ok(())
    }

    pub async fn apply_su_wrapper_fix<T: Transport>(transport: &T) -> Result<()> {
        let fix_cmd = r##"
            sh -c '
                SU_BIN="su"
                if [ -x /system/bin/su ]; then
                    SU_BIN="/system/bin/su"
                elif [ -x /data/local/tmp/su ]; then
                    SU_BIN="/data/local/tmp/su"
                fi

                $SU_BIN -c "
                    if [ -d /apex/com.android.virt/bin ]; then
                        printf \"%s\n\" \"#!/system/bin/sh\" \"exec /system/bin/su \\\"\$@\\\"\" > /apex/com.android.virt/bin/su
                        chmod 755 /apex/com.android.virt/bin/su
                        chown root:root /apex/com.android.virt/bin/su
                        chcon u:object_r:system_file:s0 /apex/com.android.virt/bin/su 2>/dev/null || true
                    fi
                    if [ -f /data/local/tmp/su ]; then
                        printf \"%s\n\" \"#!/system/bin/sh\" \"exec /system/bin/su \\\"\$@\\\"\" > /data/local/tmp/su
                        chmod 755 /data/local/tmp/su
                        chown root:root /data/local/tmp/su
                        chcon u:object_r:shell_data_file:s0 /data/local/tmp/su 2>/dev/null || true
                    fi
                "
            '
        "##;
        let _ = transport.exec(fix_cmd).await;
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

        assert_eq!(KsuVariant::from_id("next"), KsuVariant::KernelSuNext);
        assert_eq!(KsuVariant::KernelSuNext.package_name(), "com.rifsxd.ksunext");
    }
}
