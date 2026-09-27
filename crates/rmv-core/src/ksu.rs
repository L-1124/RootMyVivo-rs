use rust_i18n::t;
use serde::{Deserialize, Serialize};
use std::path::Path;
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
            .exec(&format!(
                "test -x {} && {} --version",
                default_ksud, default_ksud
            ))
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

        Err(RmvError::KsuFailed(
            t!("error.cannot_extract_ksud", name = variant.display_name()).to_string(),
        ))
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
            return Err(RmvError::KsuFailed(
                t!(
                    "error.late_load_failed",
                    code = code.to_string(),
                    error = out.trim()
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
            return Err(RmvError::KsuFailed(
                t!("error.ksu_module_not_detected").to_string(),
            ));
        }

        Self::apply_su_wrapper_fix(transport).await?;

        Ok(())
    }

    pub async fn apply_su_wrapper_fix<T: Transport>(transport: &T) -> Result<Vec<String>> {
        let (check_code, check_out) = transport.exec("/system/bin/su -c id 2>/dev/null").await?;
        if check_code != 0 || !check_out.contains("uid=0") {
            return Ok(Vec::new());
        }

        let script = r#"
            WRAPPER_B64="IyEvc3lzdGVtL2Jpbi9zaApleGVjIC9zeXN0ZW0vYmluL3N1ICIkQCIK"

            fix_if_needed() {
                TARGET="$1"
                LABEL="$2"
                DIR=$(dirname "$TARGET")
                [ ! -d "$DIR" ] && return 0

                if [ -f "$TARGET" ]; then
                    if grep -q "exec /system/bin/su" "$TARGET" 2>/dev/null && "$TARGET" -c id >/dev/null 2>&1; then
                        return 0
                    fi
                fi

                echo "$WRAPPER_B64" | base64 -d > "$TARGET" 2>/dev/null || return 0
                chmod 755 "$TARGET"
                chown root:root "$TARGET"
                [ -n "$LABEL" ] && chcon "$LABEL" "$TARGET" 2>/dev/null || true

                if "$TARGET" -c id >/dev/null 2>&1; then
                    echo "REPAIRED:$TARGET"
                fi
            }

            fix_if_needed "/apex/com.android.virt/bin/su" "u:object_r:system_file:s0"
            fix_if_needed "/data/local/tmp/su" "u:object_r:shell_data_file:s0"
        "#;

        let fix_cmd = format!("/system/bin/su -c '{}'", script.replace('\'', "'\\''"));
        let (_, out) = transport.exec(&fix_cmd).await?;

        let mut repaired = Vec::new();
        for line in out.lines() {
            if let Some(path) = line.strip_prefix("REPAIRED:") {
                repaired.push(path.trim().to_string());
            }
        }

        Ok(repaired)
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
        assert_eq!(
            KsuVariant::KernelSuNext.package_name(),
            "com.rifsxd.ksunext"
        );
    }
}
