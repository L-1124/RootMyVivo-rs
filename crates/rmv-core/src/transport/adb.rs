use async_trait::async_trait;
use rust_i18n::t;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use super::Transport;
use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};

async fn run_cmd_with_timeout(
    mut cmd: Command,
    dur: Duration,
    action_desc: &str,
) -> Result<std::process::Output> {
    match timeout(dur, cmd.output()).await {
        Ok(res) => res.map_err(|e| RmvError::Adb {
            message: t!(
                "error.adb_failed",
                action = action_desc,
                error = e.to_string()
            )
            .to_string(),
            code: None,
        }),
        Err(_) => Err(RmvError::Adb {
            message: t!(
                "error.adb_timeout",
                action = action_desc,
                seconds = dur.as_secs().to_string()
            )
            .to_string(),
            code: None,
        }),
    }
}

#[derive(Debug, Clone)]
pub struct AdbCliTransport {
    pub serial: Option<String>,
}

impl AdbCliTransport {
    pub fn new(serial: Option<String>) -> Self {
        Self { serial }
    }

    pub async fn resolve(serial: Option<String>) -> Result<Self> {
        if let Some(s) = serial {
            return Ok(Self::new(Some(s)));
        }

        let devices = Self::list_devices().await.unwrap_or_default();
        if devices.len() == 1 {
            Ok(Self::new(Some(devices[0].clone())))
        } else if devices.len() > 1 {
            Err(RmvError::Adb {
                message: t!("error.multiple_devices", devices = devices.join(", ")).to_string(),
                code: None,
            })
        } else {
            Ok(Self::new(None))
        }
    }

    fn base_cmd(&self) -> Command {
        let mut cmd = Command::new("adb");
        if let Some(s) = &self.serial {
            cmd.arg("-s").arg(s);
        }
        cmd
    }

    pub async fn list_devices() -> Result<Vec<String>> {
        let mut cmd = Command::new("adb");
        cmd.arg("devices");
        let out = run_cmd_with_timeout(cmd, Duration::from_secs(8), "devices").await?;

        let text = String::from_utf8_lossy(&out.stdout);
        let mut devices = Vec::new();
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "device" {
                devices.push(parts[0].to_string());
            }
        }
        Ok(devices)
    }
}

#[async_trait]
impl Transport for AdbCliTransport {
    async fn exec(&self, cmd: &str) -> Result<(i32, String)> {
        let mut adb_cmd = self.base_cmd();
        adb_cmd.arg("shell").arg(cmd);

        let output = run_cmd_with_timeout(adb_cmd, Duration::from_secs(45), "shell").await?;

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let combined = if stderr.is_empty() {
            stdout
        } else if stdout.is_empty() {
            stderr
        } else {
            format!("{}\n{}", stdout, stderr)
        };

        Ok((code, combined))
    }

    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        let mut adb_cmd = self.base_cmd();
        adb_cmd.arg("push").arg(local_path).arg(remote_path);

        let output = run_cmd_with_timeout(adb_cmd, Duration::from_secs(60), "push").await?;

        if !output.status.success() {
            return Err(RmvError::Adb {
                message: t!(
                    "error.adb_cmd_failed",
                    action = "push",
                    error = String::from_utf8_lossy(&output.stderr).trim()
                )
                .to_string(),
                code: output.status.code(),
            });
        }
        Ok(())
    }

    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let mut adb_cmd = self.base_cmd();
        adb_cmd.arg("pull").arg(remote_path).arg(local_path);

        let output = run_cmd_with_timeout(adb_cmd, Duration::from_secs(60), "pull").await?;

        if !output.status.success() {
            return Err(RmvError::Adb {
                message: t!(
                    "error.adb_cmd_failed",
                    action = "pull",
                    error = String::from_utf8_lossy(&output.stderr).trim()
                )
                .to_string(),
                code: output.status.code(),
            });
        }
        Ok(())
    }
    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()> {
        let temp_dir = std::env::temp_dir().join("rmv-push-tmp");
        tokio::fs::create_dir_all(&temp_dir).await.ok();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let file_name = format!("push_{}_{}", std::process::id(), nanos);
        let temp_file = temp_dir.join(file_name);
        tokio::fs::write(&temp_file, data).await?;
        let res = self.push(&temp_file, remote_path).await;
        let _ = tokio::fs::remove_file(&temp_file).await;
        if res.is_ok() && mode != 0 {
            let _ = self
                .exec(&format!("chmod {:o} {}", mode, remote_path))
                .await;
        }
        res
    }

    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let temp_dir = std::env::temp_dir().join("rmv-pull-tmp");
        tokio::fs::create_dir_all(&temp_dir).await.ok();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let file_name = format!("pull_{}_{}", std::process::id(), nanos);
        let temp_file = temp_dir.join(file_name);
        self.pull(remote_path, &temp_file).await?;
        let data = tokio::fs::read(&temp_file).await?;
        let _ = tokio::fs::remove_file(&temp_file).await;
        Ok(data)
    }

    async fn is_alive(&self) -> bool {
        let mut adb_cmd = self.base_cmd();
        adb_cmd.arg("get-state");
        match run_cmd_with_timeout(adb_cmd, Duration::from_secs(5), "get-state").await {
            Ok(out) => {
                let state = String::from_utf8_lossy(&out.stdout);
                state.trim() == "device"
            }
            Err(_) => false,
        }
    }

    async fn get_device_info(&self) -> Result<DeviceInfo> {
        if !self.is_alive().await {
            return Err(RmvError::DeviceNotFound(
                t!("error.device_offline").to_string(),
            ));
        }

        let (_, model) = self.exec("getprop ro.product.model").await?;
        let (_, device) = self.exec("getprop ro.product.device").await?;
        let (_, brand) = self.exec("getprop ro.product.brand").await?;
        let (_, proc_ver) = self.exec("cat /proc/version").await?;
        let (_, boot_id) = self.exec("cat /proc/sys/kernel/random/boot_id").await?;

        if proc_ver.trim().is_empty() || proc_ver.contains("device offline") {
            return Err(RmvError::DeviceNotFound(
                t!("error.cannot_read_proc_version").to_string(),
            ));
        }

        DeviceInfo::parse(
            model.trim(),
            device.trim(),
            brand.trim(),
            proc_ver.trim(),
            boot_id.trim(),
        )
    }

    async fn reboot_and_wait(&self, timeout_sec: u64) -> Result<()> {
        let initial_boot_id = self
            .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
            .await
            .map(|(_, out)| out.trim().to_string())
            .unwrap_or_default();

        let mut reboot_cmd = self.base_cmd();
        reboot_cmd.arg("reboot");
        let output = run_cmd_with_timeout(reboot_cmd, Duration::from_secs(10), "reboot").await?;

        if !output.status.success() {
            return Err(RmvError::Adb {
                message: t!(
                    "error.adb_cmd_failed",
                    action = "reboot",
                    error = String::from_utf8_lossy(&output.stderr).trim()
                )
                .to_string(),
                code: output.status.code(),
            });
        }

        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_secs(timeout_sec);

        // 1. 等待设备断开或初始会话失效
        while start.elapsed() < Duration::from_secs(30) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Ok((code, out)) = self
                .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
                .await
            {
                let cur = out.trim();
                if code != 0
                    || cur.is_empty()
                    || (!initial_boot_id.is_empty() && cur != initial_boot_id)
                {
                    break;
                }
            } else {
                break;
            }
        }

        // 2. 等待 adbd 重连，且确认 boot_id 确实已改变
        let mut new_session_online = false;
        while start.elapsed() < timeout_dur {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok((code, out)) = self
                .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
                .await
            {
                let cur = out.trim();
                if code == 0 && !cur.is_empty() {
                    if initial_boot_id.is_empty() || cur != initial_boot_id {
                        new_session_online = true;
                        break;
                    }
                }
            }
        }

        if !new_session_online {
            return Err(RmvError::Adb {
                message: t!("error.reboot_timeout", seconds = timeout_sec.to_string()).to_string(),
                code: None,
            });
        }

        // 3. 等待 Android 框架系统完全启动 (sys.boot_completed == 1)
        while start.elapsed() < timeout_dur {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok((code, out)) = self.exec("getprop sys.boot_completed").await {
                if code == 0 && out.trim() == "1" {
                    break;
                }
            }
        }

        // 4. 等待包管理器与系统服务就绪 (pm path android)
        while start.elapsed() < timeout_dur {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Ok((code, out)) = self.exec("pm path android 2>/dev/null").await {
                if code == 0 && out.contains("package:") {
                    break;
                }
            }
        }

        // 5. 静默等待 5 秒
        tokio::time::sleep(Duration::from_secs(5)).await;

        Ok(())
    }
}
