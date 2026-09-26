use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;
use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};
use super::Transport;

#[derive(Debug, Clone)]
pub struct AdbCliTransport {
    pub serial: Option<String>,
}

impl AdbCliTransport {
    pub fn new(serial: Option<String>) -> Self {
        Self { serial }
    }

    fn base_cmd(&self) -> Command {
        let mut cmd = Command::new("adb");
        if let Some(s) = &self.serial {
            cmd.arg("-s").arg(s);
        }
        cmd
    }

    pub async fn list_devices() -> Result<Vec<String>> {
        let out = Command::new("adb")
            .arg("devices")
            .output()
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("执行 adb devices 失败，请确认 adb 已安装且在 PATH 中: {}", e),
                code: None,
            })?;

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
        let output = self.base_cmd()
            .arg("shell")
            .arg(cmd)
            .output()
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("调用 adb shell 失败: {}", e),
                code: None,
            })?;

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
        let output = self.base_cmd()
            .arg("push")
            .arg(local_path)
            .arg(remote_path)
            .output()
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("调用 adb push 失败: {}", e),
                code: None,
            })?;

        if !output.status.success() {
            return Err(RmvError::Adb {
                message: format!(
                    "adb push 失败: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                code: output.status.code(),
            });
        }
        Ok(())
    }

    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let output = self.base_cmd()
            .arg("pull")
            .arg(remote_path)
            .arg(local_path)
            .output()
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("调用 adb pull 失败: {}", e),
                code: None,
            })?;

        if !output.status.success() {
            return Err(RmvError::Adb {
                message: format!(
                    "adb pull 失败: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                code: output.status.code(),
            });
        }
        Ok(())
    }

    async fn is_alive(&self) -> bool {
        match self.base_cmd().arg("get-state").output().await {
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
                "设备处于离线状态或未授权，请检查手机屏幕上的 USB 调试授权提示".to_string(),
            ));
        }

        let (_, model) = self.exec("getprop ro.product.model").await?;
        let (_, device) = self.exec("getprop ro.product.device").await?;
        let (_, brand) = self.exec("getprop ro.product.brand").await?;
        let (_, proc_ver) = self.exec("cat /proc/version").await?;
        let (_, boot_id) = self.exec("cat /proc/sys/kernel/random/boot_id").await?;

        if proc_ver.trim().is_empty() || proc_ver.contains("device offline") {
            return Err(RmvError::DeviceNotFound("无法读取设备 /proc/version".to_string()));
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
        let output = self.base_cmd()
            .arg("reboot")
            .output()
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("执行 adb reboot 失败: {}", e),
                code: None,
            })?;

        if !output.status.success() {
            return Err(RmvError::Adb {
                message: format!(
                    "adb reboot 失败: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                code: output.status.code(),
            });
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let _ = self.base_cmd()
            .arg("wait-for-device")
            .output()
            .await;

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_sec);

        while start.elapsed() < timeout {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Ok((code, out)) = self.exec("getprop sys.boot_completed").await {
                if code == 0 && out.trim() == "1" {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    return Ok(());
                }
            }
        }

        Err(RmvError::Adb {
            message: format!("重启后等待设备就绪超时（超过 {} 秒）", timeout_sec),
            code: None,
        })
    }
}
