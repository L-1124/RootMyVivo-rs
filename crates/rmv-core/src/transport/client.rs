use adb_client::server_device::ADBServerDevice;
use adb_client::ADBDeviceExt;
use async_trait::async_trait;
use std::net::SocketAddrV4;
use std::path::Path;

use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};
use crate::transport::Transport;

#[derive(Debug, Clone)]
pub struct AdbClientTransport {
    pub serial: Option<String>,
    pub server_addr: Option<SocketAddrV4>,
}

impl AdbClientTransport {
    pub fn new(serial: Option<String>, server_addr: Option<SocketAddrV4>) -> Self {
        Self {
            serial,
            server_addr,
        }
    }

    fn get_device(&self) -> ADBServerDevice {
        if let Some(s) = &self.serial {
            ADBServerDevice::new(s.clone(), self.server_addr)
        } else {
            ADBServerDevice::autodetect(self.server_addr)
        }
    }
}

#[async_trait]
impl Transport for AdbClientTransport {
    async fn exec(&self, cmd: &str) -> Result<(i32, String)> {
        let mut dev = self.get_device();
        let cmd = cmd.to_string();
        tokio::task::spawn_blocking(move || {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit_code = dev
                .shell_command(&cmd, Some(&mut stdout), Some(&mut stderr))
                .map_err(|e| RmvError::Adb {
                    message: e.to_string(),
                    code: None,
                })?;
            let mut combined = String::from_utf8_lossy(&stdout).to_string();
            if !stderr.is_empty() {
                combined.push_str(&String::from_utf8_lossy(&stderr));
            }
            Ok((exit_code.unwrap_or(0) as i32, combined))
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task execution failed: {}", e),
            code: None,
        })?
    }

    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        let mut dev = self.get_device();
        let local = local_path.to_path_buf();
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::open(&local).map_err(RmvError::Io)?;
            dev.push(&mut file, &remote).map_err(|e| RmvError::Adb {
                message: format!("Failed to push to {}: {}", remote, e),
                code: None,
            })?;
            Ok(())
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {}", e),
            code: None,
        })?
    }

    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let mut dev = self.get_device();
        let local = local_path.to_path_buf();
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::create(&local).map_err(RmvError::Io)?;
            dev.pull(&remote, &mut file).map_err(|e| RmvError::Adb {
                message: format!("Failed to pull {}: {}", remote, e),
                code: None,
            })?;
            Ok(())
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {}", e),
            code: None,
        })?
    }

    async fn push_bytes(&self, data: &[u8], remote_path: &str, _mode: u32) -> Result<()> {
        let mut dev = self.get_device();
        let data = data.to_vec();
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || {
            let mut cursor = std::io::Cursor::new(data);
            dev.push(&mut cursor, &remote).map_err(|e| RmvError::Adb {
                message: format!("Failed to push bytes to {}: {}", remote, e),
                code: None,
            })?;
            Ok(())
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {}", e),
            code: None,
        })?
    }

    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let mut dev = self.get_device();
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || {
            let mut output = Vec::new();
            dev.pull(&remote, &mut output).map_err(|e| RmvError::Adb {
                message: format!("Failed to pull bytes from {}: {}", remote, e),
                code: None,
            })?;
            Ok(output)
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {}", e),
            code: None,
        })?
    }

    async fn is_alive(&self) -> bool {
        self.exec("echo alive")
            .await
            .map_or(false, |(c, s)| c == 0 && s.contains("alive"))
    }

    async fn get_device_info(&self) -> Result<DeviceInfo> {
        let (_, model) = self.exec("getprop ro.product.model").await?;
        let (_, device) = self.exec("getprop ro.product.device").await?;
        let (_, brand) = self.exec("getprop ro.product.brand").await?;
        let (_, proc_version) = self.exec("cat /proc/version").await?;
        let (_, boot_id) = self.exec("cat /proc/sys/kernel/random/boot_id").await?;

        DeviceInfo::parse(
            model.trim(),
            device.trim(),
            brand.trim(),
            proc_version.trim(),
            boot_id.trim(),
        )
    }

    async fn reboot_and_wait(&self, timeout_sec: u64) -> Result<()> {
        let _ = self.exec("reboot").await;
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let start = std::time::Instant::now();
        let timeout_dur = std::time::Duration::from_secs(timeout_sec);
        while start.elapsed() < timeout_dur {
            if self.is_alive().await {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        Err(RmvError::Adb {
            message: "Device reboot timeout".to_string(),
            code: None,
        })
    }
}
