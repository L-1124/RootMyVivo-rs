use adb_client::server_device::ADBServerDevice;
use adb_client::ADBDeviceExt;
use async_trait::async_trait;
use std::net::SocketAddrV4;
use std::path::Path;

use crate::error::{Result, RmvError};
use crate::transport::{ExecOutput, Transport};

/// Pure-Rust ADB `SmartSocket` client transport implementation.
#[derive(Debug, Clone)]
pub struct AdbClientTransport {
    /// Optional target device serial identifier.
    pub serial: Option<String>,
    /// Optional ADB server socket address override.
    pub server_addr: Option<SocketAddrV4>,
}

impl AdbClientTransport {
    /// Creates a new pure-Rust ADB client transport.
    #[must_use]
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
    async fn exec(&self, cmd: &str) -> Result<ExecOutput> {
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
            let stdout = String::from_utf8_lossy(&stdout).to_string();
            let stderr = String::from_utf8_lossy(&stderr).to_string();
            let code = exit_code.map(i32::from);
            Ok(ExecOutput {
                code,
                stdout,
                stderr,
            })
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task execution failed: {e}"),
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
                message: format!("Failed to push to {remote}: {e}"),
                code: None,
            })?;
            Ok(())
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {e}"),
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
                message: format!("Failed to pull {remote}: {e}"),
                code: None,
            })?;
            Ok(())
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {e}"),
            code: None,
        })?
    }

    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()> {
        let mut dev = self.get_device();
        let data = data.to_vec();
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || {
            let mut cursor = std::io::Cursor::new(data);
            dev.push(&mut cursor, &remote).map_err(|e| RmvError::Adb {
                message: format!("Failed to push bytes to {remote}: {e}"),
                code: None,
            })?;
            let chmod_cmd = format!("chmod {:o} {}", mode, crate::quote::sh_quote(&remote));
            let _ = dev.shell_command(&chmod_cmd, None, None);
            Ok(())
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {e}"),
            code: None,
        })?
    }

    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let mut dev = self.get_device();
        let remote = remote_path.to_string();
        tokio::task::spawn_blocking(move || {
            let mut output = Vec::new();
            dev.pull(&remote, &mut output).map_err(|e| RmvError::Adb {
                message: format!("Failed to pull bytes from {remote}: {e}"),
                code: None,
            })?;
            Ok(output)
        })
        .await
        .map_err(|e| RmvError::Adb {
            message: format!("Task join failed: {e}"),
            code: None,
        })?
    }

    async fn is_alive(&self) -> bool {
        self.exec("echo alive")
            .await
            .is_ok_and(|out| out.success() && out.stdout.contains("alive"))
    }
}
