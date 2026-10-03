/// ADB CLI subprocess transport.
pub mod adb;
/// Transport builder and multi-device resolver.
pub mod builder;
/// Pure-Rust ADB `SmartSocket` client transport.
pub mod client;
/// Android Wireless Debugging mDNS discovery.
pub mod mdns;

use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};
use async_trait::async_trait;
use rust_i18n::t;
use std::path::Path;
use std::time::Duration;

pub use adb::AdbCliTransport;
pub use adb_client::server::ADBServer;
pub use builder::{TransportBuilder, TransportMode};
pub use client::AdbClientTransport;
pub use mdns::{AdbMdnsDiscovery, AdbServiceKind, DiscoveredAdbService};

/// Standardized execution result containing exit code and streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Optional exit status code returned by the remote shell.
    pub code: Option<i32>,
    /// Standard output stream captured from the command.
    pub stdout: String,
    /// Standard error stream captured from the command.
    pub stderr: String,
}

impl ExecOutput {
    /// Returns combined stdout and stderr representation.
    #[must_use]
    pub fn combined(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }

    /// Returns true if the exit status code indicates success (0).
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Core communication trait for executing commands and transferring files.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Executes a shell command on the remote device.
    async fn exec(&self, cmd: &str) -> Result<ExecOutput>;
    /// Pushes a local file to a remote path on the device.
    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()>;
    /// Pulls a remote file from the device to a local path.
    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()>;
    /// Pushes raw bytes to a remote path with the specified permission bits.
    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()>;
    /// Pulls raw bytes from a remote path on the device.
    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>>;
    /// Verifies if the device connection is responsive.
    async fn is_alive(&self) -> bool;
}

/// Extension trait providing high-level device inspection and lifecycle operations.
#[expect(
    async_fn_in_trait,
    reason = "Only consumed through generic bounds; every implementor is Send + Sync"
)]
pub trait TransportExt: Transport {
    /// Inspects and parses device metadata from system properties and `/proc/version`.
    async fn get_device_info(&self) -> Result<DeviceInfo> {
        if !self.is_alive().await {
            return Err(RmvError::DeviceNotFound(
                t!("error.device_offline").to_string(),
            ));
        }
        let model = self.exec("getprop ro.product.model").await?.stdout;
        let device = self.exec("getprop ro.product.device").await?.stdout;
        let brand = self.exec("getprop ro.product.brand").await?.stdout;
        let proc_ver = self.exec("cat /proc/version").await?.combined();
        let boot_id = self
            .exec("cat /proc/sys/kernel/random/boot_id")
            .await?
            .stdout;
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

    /// Reboots the device and awaits boot completion within `timeout_secs`.
    async fn reboot_and_wait(&self, timeout_secs: u64) -> Result<()> {
        let initial_boot_id = self
            .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
            .await
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_default();
        let reboot_res = self.exec("reboot").await;
        if let Ok(out) = &reboot_res {
            if out.code.is_some() && out.code != Some(0) {
                return Err(RmvError::Adb {
                    message: t!(
                        "error.adb_cmd_failed",
                        action = "reboot",
                        error = format!("exit code {:?}", out.code)
                    )
                    .to_string(),
                    code: out.code,
                });
            }
        }
        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_secs(timeout_secs);
        while start.elapsed() < timeout_dur {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok(out) = self
                .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
                .await
            {
                let cur = out.stdout.trim();
                if !cur.is_empty() && cur != initial_boot_id {
                    if let Ok(comp) = self.exec("getprop sys.boot_completed").await {
                        if comp.stdout.trim() == "1" {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(RmvError::Adb {
            message: t!("error.reboot_timeout", seconds = timeout_secs.to_string()).to_string(),
            code: None,
        })
    }
}

impl<T: Transport + ?Sized> TransportExt for T {}

use std::sync::Arc;

#[async_trait]
impl<T: ?Sized + Transport> Transport for Arc<T> {
    async fn exec(&self, cmd: &str) -> Result<ExecOutput> {
        (**self).exec(cmd).await
    }
    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        (**self).push(local_path, remote_path).await
    }
    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        (**self).pull(remote_path, local_path).await
    }
    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()> {
        (**self).push_bytes(data, remote_path, mode).await
    }
    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        (**self).pull_bytes(remote_path).await
    }
    async fn is_alive(&self) -> bool {
        (**self).is_alive().await
    }
}
