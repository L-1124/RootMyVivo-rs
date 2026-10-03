pub mod adb;
pub mod builder;
pub mod client;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutput {
    pub fn combined(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn exec(&self, cmd: &str) -> Result<ExecOutput>;
    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()>;
    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()>;
    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()>;
    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>>;
    async fn is_alive(&self) -> bool;
}

#[expect(async_fn_in_trait)]
pub trait TransportExt: Transport {
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
