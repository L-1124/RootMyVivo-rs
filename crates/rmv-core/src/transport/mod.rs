pub mod adb;

use std::path::Path;
use async_trait::async_trait;
use crate::device::DeviceInfo;
use crate::error::Result;

pub use adb::AdbCliTransport;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn exec(&self, cmd: &str) -> Result<(i32, String)>;
    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()>;
    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()>;
    async fn is_alive(&self) -> bool;
    async fn get_device_info(&self) -> Result<DeviceInfo>;
    async fn reboot_and_wait(&self, timeout_sec: u64) -> Result<()>;
}
