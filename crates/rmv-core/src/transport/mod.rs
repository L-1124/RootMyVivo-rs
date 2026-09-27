#[cfg(not(target_arch = "wasm32"))]
pub mod adb;
#[cfg(not(target_arch = "wasm32"))]
pub mod builder;
#[cfg(all(feature = "native-usb", not(target_arch = "wasm32")))]
pub mod usb;
#[cfg(not(target_arch = "wasm32"))]
pub mod wifi;

use crate::device::DeviceInfo;
use crate::error::Result;
use async_trait::async_trait;
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
pub use adb::AdbCliTransport;
#[cfg(not(target_arch = "wasm32"))]
pub use builder::{TransportBuilder, TransportMode};
#[cfg(all(feature = "native-usb", not(target_arch = "wasm32")))]
pub use usb::native_usb::AdbUsbTransport;
#[cfg(all(feature = "native-wifi", not(target_arch = "wasm32")))]
pub use wifi::pairing::AdbPairing;
#[cfg(all(feature = "native-wifi", not(target_arch = "wasm32")))]
pub use wifi::AdbWifiTransport;

#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait Transport: MaybeSend {
    async fn exec(&self, cmd: &str) -> Result<(i32, String)>;
    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()>;
    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()>;
    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()>;
    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>>;
    async fn is_alive(&self) -> bool;
    async fn get_device_info(&self) -> Result<DeviceInfo>;
    async fn reboot_and_wait(&self, timeout_sec: u64) -> Result<()>;
}

use std::sync::Arc;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: ?Sized + Transport> Transport for Arc<T> {
    async fn exec(&self, cmd: &str) -> Result<(i32, String)> {
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
    async fn get_device_info(&self) -> Result<DeviceInfo> {
        (**self).get_device_info().await
    }
    async fn reboot_and_wait(&self, timeout_sec: u64) -> Result<()> {
        (**self).reboot_and_wait(timeout_sec).await
    }
}
