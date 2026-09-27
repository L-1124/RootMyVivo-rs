#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use serde::{Deserialize, Serialize};
    use wasm_bindgen::prelude::*;

    #[derive(Serialize, Deserialize)]
    pub struct WasmDeviceInfo {
        pub model: String,
        pub device: String,
        pub brand: String,
        pub kernel_full: String,
        pub is_vulnerable: bool,
        pub message: String,
    }

    #[wasm_bindgen]
    pub struct RmvWebBridge {
        adb: Option<webadb_rs::wasm::Adb>,
    }

    #[wasm_bindgen]
    impl RmvWebBridge {
        #[wasm_bindgen(constructor)]
        pub fn new() -> Self {
            Self { adb: None }
        }

        /// 弹出浏览器 WebUSB 设备选择框并完成 ADB 连接与鉴权
        #[wasm_bindgen]
        pub async fn connect(&mut self) -> Result<JsValue, JsValue> {
            let mut adb = webadb_rs::wasm::Adb::new();
            let dev_info = adb.connect().await?;
            self.adb = Some(adb);
            Ok(dev_info)
        }

        /// 执行远程 shell 命令
        #[wasm_bindgen]
        pub async fn shell(&mut self, cmd: String) -> Result<String, JsValue> {
            let adb = self
                .adb
                .as_mut()
                .ok_or_else(|| JsValue::from_str("Not connected"))?;
            let output = adb.shell(cmd).await?;
            Ok(output)
        }

        /// 获取设备硬件指纹并评估 CVE 漏洞门禁
        #[wasm_bindgen]
        pub async fn check_device(&mut self) -> Result<JsValue, JsValue> {
            let adb = self
                .adb
                .as_mut()
                .ok_or_else(|| JsValue::from_str("Not connected"))?;

            let model = adb
                .shell("getprop ro.product.model".to_string())
                .await
                .unwrap_or_default()
                .trim()
                .to_string();
            let device = adb
                .shell("getprop ro.product.device".to_string())
                .await
                .unwrap_or_default()
                .trim()
                .to_string();
            let brand = adb
                .shell("getprop ro.product.brand".to_string())
                .await
                .unwrap_or_default()
                .trim()
                .to_string();
            let proc_ver = adb
                .shell("cat /proc/version".to_string())
                .await
                .unwrap_or_default()
                .trim()
                .to_string();
            let boot_id = adb
                .shell("cat /proc/sys/kernel/random/boot_id".to_string())
                .await
                .unwrap_or_default()
                .trim()
                .to_string();

            let (is_vulnerable, message) =
                match rmv_core::DeviceInfo::parse(&model, &device, &brand, &proc_ver, &boot_id) {
                    Ok(info) => match info.evaluate_gate() {
                        rmv_core::GateStatus::Vulnerable => (
                            true,
                            "Vulnerable: device can be rooted without unlocking bootloader"
                                .to_string(),
                        ),
                        rmv_core::GateStatus::Patched { reason, .. } => {
                            (false, format!("Patched: {}", reason))
                        }
                        rmv_core::GateStatus::UnsupportedVersion(v) => {
                            (false, format!("Unsupported kernel version: {}", v))
                        }
                    },
                    Err(e) => (false, e.to_string()),
                };

            let result = WasmDeviceInfo {
                model,
                device,
                brand,
                kernel_full: proc_ver,
                is_vulnerable,
                message,
            };

            serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::*;

#[cfg(not(target_arch = "wasm32"))]
pub fn wasm_only_dummy() {}
