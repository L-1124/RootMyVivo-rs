use crate::error::{Result, RmvError};
use crate::transport::client::AdbClientTransport;
use crate::transport::{AdbCliTransport, Transport};
use adb_client::server::ADBServer;
use rust_i18n::t;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Auto,
    Client,
    Cli,
}

impl TransportMode {
    pub fn from_str_opt(s: Option<&str>) -> Self {
        match s.map(|v| v.to_ascii_lowercase()).as_deref() {
            Some("cli") => Self::Cli,
            Some("client") | Some("server") | Some("usb") | Some("wifi") => Self::Client,
            _ => Self::Auto,
        }
    }
}

pub struct TransportBuilder;

impl TransportBuilder {
    pub async fn resolve(
        serial: Option<String>,
        mode: TransportMode,
    ) -> Result<Arc<dyn Transport>> {
        if mode == TransportMode::Cli {
            let cli = AdbCliTransport::resolve(serial).await?;
            return Ok(Arc::new(cli));
        }

        // 1. If explicit serial is provided
        if let Some(s) = &serial {
            // If serial looks like IP:port, try connect_device first if not online
            if s.contains(':') {
                if let Ok(addr) = s.parse::<std::net::SocketAddrV4>() {
                    let mut server = ADBServer::default();
                    let _ = server.connect_device(addr);
                }
            }
            let client = AdbClientTransport::new(Some(s.clone()), None);
            if client.is_alive().await {
                return Ok(Arc::new(client));
            }
        }

        // 2. Query devices from ADB server
        let mut server = ADBServer::default();
        let devices = server.devices().map_err(|e| RmvError::Adb {
            message: format!("Failed to query devices from ADB server: {}", e),
            code: None,
        })?;

        let online_devices: Vec<String> = devices
            .into_iter()
            .filter(|d| d.state == adb_client::server::DeviceState::Device)
            .map(|d| d.identifier)
            .collect();

        if online_devices.is_empty() {
            // Fallback to CLI subprocess
            if let Ok(cli) = AdbCliTransport::resolve(serial.clone()).await {
                if cli.is_alive().await {
                    return Ok(Arc::new(cli));
                }
            }
            return Err(RmvError::DeviceNotFound(
                t!("error.device_not_found_cli").to_string(),
            ));
        }

        if online_devices.len() == 1 {
            let dev = online_devices.into_iter().next().unwrap();
            let client = AdbClientTransport::new(Some(dev), None);
            return Ok(Arc::new(client));
        }
        if let Some(target) = &serial {
            if online_devices.contains(target) {
                let client = AdbClientTransport::new(Some(target.clone()), None);
                return Ok(Arc::new(client));
            }
            return Err(RmvError::DeviceNotFound(
                t!("error.device_not_found_cli").to_string(),
            ));
        }

        Err(RmvError::Adb {
            message: t!(
                "error.multiple_devices",
                devices = online_devices.join(", ")
            )
            .to_string(),
            code: None,
        })
    }

    pub async fn list_online_devices(mode: TransportMode) -> Result<Vec<(String, String)>> {
        if mode == TransportMode::Cli {
            let cli_devs = AdbCliTransport::list_devices().await.unwrap_or_default();
            return Ok(cli_devs.into_iter().map(|d| (d.clone(), d)).collect());
        }

        let mut server = ADBServer::default();
        let devices = server.devices().map_err(|e| RmvError::Adb {
            message: format!("Failed to query devices from ADB server: {}", e),
            code: None,
        })?;

        let online: Vec<String> = devices
            .into_iter()
            .filter(|d| d.state == adb_client::server::DeviceState::Device)
            .map(|d| d.identifier)
            .collect();

        if online.is_empty() {
            let cli_devs = AdbCliTransport::list_devices().await.unwrap_or_default();
            return Ok(cli_devs.into_iter().map(|d| (d.clone(), d)).collect());
        }

        let mut results = Vec::with_capacity(online.len());
        for dev in online {
            let client = AdbClientTransport::new(Some(dev.clone()), None);
            let model_desc = match tokio::time::timeout(
                std::time::Duration::from_millis(600),
                client.exec("getprop ro.product.model"),
            )
            .await
            {
                Ok(Ok((0, out))) if !out.trim().is_empty() => out.trim().to_string(),
                _ => String::new(),
            };
            results.push((dev, model_desc));
        }
        Ok(results)
    }
}
