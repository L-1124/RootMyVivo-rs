use crate::error::Result;
#[cfg(feature = "native-wifi")]
use crate::transport::wifi::AdbWifiTransport;
#[cfg(feature = "native-usb")]
use crate::transport::AdbUsbTransport;
use crate::transport::{AdbCliTransport, Transport};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Auto,
    Usb,
    Wifi,
    Cli,
}

impl TransportMode {
    pub fn from_str_opt(s: Option<&str>) -> Self {
        match s.map(|v| v.to_ascii_lowercase()).as_deref() {
            Some("usb") => Self::Usb,
            Some("wifi") | Some("tcp") => Self::Wifi,
            Some("cli") => Self::Cli,
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
        match mode {
            TransportMode::Cli => {
                let cli = AdbCliTransport::resolve(serial).await?;
                Ok(Arc::new(cli))
            }
            #[cfg(feature = "native-usb")]
            TransportMode::Usb => {
                let usb = AdbUsbTransport::new(serial);
                usb.connect().await?;
                Ok(Arc::new(usb))
            }
            #[cfg(not(feature = "native-usb"))]
            TransportMode::Usb => {
                let cli = AdbCliTransport::resolve(serial).await?;
                Ok(Arc::new(cli))
            }
            #[cfg(feature = "native-wifi")]
            TransportMode::Wifi => {
                let wifi = AdbWifiTransport::new(serial);
                wifi.connect().await?;
                Ok(Arc::new(wifi))
            }
            #[cfg(not(feature = "native-wifi"))]
            TransportMode::Wifi => {
                let cli = AdbCliTransport::resolve(serial).await?;
                Ok(Arc::new(cli))
            }
            TransportMode::Auto => {
                // 1. If serial looks like IP:PORT, directly try Wifi
                if let Some(s) = &serial {
                    if s.contains(':')
                        && s.split(':')
                            .next()
                            .unwrap_or("")
                            .parse::<std::net::IpAddr>()
                            .is_ok()
                    {
                        #[cfg(feature = "native-wifi")]
                        {
                            let wifi = AdbWifiTransport::new(Some(s.clone()));
                            if wifi.connect().await.is_ok() {
                                return Ok(Arc::new(wifi));
                            }
                        }
                    }
                }

                // 2. Try native USB
                #[cfg(feature = "native-usb")]
                {
                    let usb = AdbUsbTransport::new(serial.clone());
                    if usb.connect().await.is_ok() {
                        return Ok(Arc::new(usb));
                    }
                }

                // 3. Try native Wi-Fi mDNS discovery
                #[cfg(feature = "native-wifi")]
                {
                    let wifi = AdbWifiTransport::new(None);
                    if wifi.connect().await.is_ok() {
                        return Ok(Arc::new(wifi));
                    }
                }

                // 4. Fallback to CLI
                let cli = AdbCliTransport::resolve(serial).await?;
                Ok(Arc::new(cli))
            }
        }
    }
}
