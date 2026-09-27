use crate::error::Result;
#[cfg(feature = "native-usb")]
use crate::transport::AdbUsbTransport;
use crate::transport::{AdbCliTransport, Transport};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Auto,
    Usb,
    Cli,
}

impl TransportMode {
    pub fn from_str_opt(s: Option<&str>) -> Self {
        match s.map(|v| v.to_ascii_lowercase()).as_deref() {
            Some("usb") => Self::Usb,
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
            TransportMode::Auto => {
                #[cfg(feature = "native-usb")]
                {
                    let usb = AdbUsbTransport::new(serial.clone());
                    if usb.connect().await.is_ok() {
                        return Ok(Arc::new(usb));
                    }
                }
                let cli = AdbCliTransport::resolve(serial).await?;
                Ok(Arc::new(cli))
            }
        }
    }
}
