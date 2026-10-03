#[derive(Debug, thiserror::Error)]
pub enum RmvError {
    #[error("ADB error: {message}")]
    Adb { message: String, code: Option<i32> },
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Unsupported kernel version: {version} ({reason})")]
    UnsupportedKernel { version: String, reason: String },
    #[error("Catalog fetch failed: {0}")]
    CatalogFetchFailed(String),
    #[error("Payload not found for device {device} with kernel {kernel}")]
    PayloadNotFound { device: String, kernel: String },
    #[error("Payload hash mismatch: expected {expected}, actual {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Exploit timeout (last attempt: {last_attempt:?})")]
    ExploitTimeout {
        last_attempt: Option<u32>,
        log_tail: String,
    },
    #[error("Kernel slab memory poisoned by previous exploit; reboot required")]
    BootPoisoned,
    #[error("Device unexpectedly rebooted during exploit execution (kernel panic suspected)")]
    DeviceRebooted,
    #[error("Exploit failed: {0}")]
    ExploitFailed(String),
    #[error("KernelSU operation failed: {0}")]
    KsuFailed(String),
    #[error("Operation cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl RmvError {
    pub fn localized(&self) -> String {
        match self {
            Self::Adb { message, .. } => rust_i18n::t!("error.adb", message = message).to_string(),
            Self::DeviceNotFound(s) => {
                rust_i18n::t!("error.device_not_found", message = s).to_string()
            }
            Self::UnsupportedKernel { version, reason } => rust_i18n::t!(
                "error.unsupported_kernel",
                version = version,
                reason = reason
            )
            .to_string(),
            Self::CatalogFetchFailed(s) => {
                rust_i18n::t!("error.catalog_fetch_failed", message = s).to_string()
            }
            Self::PayloadNotFound { device, kernel } => {
                rust_i18n::t!("error.payload_not_found", device = device, kernel = kernel)
                    .to_string()
            }
            Self::HashMismatch { expected, actual } => {
                rust_i18n::t!("error.hash_mismatch", expected = expected, actual = actual)
                    .to_string()
            }
            Self::ExploitTimeout { .. } => rust_i18n::t!("error.exploit_timeout").to_string(),
            Self::BootPoisoned => rust_i18n::t!("error.boot_poisoned").to_string(),
            Self::DeviceRebooted => rust_i18n::t!("error.device_rebooted").to_string(),
            Self::ExploitFailed(s) => {
                rust_i18n::t!("error.exploit_failed", message = s).to_string()
            }
            Self::KsuFailed(s) => rust_i18n::t!("error.ksu_failed", message = s).to_string(),
            Self::Cancelled => rust_i18n::t!("error.cancelled").to_string(),
            Self::Io(e) => {
                let msg = e.to_string();
                rust_i18n::t!("error.io", message = msg).to_string()
            }
            Self::Http(e) => {
                let msg = e.to_string();
                rust_i18n::t!("error.http", message = msg).to_string()
            }
            Self::Json(e) => {
                let msg = e.to_string();
                rust_i18n::t!("error.json", message = msg).to_string()
            }
        }
    }
}

pub type Result<T, E = RmvError> = std::result::Result<T, E>;
