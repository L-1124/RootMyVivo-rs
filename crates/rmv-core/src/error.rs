/// Core error enumeration encompassing transport, exploit, and supply chain failures.
#[derive(Debug, thiserror::Error)]
pub enum RmvError {
    /// Low-level ADB communication or command failure.
    #[error("ADB error: {message}")]
    Adb {
        /// Descriptive error message.
        message: String,
        /// Optional exit status code.
        code: Option<i32>,
    },
    /// Target device could not be located or identified.
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    /// Linux kernel version on device is patched or out of vulnerable range.
    #[error("Unsupported kernel version: {version} ({reason})")]
    UnsupportedKernel {
        /// Detected kernel release string.
        version: String,
        /// Evaluation rationale.
        reason: String,
    },
    /// Remote payload catalog download failed.
    #[error("Catalog fetch failed: {0}")]
    CatalogFetchFailed(String),
    /// No matching exploit payload exists in the catalog for the target device.
    #[error("Payload not found for device {device} with kernel {kernel}")]
    PayloadNotFound {
        /// Target device model code.
        device: String,
        /// Kernel build fingerprint.
        kernel: String,
    },
    /// Cryptographic checksum of downloaded asset does not match expected digest.
    #[error("Payload hash mismatch: expected {expected}, actual {actual}")]
    HashMismatch {
        /// Expected SHA-256 hex digest.
        expected: String,
        /// Computed actual SHA-256 hex digest.
        actual: String,
    },
    /// Exploit polling loop timed out before achieving root.
    #[error("Exploit timeout (last attempt: {last_attempt:?})")]
    ExploitTimeout {
        /// Last recorded exploit attempt number.
        last_attempt: Option<u32>,
        /// Tail of remote execution log.
        log_tail: String,
    },
    /// Previous exploit failure left kernel memory poisoned.
    #[error("Kernel slab memory poisoned by previous exploit; reboot required")]
    BootPoisoned,
    /// Exploit daemon process exited prematurely or returned failure.
    #[error("Exploit failed: {0}")]
    ExploitFailed(String),
    /// `KernelSU` driver loading or daemon invocation failed.
    #[error("KernelSU operation failed: {0}")]
    KsuFailed(String),
    /// Operation was cancelled by user or signal.
    #[error("Operation cancelled")]
    Cancelled,
    /// Underlying standard I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Network request failure.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// JSON serialization or deserialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl RmvError {
    /// Returns a localized user-friendly representation of the error.
    #[must_use]
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
            Self::ExploitTimeout { last_attempt, .. } => rust_i18n::t!(
                "error.exploit_timeout",
                attempts = last_attempt.map_or("-".to_string(), |a| a.to_string())
            )
            .to_string(),
            Self::BootPoisoned => rust_i18n::t!("error.boot_poisoned").to_string(),
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

/// Standard result type alias using `RmvError` as default error type.
pub type Result<T, E = RmvError> = std::result::Result<T, E>;
