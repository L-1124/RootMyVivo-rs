use std::fmt;

#[derive(Debug)]
pub enum RmvError {
    Adb {
        message: String,
        code: Option<i32>,
    },
    DeviceNotFound(String),
    UnsupportedKernel {
        version: String,
        reason: String,
    },
    CatalogFetchFailed(String),
    PayloadDeviceMismatch {
        expected: String,
        found: String,
        labels: String,
    },
    PayloadNotFound {
        device: String,
        kernel: String,
    },
    HashMismatch {
        expected: String,
        actual: String,
    },
    ExploitTimeout {
        last_attempt: Option<u32>,
        log_tail: String,
    },
    ExploitFailed(String),
    KsuFailed(String),
    Cancelled,
    Io(std::io::Error),
    #[cfg(not(target_arch = "wasm32"))]
    Http(reqwest::Error),
    Json(serde_json::Error),
}

impl fmt::Display for RmvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adb { message, .. } => {
                write!(f, "{}", rust_i18n::t!("error.adb", message = message))
            }
            Self::DeviceNotFound(s) => {
                write!(
                    f,
                    "{}",
                    rust_i18n::t!("error.device_not_found", message = s)
                )
            }
            Self::UnsupportedKernel { version, reason } => {
                write!(
                    f,
                    "{}",
                    rust_i18n::t!(
                        "error.unsupported_kernel",
                        version = version,
                        reason = reason
                    )
                )
            }
            Self::CatalogFetchFailed(s) => {
                write!(
                    f,
                    "{}",
                    rust_i18n::t!("error.catalog_fetch_failed", message = s)
                )
            }
            Self::PayloadDeviceMismatch {
                expected,
                found,
                labels,
            } => {
                write!(
                    f,
                    "{}",
                    rust_i18n::t!(
                        "error.payload_device_mismatch",
                        expected = expected,
                        found = found,
                        labels = labels
                    )
                )
            }
            Self::PayloadNotFound { device, kernel } => {
                write!(
                    f,
                    "{}",
                    rust_i18n::t!("error.payload_not_found", device = device, kernel = kernel)
                )
            }
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "{}",
                    rust_i18n::t!("error.hash_mismatch", expected = expected, actual = actual)
                )
            }
            Self::ExploitTimeout { .. } => {
                write!(f, "{}", rust_i18n::t!("error.exploit_timeout"))
            }
            Self::ExploitFailed(s) => {
                write!(f, "{}", rust_i18n::t!("error.exploit_failed", message = s))
            }
            Self::KsuFailed(s) => {
                write!(f, "{}", rust_i18n::t!("error.ksu_failed", message = s))
            }
            Self::Cancelled => write!(f, "{}", rust_i18n::t!("error.cancelled")),
            Self::Io(e) => {
                let msg = e.to_string();
                write!(f, "{}", rust_i18n::t!("error.io", message = msg))
            }
            #[cfg(not(target_arch = "wasm32"))]
            Self::Http(e) => {
                let msg = e.to_string();
                write!(f, "{}", rust_i18n::t!("error.http", message = msg))
            }
            Self::Json(e) => {
                let msg = e.to_string();
                write!(f, "{}", rust_i18n::t!("error.json", message = msg))
            }
        }
    }
}

impl std::error::Error for RmvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Http(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RmvError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<reqwest::Error> for RmvError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e)
    }
}

impl From<serde_json::Error> for RmvError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub type Result<T, E = RmvError> = std::result::Result<T, E>;
