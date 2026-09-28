rust_i18n::i18n!("locales", fallback = "en");
pub use rust_i18n::t;

#[cfg(not(target_arch = "wasm32"))]
pub mod catalog;
pub mod device;
#[cfg(not(target_arch = "wasm32"))]
pub mod engine;
pub mod error;
pub mod event;
#[cfg(not(target_arch = "wasm32"))]
pub mod history;
pub mod i18n;
#[cfg(not(target_arch = "wasm32"))]
pub mod ksu;
pub mod payload;
#[cfg(not(target_arch = "wasm32"))]
pub mod persistence;
pub mod transport;

#[cfg(not(target_arch = "wasm32"))]
pub use catalog::{CatalogV5, KernelBuild, PayloadFile};
pub use device::{
    check_root_status, parse_root_probe, DeviceInfo, GateStatus, RootStatus, ROOT_PROBE_CMD,
};
#[cfg(not(target_arch = "wasm32"))]
pub use engine::{EngineOptions, ExploitEngine};
pub use error::{Result, RmvError};
pub use event::{EngineEvent, EngineStatus, LogLevel, Phase};
#[cfg(not(target_arch = "wasm32"))]
pub use history::{HistoryManager, RunRecord};
pub use i18n::{current_language, set_current_language, Language};
#[cfg(not(target_arch = "wasm32"))]
pub use ksu::{KsuOrchestrator, KsuVariant};
pub use payload::{find_local_payload, inspect_payload, verify_payload_file, PayloadIdentity};
#[cfg(not(target_arch = "wasm32"))]
pub use persistence::{CleanOutcome, Persistence};
#[cfg(all(feature = "native-usb", not(target_arch = "wasm32")))]
pub use transport::AdbUsbTransport;
pub use transport::Transport;
#[cfg(not(target_arch = "wasm32"))]
pub use transport::{AdbCliTransport, TransportBuilder, TransportMode};
#[cfg(all(feature = "native-wifi", not(target_arch = "wasm32")))]
pub use transport::{AdbPairing, AdbWifiTransport};
