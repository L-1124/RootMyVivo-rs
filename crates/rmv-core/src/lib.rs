rust_i18n::i18n!("locales", fallback = "en");
pub use rust_i18n::t;

pub mod catalog;
pub mod device;
pub mod engine;
pub mod error;
pub mod event;
pub mod guard;
pub mod ksu;
pub mod payload;
pub mod persistence;
pub mod transport;
pub mod history;
pub mod i18n;

pub use catalog::{CatalogV5, KernelBuild, PayloadFile};
pub use device::{DeviceInfo, GateStatus};
pub use engine::{EngineOptions, ExploitEngine};
pub use error::{Result, RmvError};
pub use event::{EngineEvent, EngineStatus, LogLevel, Phase};
pub use ksu::{KsuOrchestrator, KsuVariant};
pub use payload::{find_local_payload, inspect_payload, verify_payload_file, PayloadIdentity};
pub use persistence::{CleanOutcome, Persistence};
pub use transport::{AdbCliTransport, Transport};
pub use history::{HistoryManager, RunRecord};
pub use guard::{BootVerdict, DirtyBoot};
pub use i18n::{current_language, set_current_language, Language};
