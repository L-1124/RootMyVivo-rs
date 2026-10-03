#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::print_stderr))]

rust_i18n::i18n!("locales", fallback = "en");
pub use rust_i18n::t;

pub mod catalog;
pub mod device;
pub mod engine;
pub mod error;
pub mod event;
pub mod history;
pub mod i18n;
pub mod ksu;
pub mod manager;
pub mod mirror;
pub mod persistence;
pub mod transport;

pub use catalog::{
    CatalogCacheMeta, CatalogConfig, CatalogUrlSource, CatalogV5, KernelBuild, PayloadFile,
    CATALOG_CACHE_MAX_AGE_SECS,
};
pub use device::{
    check_root_status, parse_root_probe, DeviceInfo, GateStatus, RootStatus, ROOT_PROBE_CMD,
};
pub use engine::{EngineOptions, ExploitEngine};
pub use error::{Result, RmvError};
pub use event::{EngineEvent, EngineStatus, LogLevel, Phase};
pub use history::{HistoryManager, RunRecord, RunStatus};
pub use i18n::{current_language, set_current_language, Language};
pub use ksu::{KsuOrchestrator, KsuVariant};
pub use manager::{get_static_asset, CachedManagerInfo, ManagerAssetInfo, ManagerDownloader};
pub use mirror::{MirrorConfig, DEFAULT_GITHUB_MIRRORS};
pub use persistence::{CleanOutcome, Persistence};
pub use transport::Transport;
pub use transport::{
    ADBServer, AdbCliTransport, AdbClientTransport, AdbMdnsDiscovery, AdbServiceKind,
    DiscoveredAdbService, TransportBuilder, TransportMode,
};
