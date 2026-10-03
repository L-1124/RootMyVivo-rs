//! `RootMyVivo` core library providing device gating, payload catalog resolution,
//! exploit orchestration, and `KernelSU` late-loading for bootloader-locked vivo/iQOO devices.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::print_stderr))]

rust_i18n::i18n!("locales", fallback = "en");
pub use rust_i18n::t;

/// Payload catalog management and local cache operations.
pub mod catalog;
/// Device property inspection and vulnerability gate evaluation.
pub mod device;
/// Exploit execution pipeline and state machine orchestration.
pub mod engine;
/// Strongly-typed error definitions and localization.
pub mod error;
/// Pipeline event definitions and status reporting.
pub mod event;
/// Exploit execution history recording and analytics.
pub mod history;
/// Localization runtime and system language detection.
pub mod i18n;
/// `KernelSU` dynamic late-loading and module orchestration.
pub mod ksu;
/// Root manager APK asset retrieval, verification, and caching.
pub mod manager;
/// GitHub release mirror fallback and connection testing.
pub mod mirror;
/// Standard application directory and file paths.
pub mod paths;
/// On-device artifact cleanup and trace elimination.
pub mod persistence;
/// Shell command argument quoting and sanitization.
pub mod quote;
/// Device communication transports (ADB CLI, ADB `SmartSocket` client).
pub mod transport;

pub use catalog::{
    CatalogCacheMeta, CatalogConfig, CatalogUrlSource, CatalogV5, DeviceEntry, KernelBuild,
    PayloadFile, CATALOG_CACHE_MAX_AGE_SECS,
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
pub use manager::{CachedManagerInfo, ManagerAssetInfo, ManagerDownloader};
pub use mirror::{MirrorConfig, DEFAULT_GITHUB_MIRRORS};
pub use paths::{
    cache_dir, catalog_url_file, history_dir, manager_cache_dir, mirror_config_file, rmv_home_dir,
};
pub use persistence::{CleanOutcome, Persistence};
pub use quote::sh_quote;
pub use transport::{
    ADBServer, AdbCliTransport, AdbClientTransport, AdbMdnsDiscovery, AdbServiceKind,
    DiscoveredAdbService, TransportBuilder, TransportMode,
};
pub use transport::{ExecOutput, Transport, TransportExt};
