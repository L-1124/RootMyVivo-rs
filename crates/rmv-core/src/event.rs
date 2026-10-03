use serde::{Deserialize, Serialize};

/// Major execution phases of the exploit engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Phase {
    /// Device inspection and kernel version gating.
    DeviceCheck,
    /// Online catalog retrieval and matching.
    Catalog,
    /// Payload download and verification.
    Download,
    /// On-device deployment and permission configuration.
    Deploy,
    /// Privilege escalation execution and root polling.
    Exploit,
    /// `KernelSU` dynamic late-loading and activation.
    Ksu,
    /// Teardown, trace cleanup, and execution logging.
    Finished,
}

impl Phase {
    /// Returns the localized display name for the phase.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::DeviceCheck => rust_i18n::t!("phase.device_check").to_string(),
            Self::Catalog => rust_i18n::t!("phase.catalog").to_string(),
            Self::Download => rust_i18n::t!("phase.download").to_string(),
            Self::Deploy => rust_i18n::t!("phase.deploy").to_string(),
            Self::Exploit => rust_i18n::t!("phase.exploit").to_string(),
            Self::Ksu => rust_i18n::t!("phase.ksu").to_string(),
            Self::Finished => rust_i18n::t!("phase.finished").to_string(),
        }
    }
}

/// Severity levels for engine log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Informational progress messages.
    Info,
    /// Successful milestone messages.
    Ok,
    /// Non-fatal warnings and fallbacks.
    Warn,
    /// Error occurrences.
    Error,
    /// Active running state indicators.
    Running,
}

/// Overall run completion statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EngineStatus {
    /// Engine is not currently running.
    Idle,
    /// Exploit or loading is actively executing.
    Running,
    /// Full success with temporary root and active `KernelSU`.
    Success,
    /// Partial success with temporary root but skipped `KernelSU`.
    Partial,
    /// Exploit failed to achieve root privileges.
    Failed,
}

/// Real-time engine event stream emitted during pipeline execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EngineEvent {
    /// Transition to a new execution step.
    Step {
        /// Current execution phase.
        phase: Phase,
        /// 1-based step index.
        index: usize,
        /// Total steps in the pipeline.
        total: usize,
        /// Human-readable step description.
        desc: String,
    },
    /// Diagnostic log line.
    Log {
        /// Message severity level.
        level: LogLevel,
        /// Log message text.
        line: String,
    },
    /// Transient progress or spinner text update.
    Progress {
        /// Progress status text.
        text: String,
        /// Whether the progress activity indicator should remain active.
        active: bool,
    },
    /// File download byte progress update.
    Download {
        /// Target filename.
        filename: String,
        /// Bytes transferred so far.
        downloaded: u64,
        /// Total file size in bytes.
        total: u64,
    },
    /// Live exploit execution output captured from the device daemon.
    ExploitLive {
        /// Current exploit attempt index.
        attempt: Option<u32>,
        /// Maximum configured attempts.
        max: Option<u32>,
        /// New log lines.
        lines: Vec<String>,
    },
    /// High-level engine state transition.
    Status(EngineStatus),
    /// Final pipeline completion event.
    Completed {
        /// Boolean success indicator.
        success: bool,
        /// Resolved run status.
        #[serde(default)]
        status: Option<EngineStatus>,
        /// Summary message.
        message: String,
    },
}
