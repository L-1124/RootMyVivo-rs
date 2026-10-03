use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Phase {
    DeviceCheck,
    Catalog,
    Download,
    Deploy,
    Exploit,
    Ksu,
    Finished,
}

impl Phase {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Ok,
    Warn,
    Error,
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EngineStatus {
    Idle,
    Running,
    Success,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EngineEvent {
    Step {
        phase: Phase,
        index: usize,
        total: usize,
        desc: String,
    },
    Log {
        level: LogLevel,
        line: String,
    },
    Progress {
        text: String,
        active: bool,
    },
    Download {
        filename: String,
        downloaded: u64,
        total: u64,
    },
    ExploitLive {
        attempt: Option<u32>,
        max: Option<u32>,
        lines: Vec<String>,
    },
    Status(EngineStatus),
    Completed {
        success: bool,
        #[serde(default)]
        status: Option<EngineStatus>,
        message: String,
    },
}
