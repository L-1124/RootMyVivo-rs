use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    DeviceCheck,
    Catalog,
    Download,
    Deploy,
    Exploit,
    Persistence,
    Ksu,
    Finished,
}

impl Phase {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::DeviceCheck => "设备环境与安全门禁检测",
            Self::Catalog => "载荷编目检索",
            Self::Download => "载荷下载与校验",
            Self::Deploy => "推送载荷至设备",
            Self::Exploit => "执行提权注入",
            Self::Persistence => "本地持久化连接配置",
            Self::Ksu => "KernelSU 模块加载",
            Self::Finished => "完成",
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
pub enum EngineStatus {
    Idle,
    Running,
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        message: String,
    },
}
