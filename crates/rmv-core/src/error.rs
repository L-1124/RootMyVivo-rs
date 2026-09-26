use thiserror::Error;

#[derive(Error, Debug)]
pub enum RmvError {
    #[error("ADB 异常: {message}")]
    Adb {
        message: String,
        code: Option<i32>,
    },

    #[error("未检测到有效 ADB 设备: {0}")]
    DeviceNotFound(String),

    #[error("内核不受支持或漏洞已修补: {version} ({reason})")]
    UnsupportedKernel {
        version: String,
        reason: String,
    },

    #[error("拉取载荷目录失败: {0}")]
    CatalogFetchFailed(String),

    #[error("载荷与设备不匹配: 期望 {expected}, 载荷内实为 {found} (标签: {labels})")]
    PayloadDeviceMismatch {
        expected: String,
        found: String,
        labels: String,
    },

    #[error("未在目录中找到匹配当前设备与内核的载荷 (设备: {device}, 内核: {kernel})")]
    PayloadNotFound {
        device: String,
        kernel: String,
    },

    #[error("载荷 SHA-256 校验不匹配! 期望: {expected}, 实际: {actual}")]
    HashMismatch {
        expected: String,
        actual: String,
    },

    #[error("提权超时 (最后尝试: {last_attempt:?})")]
    ExploitTimeout {
        last_attempt: Option<u32>,
        log_tail: String,
    },

    #[error("提权运行失败: {0}")]
    ExploitFailed(String),

    #[error("KernelSU/SukiSU 操作失败: {0}")]
    KsuFailed(String),
    #[error("流程被用户主动取消")]
    Cancelled,

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP 网络请求错误: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON 序列化解析错误: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T, E = RmvError> = std::result::Result<T, E>;
