use rust_i18n::t;
use crate::error::{Result, RmvError};
use crate::transport::Transport;

pub struct Persistence;

/// 清理执行结果：有无 root 决定能否连 root 属主的残留一并清掉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanOutcome {
    WithRoot,
    ShellOnly,
}

/// 基础清理脚本。不含单引号，可直接执行，也可包进 su -c。
const BASIC_CLEAN: &str = "rm -rf /data/local/tmp/rmv /data/local/tmp/live.log /data/local/tmp/DONE 2>/dev/null; \
                            chown -R 2000:2000 /data/local/tmp 2>/dev/null; true";

/// 深度清理脚本：额外清掉残留 su 客户端、socket、daemon 日志与模块缓存。
const DEEP_CLEAN: &str = "rm -rf /data/local/tmp/rmv /data/local/tmp/ota /data/local/tmp/live.log \
                          /data/local/tmp/DONE /data/local/tmp/preload.so /data/local/tmp/su \
                          /data/local/tmp/temp_su.sock /data/local/tmp/su_daemon.log \
                          /data/local/tmp/exploit_run.log /data/adb/rmv 2>/dev/null; \
                          pkill -f \"su --daemon\" 2>/dev/null; \
                          chown -R 2000:2000 /data/local/tmp 2>/dev/null; true";

impl Persistence {
    pub async fn clean_traces<T: Transport>(transport: &T, deep: bool) -> Result<CleanOutcome> {
        // 优先以 root 清理，无 root 时退回 shell 身份
        let script = if deep { DEEP_CLEAN } else { BASIC_CLEAN };

        let (root_code, _) = transport
            .exec(&format!("su -c '{}'", script))
            .await
            .unwrap_or((-1, String::new()));
        if root_code == 0 {
            return Ok(CleanOutcome::WithRoot);
        }

        let (code, out) = transport.exec(script).await?;
        if code != 0 {
            return Err(RmvError::ExploitFailed(
                t!("error.clean_traces_failed", error = out.trim()).to_string(),
            ));
        }
        Ok(CleanOutcome::ShellOnly)
    }
}
