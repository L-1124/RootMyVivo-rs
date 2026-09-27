use crate::error::{Result, RmvError};
use crate::transport::Transport;
use rust_i18n::t;

pub struct Persistence;

/// 清理执行结果：有无 root 决定能否连 root 属主的残留一并清掉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanOutcome {
    WithRoot,
    ShellOnly,
}

/// 清理脚本：清掉注入残留（su 客户端、socket、daemon 日志）与模块缓存，
/// 并解除 `/apex/com.android.virt/bin` 上注入期叠加的 tmpfs 覆盖挂载（恢复原厂 AVF 组件）。
/// 不含单引号，可直接执行，也可包进 su -c。
/// AVF 覆盖最多 2 层，循环上限 4 次兜底，避免 umount 失效时空转。
/// chown 刻意不加 -R：递归会把 /data/local/tmp 下第三方 App 的文件属主一并改掉。
const CLEAN: &str = "for n in 1 2 3 4; do \
                       mount | grep -q \"tmpfs on /apex/com.android.virt/bin\" || break; \
                       umount /apex/com.android.virt/bin 2>/dev/null || break; \
                     done; \
                     rm -rf /data/local/tmp/rmv /data/local/tmp/ota /data/local/tmp/live.log \
                     /data/local/tmp/DONE /data/local/tmp/preload.so /data/local/tmp/su \
                     /data/local/tmp/temp_su.sock /data/local/tmp/su_daemon.log \
                     /data/local/tmp/exploit_run.log /data/adb/rmv 2>/dev/null; \
                     pkill -f \"[s]u --daemon\" 2>/dev/null; \
                     chown 2000:2000 /data/local/tmp 2>/dev/null; true";

impl Persistence {
    pub async fn clean_traces<T: Transport>(transport: &T) -> Result<CleanOutcome> {
        // 优先以 root 清理，无 root 时退回 shell 身份
        let (root_code, _) = transport
            .exec(&format!("su -c '{}'", CLEAN))
            .await
            .unwrap_or((-1, String::new()));
        if root_code == 0 {
            return Ok(CleanOutcome::WithRoot);
        }

        let (code, out) = transport.exec(CLEAN).await?;
        if code != 0 {
            return Err(RmvError::ExploitFailed(
                t!("error.clean_traces_failed", error = out.trim()).to_string(),
            ));
        }
        Ok(CleanOutcome::ShellOnly)
    }
}
