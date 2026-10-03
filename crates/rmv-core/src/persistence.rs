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

/// 清理脚本：清理注入工作目录（/data/local/tmp/rmv）及根目录临时残留，
/// 终止提权守护进程并恢复目录属主。
/// 不含单引号，可直接执行，也可包进 su -c。
/// chown 刻意不加 -R：递归会把 /data/local/tmp 下第三方 App 的文件属主一并改掉。
const CLEAN: &str = "rm -rf /data/local/tmp/rmv /data/local/tmp/ota /data/local/tmp/live.log \
                     /data/local/tmp/DONE /data/local/tmp/preload.so /data/local/tmp/su \
                     /data/local/tmp/temp_su.sock /data/local/tmp/su_daemon.log \
                     /data/local/tmp/temp_su.pid /data/local/tmp/exploit_run.log /data/adb/rmv 2>/dev/null; \
                     pkill -f \"[s]u --daemon\" 2>/dev/null; \
                     chown 2000:2000 /data/local/tmp 2>/dev/null; true";

impl Persistence {
    pub async fn clean_traces<T: Transport>(transport: &T) -> Result<CleanOutcome> {
        // 1. 如果 KernelSU 已加载，使用 ksud debug su 直接以内核 root (u:r:ksu:s0) 穿透 SELinux 清理
        let ksu_clean_cmd = format!(
            r#"sh -c '
                KSUD=""
                if [ -x /data/local/tmp/rmv/ksud ]; then
                    KSUD="/data/local/tmp/rmv/ksud"
                elif [ -x /data/adb/ksu/bin/ksud ]; then
                    KSUD="/data/adb/ksu/bin/ksud"
                elif command -v ksud >/dev/null 2>&1; then
                    KSUD="ksud"
                fi
                if [ -n "$KSUD" ]; then
                    echo "{}" | $KSUD debug su 2>/dev/null
                else
                    exit 1
                fi
            '"#,
            CLEAN
        );
        if let Ok(out) = transport.exec(&ksu_clean_cmd).await {
            if out.success() {
                return Ok(CleanOutcome::WithRoot);
            }
        }

        // 2. 尝试临时 su 客户端或 /system/bin/su 执行 root 清理
        let temp_su_clean_cmd = format!(
            r#"sh -c '
                [ -e /data/local/tmp/rmv/temp_su.sock ] && [ ! -e /data/local/tmp/temp_su.sock ] && ln -sf /data/local/tmp/rmv/temp_su.sock /data/local/tmp/temp_su.sock 2>/dev/null
                [ -e /data/local/tmp/rmv/su ] && [ ! -e /data/local/tmp/su ] && ln -sf /data/local/tmp/rmv/su /data/local/tmp/su 2>/dev/null
                if [ -x /data/local/tmp/rmv/su ]; then
                    RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c "{}" 2>/dev/null
                elif [ -x /data/local/tmp/su ]; then
                    /data/local/tmp/su -c "{}" 2>/dev/null
                elif [ -x /system/bin/su ]; then
                    /system/bin/su -c "{}" 2>/dev/null
                else
                    su -c "{}" 2>/dev/null
                fi
            '"#,
            CLEAN, CLEAN, CLEAN, CLEAN
        );
        if let Ok(out) = transport.exec(&temp_su_clean_cmd).await {
            if out.success() {
                return Ok(CleanOutcome::WithRoot);
            }
        }

        // 3. 无 root 时退回 shell 身份尽力清理
        let out = transport.exec(CLEAN).await?;
        if !out.success() {
            return Err(RmvError::ExploitFailed(
                t!("error.clean_traces_failed", error = out.combined().trim()).to_string(),
            ));
        }
        Ok(CleanOutcome::ShellOnly)
    }

    /// 当提权或 late-load 失败时，如果 /data/adb 为空目录，则安全删除，
    /// 避免在非 root 设备物理分区遗留空目录导致银行或安全检测误报。
    /// rmdir 具备天然安全性：若包含模块或文件则拒绝删除 (ENOTEMPTY)。
    pub async fn prune_empty_data_adb<T: Transport>(transport: &T) -> Result<()> {
        let prune_cmd = r#"sh -c '
            PRUNE_SCRIPT="rmdir /data/adb 2>/dev/null; true"
            if [ -x /system/bin/su ]; then
                /system/bin/su -c "$PRUNE_SCRIPT" 2>/dev/null
            elif [ -x /data/local/tmp/rmv/su ]; then
                RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c "$PRUNE_SCRIPT" 2>/dev/null
            elif [ -x /data/local/tmp/su ]; then
                /data/local/tmp/su -c "$PRUNE_SCRIPT" 2>/dev/null
            else
                su -c "$PRUNE_SCRIPT" 2>/dev/null
            fi
        '"#;
        let _ = transport.exec(prune_cmd).await;
        Ok(())
    }
}
