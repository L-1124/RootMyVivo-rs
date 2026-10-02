use reqwest::Client;
use rust_i18n::t;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

use crate::catalog::CatalogV5;
use crate::device::{check_root_status, GateStatus};
use crate::error::{Result, RmvError};
use crate::event::{EngineEvent, EngineStatus, LogLevel, Phase};
use crate::history::{HistoryManager, RunRecord};
use crate::ksu::{KsuOrchestrator, KsuVariant};
use crate::manager::ManagerDownloader;
use crate::persistence::Persistence;
use crate::transport::Transport;

#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub custom_payload: Option<PathBuf>,
    pub custom_catalog_url: Option<String>,
    pub ksu_variant: KsuVariant,
    pub skip_ksu: bool,
    pub attempts: u32,
    pub retry_delay: u64,
    pub save_history: bool,
    pub reboot_first: bool,
    pub force_payload: bool,
    /// 本地载荷库目录，闸门失败时用于按本机指纹回退配对。
    pub payload_dirs: Vec<PathBuf>,
    /// 只解析与校验载荷，不下发、不执行。
    pub dry_run: bool,
    /// PC 本地提供的 KernelSU/SukiSU 管理器 APK 路径（用于免预装就地提取 ksud）。
    pub manager_apk: Option<PathBuf>,
    /// GitHub Release 加速镜像前缀（如 https://ghproxy.net/ 或 direct）
    pub github_mirror: Option<String>,
    /// 管理器版本 Tag（None 表示默认最新发布版）
    pub manager_version: Option<String>,
    /// 提权成功后是否自动静默安装管理器 APK（默认为 true）
    pub install_manager: bool,
    /// 提权等待窗口（秒）。CFI 探测最多 24 次且带随机延迟，窗口需覆盖整个探测期。
    pub timeout_secs: u64,
    /// 提权与 KernelSU 加载成功后是否自动触发系统软重启 (ksud soft-reboot)
    pub soft_reboot: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            custom_payload: None,
            custom_catalog_url: None,
            ksu_variant: KsuVariant::SukiSuUltra,
            skip_ksu: false,
            attempts: 3,
            retry_delay: 8,
            save_history: true,
            reboot_first: false,
            force_payload: false,
            payload_dirs: Vec::new(),
            dry_run: false,
            manager_apk: None,
            github_mirror: None,
            manager_version: None,
            install_manager: true,
            timeout_secs: 900,
            soft_reboot: false,
        }
    }
}

pub struct ExploitEngine {
    client: Client,
    work_dir: PathBuf,
}

fn append_captured_log(captured: &mut Vec<String>, line: &str) {
    if captured.len() >= 50 {
        captured.remove(0);
    }
    captured.push(line.to_string());
}

impl ExploitEngine {
    pub fn new(work_dir: impl AsRef<Path>) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            work_dir: work_dir.as_ref().to_path_buf(),
        }
    }

    pub async fn run<T: Transport>(
        &self,
        transport: &T,
        options: EngineOptions,
        event_tx: UnboundedSender<EngineEvent>,
    ) -> Result<()> {
        let mut captured_logs = Vec::new();
        let res = self
            .run_internal(transport, &options, &event_tx, &mut captured_logs)
            .await;

        if options.save_history && !options.dry_run {
            let (model, code, kernel, payload_str, success, message) = match &res {
                Ok((dev, p_path, msg)) => (
                    dev.model.clone(),
                    dev.device.clone(),
                    dev.kernel_full.clone(),
                    p_path.display().to_string(),
                    true,
                    msg.clone(),
                ),
                Err(e) => {
                    let (m, c, k) = if let Ok(d) = transport.get_device_info().await {
                        (d.model, d.device, d.kernel_full)
                    } else {
                        ("-".to_string(), "-".to_string(), "-".to_string())
                    };
                    (
                        m,
                        c,
                        k,
                        options
                            .custom_payload
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        false,
                        e.to_string(),
                    )
                }
            };

            let record = RunRecord {
                id: HistoryManager::new_record_id(),
                timestamp: HistoryManager::current_timestamp(),
                device_model: model,
                device_code: code,
                kernel,
                payload: payload_str,
                ksu_variant: options.ksu_variant.display_name().to_string(),
                success,
                message,
                logs: captured_logs,
            };
            let _ = HistoryManager::save_record(&HistoryManager::default_dir(), &record).await;
        }

        res.map(|_| ())
    }

    async fn run_internal<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        event_tx: &UnboundedSender<EngineEvent>,
        captured_logs: &mut Vec<String>,
    ) -> Result<(crate::device::DeviceInfo, PathBuf, String)> {
        let total_steps = if options.skip_ksu { 4 } else { 5 };
        let _ = event_tx.send(EngineEvent::Status(EngineStatus::Running));
        // 步骤 1: 设备环境与门禁检测
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::DeviceCheck,
            index: 1,
            total: total_steps,
            desc: t!("phase.device_check").to_string(),
        });
        if options.reboot_first {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Info,
                line: t!("log.reboot_pristine").to_string(),
            });
            transport.reboot_and_wait(120).await?;
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.reboot_done").to_string(),
            });
        }

        let mut device = transport.get_device_info().await?;
        let _ = event_tx.send(EngineEvent::Log {
            level: LogLevel::Ok,
            line: t!(
                "log.device_info",
                model = &device.model,
                device = &device.device,
                brand = &device.brand,
                kernel = device.gki_git_id.as_deref().unwrap_or("-")
            )
            .to_string(),
        });

        match device.evaluate_gate() {
            GateStatus::Vulnerable => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Ok,
                    line: t!("log.gate_passed").to_string(),
                });
            }
            GateStatus::Patched { version, reason } => {
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::UnsupportedKernel { version, reason });
            }
            GateStatus::UnsupportedVersion(v) => {
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::UnsupportedKernel {
                    version: v,
                    reason: t!("gate.unsupported_version").to_string(),
                });
            }
        }

        // 步骤 2: 载荷获取 (自定义文件 或 在线编目匹配)
        let payload_local_path = if let Some(custom) = &options.custom_payload {
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Catalog,
                index: 2,
                total: total_steps,
                desc: t!("log.custom_payload", path = custom.display().to_string()).to_string(),
            });

            if !custom.exists() {
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::ExploitFailed(
                    t!(
                        "error.local_payload_not_found",
                        path = custom.display().to_string()
                    )
                    .to_string(),
                ));
            }
            custom.clone()
        } else {
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Catalog,
                index: 2,
                total: total_steps,
                desc: t!("log.catalog_search").to_string(),
            });

            let catalog =
                CatalogV5::fetch_with_url(&self.client, options.custom_catalog_url.as_deref())
                    .await?;

            if let Some(meta) = &catalog.cached_meta {
                if CatalogV5::is_fresh(meta.fetched_at, crate::catalog::CATALOG_CACHE_MAX_AGE_SECS)
                {
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Info,
                        line: t!("log.catalog_cache_used", url = meta.url.clone()).to_string(),
                    });
                } else {
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Warn,
                        line: t!("log.catalog_cache_expired", url = meta.url.clone()).to_string(),
                    });
                }
            }
            let (_device_entry, kernel_build) =
                catalog
                    .match_payload(&device)
                    .ok_or_else(|| RmvError::PayloadNotFound {
                        device: format!("{}/{}", device.model, device.device),
                        kernel: device.kernel_full.clone(),
                    })?;

            // Block execution if the catalog marks this build as patched
            if kernel_build.status.eq_ignore_ascii_case("patched") {
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::UnsupportedKernel {
                    version: device.kernel_full.clone(),
                    reason: t!("gate.cve_patched_backport").to_string(),
                });
            }

            let file_info =
                kernel_build
                    .file
                    .as_ref()
                    .ok_or_else(|| RmvError::PayloadNotFound {
                        device: device.model.clone(),
                        kernel: "匹配成功但该构建未提供下载文件".to_string(),
                    })?;

            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!(
                    "log.matched_payload",
                    name = &file_info.name,
                    size = file_info.size.to_string()
                )
                .to_string(),
            });

            // 步骤 3: 载荷下载与哈希校验
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Download,
                index: 3,
                total: total_steps,
                desc: t!("log.download_verify", name = &file_info.name).to_string(),
            });

            tokio::fs::create_dir_all(&self.work_dir).await?;
            let target_file = self.work_dir.join(&file_info.name);
            CatalogV5::download_payload(&self.client, file_info, &target_file, Some(&event_tx))
                .await?;

            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.hash_ok").to_string(),
            });

            target_file
        };

        if options.dry_run {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!(
                    "log.dry_run_done",
                    path = payload_local_path.display().to_string()
                )
                .to_string(),
            });
            let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
            let msg = t!(
                "log.dry_run_complete_msg",
                path = payload_local_path.display().to_string()
            )
            .to_string();
            let _ = event_tx.send(EngineEvent::Completed {
                success: true,
                message: msg.clone(),
            });
            return Ok((device, payload_local_path, msg));
        }

        // 部署阶段
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Deploy,
            index: if options.custom_payload.is_some() {
                2
            } else {
                3
            },
            total: total_steps,
            desc: t!("log.deploy_so").to_string(),
        });

        let remote_dir = "/data/local/tmp/rmv";
        let remote_so = "/data/local/tmp/rmv/preload.so";
        let _ = transport
            .exec(&format!(
                "mkdir -p {} {}/rmv && rm -f {} /data/local/tmp/rmv/DONE /data/local/tmp/rmv/rmv/DONE /data/local/tmp/rmv/live.log",
                remote_dir, remote_dir, remote_so
            ))
            .await?;
        transport.push(&payload_local_path, remote_so).await?;
        let _ = transport.exec(&format!("chmod 755 {}", remote_so)).await?;

        // 步骤: 执行提权并监听
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Exploit,
            index: if options.custom_payload.is_some() {
                3
            } else {
                4
            },
            total: total_steps,
            desc: t!("log.exploit_start").to_string(),
        });

        // 确保设备处于已完全启动就绪状态 (sys.boot_completed == 1)
        if let Ok((code, out)) = transport.exec("getprop sys.boot_completed").await {
            if code != 0 || out.trim() != "1" {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Info,
                    line: t!("log.waiting_boot_complete").to_string(),
                });
                let boot_deadline = std::time::Instant::now();
                while boot_deadline.elapsed() < Duration::from_secs(120) {
                    sleep(Duration::from_secs(2)).await;
                    if let Ok((c, o)) = transport.exec("getprop sys.boot_completed").await {
                        if c == 0 && o.trim() == "1" {
                            break;
                        }
                    }
                }
                sleep(Duration::from_secs(4)).await;
            }
        }

        // 刷新当前真实的 live boot_id，杜绝因开机延迟等造成的假阳性误判
        if let Ok((code, out)) = transport
            .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
            .await
        {
            let cur = out.trim();
            if code == 0 && !cur.is_empty() {
                device.boot_id = cur.to_string();
            }
        }

        // 检查是否已拥有 root 权限
        let root_status = check_root_status(transport).await?;
        let already_rooted = root_status.is_rooted();
        let mut is_rooted = already_rooted;
        if is_rooted {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.root_already").to_string(),
            });
        } else {
            // 启动前先杀死残留的僵死 true 进程并清空历史 DONE 哨兵，保证全新提权环境
            let _ = transport
                .exec("pkill -9 -x true 2>/dev/null; rm -f /data/local/tmp/rmv/DONE /data/local/tmp/rmv/rmv/DONE /data/local/tmp/rmv/live.log")
                .await;
            let run_cmd = format!(
                "cd {} && (RMV_HOME='{}' RMV_ATTEMPTS='{}' RMV_RETRY_DELAY='{}' LD_PRELOAD={} /system/bin/true > /data/local/tmp/rmv/live.log 2>&1 &)",
                remote_dir, remote_dir, options.attempts, options.retry_delay, remote_so
            );
            let _ = transport.exec(&run_cmd).await?;

            // CFI 探测单轮最多 24 次且每次带随机延迟，窗口需覆盖整个探测期
            let timeout_limit = options.timeout_secs;
            let mut elapsed_sec = 0u64;
            let mut last_log_tail = String::new();
            let mut last_attempt: Option<u32> = None;
            let attempt_re = regex::Regex::new(r"rmv exploit attempt (\d+)/(\d+)")
                .expect("static attempt pattern");
            let mut payload_alive;
            let mut boot_poisoned = false;
            let mut attempts_exhausted = false;
            let mut process_exited = false;
            while timeout_limit == 0 || elapsed_sec < timeout_limit {
                sleep(Duration::from_secs(2)).await;
                elapsed_sec += 2;

                // Single round-trip fast probe: logs, completion sentinel, liveness, su
                let (_, probe) = transport
                    .exec(
                        "tail -n 15 /data/local/tmp/rmv/live.log 2>/dev/null; \
                         echo __RMV_DONE__; cat /data/local/tmp/rmv/DONE /data/local/tmp/rmv/rmv/DONE 2>/dev/null | head -n 1; \
                         echo __RMV_ALIVE__; pgrep -x true 2>/dev/null || pgrep -f preload.so 2>/dev/null; \
                         echo __RMV_SU__; [ -e /data/local/tmp/rmv/temp_su.sock ] && [ ! -e /data/local/tmp/temp_su.sock ] && ln -sf /data/local/tmp/rmv/temp_su.sock /data/local/tmp/temp_su.sock 2>/dev/null; [ -e /data/local/tmp/rmv/su ] && [ ! -e /data/local/tmp/su ] && ln -sf /data/local/tmp/rmv/su /data/local/tmp/su 2>/dev/null; RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c id 2>/dev/null || /data/local/tmp/su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null; \
                         echo __RMV_END__",
                    )
                    .await?;
                let tail_part = probe
                    .split("__RMV_DONE__")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let done_part = probe
                    .split("__RMV_DONE__")
                    .nth(1)
                    .unwrap_or("")
                    .split("__RMV_ALIVE__")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let alive_part = probe
                    .split("__RMV_ALIVE__")
                    .nth(1)
                    .unwrap_or("")
                    .split("__RMV_SU__")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let su_part = probe
                    .split("__RMV_SU__")
                    .nth(1)
                    .unwrap_or("")
                    .split("__RMV_END__")
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !tail_part.is_empty() && tail_part != last_log_tail {
                    last_log_tail = tail_part.clone();
                    if let Some(caps) = attempt_re.captures(&tail_part) {
                        last_attempt = caps.get(1).and_then(|m| m.as_str().parse().ok());
                    }
                    let lines: Vec<String> = tail_part
                        .lines()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    for l in &lines {
                        append_captured_log(captured_logs, l);
                    }
                    let _ = event_tx.send(EngineEvent::ExploitLive {
                        attempt: last_attempt,
                        max: Some(options.attempts),
                        lines,
                    });
                }

                if tail_part.contains("boot_poisoned") {
                    boot_poisoned = true;
                }

                payload_alive = !alive_part.is_empty();

                if su_part.contains("uid=0") {
                    is_rooted = true;
                    break;
                }

                // 载荷写下的完成哨兵：DONE ('1' 或 RMV_DONE = 成功, '0' = 失败)
                let done_ok = done_part.contains('1') || done_part.contains("RMV_DONE");
                let done_fail = done_part.contains('0');
                if done_ok {
                    let mut su_ready = false;
                    for _ in 0..10 {
                        let (_, su_check) = transport
                            .exec("RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c id 2>/dev/null || /data/local/tmp/su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null")
                            .await
                            .unwrap_or((1, String::new()));
                        if su_check.contains("uid=0") {
                            su_ready = true;
                            break;
                        }
                        sleep(Duration::from_millis(500)).await;
                    }
                    if su_ready {
                        is_rooted = true;
                        break;
                    }
                } else if done_fail {
                    attempts_exhausted = true;
                    break;
                }

                // 载荷进程已退出且无完成哨兵：崩溃或异常中断，无需空等窗口
                if elapsed_sec >= 6 && !payload_alive {
                    process_exited = true;
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        line: t!("log.exploit_gone").to_string(),
                    });
                    break;
                }
            }

            if !is_rooted {
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                // 失败路径前先拉取真实设备日志保全至 host history，避免 clean 后证据销毁
                if let Ok((_, log_content)) = transport
                    .exec("cat /data/local/tmp/rmv/live.log 2>/dev/null")
                    .await
                {
                    for line in log_content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            append_captured_log(captured_logs, trimmed);
                        }
                    }
                }
                let _ = transport
                    .exec("pkill -9 -x true 2>/dev/null; pkill -f preload.so 2>/dev/null")
                    .await;
                let _ = Persistence::clean_traces(transport).await;

                if boot_poisoned {
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        line: t!("log.boot_poisoned").to_string(),
                    });
                    return Err(RmvError::BootPoisoned);
                }

                if attempts_exhausted {
                    let count = last_attempt.unwrap_or(options.attempts);
                    let err_msg = t!(
                        "error.exploit_attempts_exhausted",
                        count = count.to_string()
                    )
                    .to_string();
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        line: err_msg.clone(),
                    });
                    return Err(RmvError::ExploitFailed(err_msg));
                }

                if process_exited {
                    let err_msg = t!("error.exploit_process_exited").to_string();
                    return Err(RmvError::ExploitFailed(err_msg));
                }

                return Err(RmvError::ExploitTimeout {
                    last_attempt,
                    log_tail: last_log_tail,
                });
            }
        }

        if !already_rooted {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.uid0_ok").to_string(),
            });
        }

        // 步骤: KernelSU Late-Load
        if !options.skip_ksu {
            let ksu_step = if options.custom_payload.is_some() {
                4
            } else {
                5
            };
            let is_ksu_live = KsuOrchestrator::is_module_loaded(transport)
                .await
                .unwrap_or(false);
            let is_ksu_functional = KsuOrchestrator::is_ksu_functional(transport)
                .await
                .unwrap_or(false);
            if is_ksu_live && is_ksu_functional {
                let _ = event_tx.send(EngineEvent::Step {
                    phase: Phase::Ksu,
                    index: ksu_step,
                    total: total_steps,
                    desc: t!("log.ksu_already_active").to_string(),
                });
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Ok,
                    line: t!("log.ksu_already_active").to_string(),
                });
            } else {
                let _ = event_tx.send(EngineEvent::Step {
                    phase: Phase::Ksu,
                    index: ksu_step,
                    total: total_steps,
                    desc: t!("log.ksu_start", name = options.ksu_variant.display_name())
                        .to_string(),
                });

                let mut host_apk = options.manager_apk.clone();
                if host_apk.is_none() {
                    let (code, out) = transport
                        .exec(&format!("pm path {}", options.ksu_variant.package_name()))
                        .await
                        .unwrap_or((1, String::new()));
                    let has_installed_app = code == 0 && out.contains("package:");

                    if !has_installed_app {
                        let _ = event_tx.send(EngineEvent::Log {
                            level: LogLevel::Info,
                            line: t!(
                                "log.manager_auto_download",
                                name = options.ksu_variant.display_name()
                            )
                            .to_string(),
                        });
                        let downloaded = ManagerDownloader::download_manager(
                            &self.client,
                            options.ksu_variant,
                            options.manager_version.as_deref(),
                            None,
                            options.github_mirror.as_deref(),
                            Some(event_tx),
                        )
                        .await?;
                        host_apk = Some(downloaded);
                    }
                }

                if options.install_manager {
                    if let Some(apk_path) = host_apk.as_ref() {
                        let pkg = options.ksu_variant.package_name();
                        let (code, out) = transport
                            .exec(&format!("pm path {}", pkg))
                            .await
                            .unwrap_or((1, String::new()));
                        if code != 0 || !out.contains("package:") {
                            let _ = event_tx.send(EngineEvent::Log {
                                level: LogLevel::Info,
                                line: t!(
                                    "log.manager_installing",
                                    name = options.ksu_variant.display_name()
                                )
                                .to_string(),
                            });

                            // 检测是否处于锁屏或息屏状态（vivo/OriginOS 锁屏下会直接拒绝 USB 安装）
                            let lock_check_cmd = "sh -c 'dumpsys power 2>/dev/null | grep -iE \"mWakefulness=(Asleep|Dozing)\"; dumpsys window 2>/dev/null | grep -iE \"(mShowing=true|isStatusBarKeyguard=true|mDreamingLockscreen=true)\"; dumpsys trust 2>/dev/null | grep -i \"device is locked: true\"'";
                            let is_locked =
                                if let Ok((_, out)) = transport.exec(lock_check_cmd).await {
                                    !out.trim().is_empty()
                                } else {
                                    false
                                };

                            if is_locked {
                                let _ = event_tx.send(EngineEvent::Log {
                                    level: LogLevel::Warn,
                                    line: t!("log.manager_screen_locked").to_string(),
                                });
                                let unlock_deadline = std::time::Instant::now();
                                while unlock_deadline.elapsed() < Duration::from_secs(12) {
                                    sleep(Duration::from_secs(2)).await;
                                    if let Ok((_, out)) = transport.exec(lock_check_cmd).await {
                                        if out.trim().is_empty() {
                                            break;
                                        }
                                    }
                                }
                            }

                            let _ = event_tx.send(EngineEvent::Log {
                                level: LogLevel::Info,
                                line: t!("log.manager_install_prompt").to_string(),
                            });

                            let remote_install_apk = "/data/local/tmp/rmv/manager_install.apk";
                            if transport.push(apk_path, remote_install_apk).await.is_ok() {
                                // Root 环境执行安装以规避 OEM 限制
                                let install_cmd = format!(
                                    "sh -c 'if [ -x /data/local/tmp/rmv/su ]; then RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c \"pm install -r -d {}\" 2>/dev/null; elif [ -x /data/local/tmp/su ]; then /data/local/tmp/su -c \"pm install -r -d {}\" 2>/dev/null; elif [ -x /system/bin/su ]; then /system/bin/su -c \"pm install -r -d {}\" 2>/dev/null; else pm install -r -d {}; fi'",
                                    remote_install_apk, remote_install_apk, remote_install_apk, remote_install_apk
                                );
                                let (inst_code, inst_out) = transport
                                    .exec(&install_cmd)
                                    .await
                                    .unwrap_or((1, String::new()));
                                let _ = transport
                                    .exec(&format!("rm -f {}", remote_install_apk))
                                    .await;
                                if inst_code == 0
                                    && (inst_out.contains("Success") || inst_out.is_empty())
                                {
                                    let _ = event_tx.send(EngineEvent::Log {
                                        level: LogLevel::Ok,
                                        line: t!(
                                            "log.manager_install_ok",
                                            name = options.ksu_variant.display_name()
                                        )
                                        .to_string(),
                                    });
                                } else {
                                    let _ = event_tx.send(EngineEvent::Log {
                                        level: LogLevel::Warn,
                                        line: t!(
                                            "error.manager_install_failed",
                                            name = options.ksu_variant.display_name(),
                                            message = inst_out.trim()
                                        )
                                        .to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                if let Err(e) = KsuOrchestrator::late_load(
                    transport,
                    options.ksu_variant,
                    None,
                    host_apk.as_deref(),
                )
                .await
                {
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        line: e.to_string(),
                    });
                    let _ = Persistence::prune_empty_data_adb(transport).await;
                    return Err(e);
                }
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Ok,
                    line: t!("log.ksu_ok", name = options.ksu_variant.display_name()).to_string(),
                });
            }
        }

        if options.soft_reboot {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Info,
                line: t!("log.soft_reboot_pending").to_string(),
            });
            let soft_reboot_cmd = "if [ -x /data/adb/ksu/bin/ksud ]; then /data/adb/ksu/bin/ksud soft-reboot; elif [ -x /data/local/tmp/rmv/ksud ]; then /data/local/tmp/rmv/ksud soft-reboot; else setprop ctl.restart zygote; fi";
            let _ = transport
                .exec(&format!(
                    "/system/bin/su -c '{}' 2>/dev/null",
                    soft_reboot_cmd
                ))
                .await;

            let success_msg = t!("log.finished").to_string();
            let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
            let _ = event_tx.send(EngineEvent::Completed {
                success: true,
                message: success_msg.clone(),
            });
            return Ok((device, payload_local_path, success_msg));
        }
        // 清理设备端临时痕迹
        let _ = Persistence::clean_traces(transport).await;

        let success_msg = t!("log.finished").to_string();
        let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
        let _ = event_tx.send(EngineEvent::Completed {
            success: true,
            message: success_msg.clone(),
        });

        Ok((device, payload_local_path, success_msg))
    }
}
