use reqwest::Client;
use rust_i18n::t;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

use crate::catalog::CatalogV5;
use crate::device::{check_root_status, DeviceInfo, GateStatus};
use crate::error::{Result, RmvError};
use crate::event::{EngineEvent, EngineStatus, LogLevel, Phase};
use crate::history::{HistoryManager, RunRecord, RunStatus};
use crate::ksu::{KsuOrchestrator, KsuVariant};
use crate::manager::ManagerDownloader;
use crate::persistence::Persistence;
use crate::quote::sh_quote;
use crate::transport::{Transport, TransportExt};

#[expect(clippy::expect_used, reason = "Known compile-time regex literal")]
static ATTEMPT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"rmv exploit attempt (\d+)/(\d+)").expect("valid exploit attempt regex")
});

/// Options configuring the execution of [`ExploitEngine`].
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI argument configuration bag with boolean flags"
)]
pub struct EngineOptions {
    /// Optional path to a custom local `.so` payload instead of downloading from catalog.
    pub custom_payload: Option<PathBuf>,
    /// Optional custom URL pointing to a remote `catalog.json`.
    pub custom_catalog_url: Option<String>,
    /// Variant of `KernelSU`/`SukiSU` to deploy upon obtaining root privilege.
    pub ksu_variant: KsuVariant,
    /// Whether to skip `KernelSU` installation and leave raw temporary root intact.
    pub skip_ksu: bool,
    /// Maximum number of exploit attempts before giving up.
    pub attempts: u32,
    /// Delay in seconds between successive exploit attempts.
    pub retry_delay: u64,
    /// Whether to persist run records into the local history store.
    pub save_history: bool,
    /// Whether to force a device reboot before launching the exploit loop.
    pub reboot_first: bool,
    /// Whether to bypass gate check failures and force payload deployment.
    pub force_payload: bool,
    /// Local directories searched for fallback payloads matching device fingerprint.
    pub payload_dirs: Vec<PathBuf>,
    /// When true, resolves and validates payloads without pushing or executing on device.
    pub dry_run: bool,
    /// Path to a local `KernelSU`/`SukiSU` manager APK to extract `ksud` without preinstallation.
    pub manager_apk: Option<PathBuf>,
    /// Mirror prefix URL for GitHub Releases downloads (e.g. `https://ghproxy.net/`).
    pub github_mirror: Option<String>,
    /// Target manager version tag (e.g. `v4.2.0`), or `None` for pinned default.
    pub manager_version: Option<String>,
    /// Whether to automatically install the manager APK onto the device after root.
    pub install_manager: bool,
    /// Timeout in seconds waiting for exploit completion sentinel or process exit.
    pub timeout_secs: u64,
    /// Whether to execute `ksud soft-reboot` after successful `KernelSU` deployment.
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

/// Orchestrates device verification, payload resolution, exploit execution, and `KernelSU` late-loading.
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

fn emit_log(
    event_tx: &UnboundedSender<EngineEvent>,
    captured: &mut Vec<String>,
    level: LogLevel,
    line: impl Into<String>,
) {
    let line_str = line.into();
    append_captured_log(captured, &line_str);
    let _ = event_tx.send(EngineEvent::Log {
        level,
        line: line_str,
    });
}

impl ExploitEngine {
    /// Creates a new `ExploitEngine` with a configured local working directory.
    pub fn new(work_dir: impl AsRef<Path>) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            work_dir: work_dir.as_ref().to_path_buf(),
        }
    }

    /// Executes the complete root acquisition and `KernelSU` late-load lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error if device communication fails, gate checks reject the target,
    /// payload download or verification fails, the exploit process exits or times out,
    /// or `KernelSU` deployment encounters an unrecoverable error.
    pub async fn run<T: Transport>(
        &self,
        transport: &T,
        options: EngineOptions,
        event_tx: UnboundedSender<EngineEvent>,
    ) -> Result<()> {
        let record_id = HistoryManager::new_record_id();
        let timestamp = HistoryManager::current_timestamp();
        let history_dir = HistoryManager::default_dir();

        let initial_record = if options.save_history && !options.dry_run {
            let init_rec = RunRecord {
                id: record_id.clone(),
                timestamp: timestamp.clone(),
                device_model: "-".to_string(),
                device_code: "-".to_string(),
                kernel: "-".to_string(),
                payload: options
                    .custom_payload
                    .as_ref()
                    .map_or_else(|| "-".to_string(), |p| p.display().to_string()),
                ksu_variant: options.ksu_variant.display_name().to_string(),
                success: false,
                status: Some(RunStatus::Running),
                message: t!("phase.in_progress").to_string(),
                logs: Vec::new(),
            };
            let _ = HistoryManager::save_record(&history_dir, &init_rec).await;
            Some(init_rec)
        } else {
            None
        };

        let mut captured_logs = Vec::new();
        let res = self
            .run_internal(
                transport,
                &options,
                &event_tx,
                &mut captured_logs,
                &record_id,
                &timestamp,
            )
            .await;

        if options.save_history && !options.dry_run {
            let (model, code, kernel, payload_str, success, status, message) = match &res {
                Ok((dev, p_path, st, msg)) => (
                    dev.model.clone(),
                    dev.device.clone(),
                    dev.kernel_full.clone(),
                    p_path.display().to_string(),
                    true,
                    Some(*st),
                    msg.clone(),
                ),
                Err(e) => {
                    let (m, c, k) = if let Ok(d) = transport.get_device_info().await {
                        (d.model, d.device, d.kernel_full)
                    } else if let Some(init) = &initial_record {
                        (
                            init.device_model.clone(),
                            init.device_code.clone(),
                            init.kernel.clone(),
                        )
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
                            .map_or_else(|| "-".to_string(), |p| p.display().to_string()),
                        false,
                        Some(RunStatus::Fail),
                        e.to_string(),
                    )
                }
            };

            let record = RunRecord {
                id: record_id,
                timestamp,
                device_model: model,
                device_code: code,
                kernel,
                payload: payload_str,
                ksu_variant: options.ksu_variant.display_name().to_string(),
                success,
                status,
                message,
                logs: captured_logs,
            };
            let _ = HistoryManager::save_record(&history_dir, &record).await;
        }

        res.map(|_| ())
    }

    async fn run_internal<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        event_tx: &UnboundedSender<EngineEvent>,
        captured_logs: &mut Vec<String>,
        record_id: &str,
        timestamp: &str,
    ) -> Result<(DeviceInfo, PathBuf, RunStatus, String)> {
        let total_steps: usize = if options.skip_ksu { 4 } else { 5 };
        let _ = event_tx.send(EngineEvent::Status(EngineStatus::Running));

        // Stage 1: Device Check & Gate Evaluation
        let mut device = self
            .stage1_device_check(transport, options, event_tx, captured_logs, total_steps)
            .await?;

        // 实时同步 Stage 1 结果至本地历史
        if options.save_history && !options.dry_run {
            let step1_rec = RunRecord {
                id: record_id.to_string(),
                timestamp: timestamp.to_string(),
                device_model: device.model.clone(),
                device_code: device.device.clone(),
                kernel: device.kernel_full.clone(),
                payload: options
                    .custom_payload
                    .as_ref()
                    .map_or_else(|| "-".to_string(), |p| p.display().to_string()),
                ksu_variant: options.ksu_variant.display_name().to_string(),
                success: false,
                status: Some(RunStatus::Running),
                message: t!("phase.in_progress").to_string(),
                logs: captured_logs.clone(),
            };
            let _ = HistoryManager::save_record(&HistoryManager::default_dir(), &step1_rec).await;
        }

        // Stage 2: Payload Resolution & Verification
        let payload_local_path = self
            .stage2_resolve_payload(transport, options, &device, event_tx, total_steps)
            .await?;

        if options.dry_run {
            emit_log(
                event_tx,
                captured_logs,
                LogLevel::Ok,
                t!(
                    "log.dry_run_done",
                    path = payload_local_path.display().to_string()
                ),
            );
            let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
            let msg = t!(
                "log.dry_run_complete_msg",
                path = payload_local_path.display().to_string()
            )
            .to_string();
            let _ = event_tx.send(EngineEvent::Completed {
                success: true,
                status: Some(EngineStatus::Success),
                message: msg.clone(),
            });
            return Ok((device, payload_local_path, RunStatus::Pass, msg));
        }

        // Stage 3: Payload Deployment
        self.stage3_deploy_payload(
            transport,
            options,
            &payload_local_path,
            event_tx,
            total_steps,
        )
        .await?;

        // Stage 4: Exploit Execution & Root Attainment
        let already_rooted = self
            .stage4_execute_exploit(
                transport,
                options,
                &mut device,
                event_tx,
                captured_logs,
                total_steps,
            )
            .await?;

        if !already_rooted {
            emit_log(event_tx, captured_logs, LogLevel::Ok, t!("log.uid0_ok"));
        }

        // 实时同步 Stage 4 (UID=0 达成) 结果至本地历史
        if options.save_history && !options.dry_run {
            let root_rec = RunRecord {
                id: record_id.to_string(),
                timestamp: timestamp.to_string(),
                device_model: device.model.clone(),
                device_code: device.device.clone(),
                kernel: device.kernel_full.clone(),
                payload: payload_local_path.display().to_string(),
                ksu_variant: options.ksu_variant.display_name().to_string(),
                success: false,
                status: Some(RunStatus::Running),
                message: t!("log.uid0_ok").to_string(),
                logs: captured_logs.clone(),
            };
            let _ = HistoryManager::save_record(&HistoryManager::default_dir(), &root_rec).await;
        }

        // Stage 5: KernelSU Setup & Late-Load
        let ksu_ok = self
            .stage5_setup_ksu(transport, options, event_tx, captured_logs, total_steps)
            .await?;

        if !ksu_ok {
            let partial_msg = t!("log.partial_success_temp_root").to_string();
            return Ok((device, payload_local_path, RunStatus::Partial, partial_msg));
        }

        // Stage 6: Finalize (Soft reboot or trace cleanup)
        let finalize_msg = self
            .stage6_finalize(transport, options, event_tx, captured_logs)
            .await?;

        Ok((device, payload_local_path, RunStatus::Pass, finalize_msg))
    }

    async fn stage1_device_check<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        event_tx: &UnboundedSender<EngineEvent>,
        captured_logs: &mut Vec<String>,
        total_steps: usize,
    ) -> Result<DeviceInfo> {
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::DeviceCheck,
            index: 1,
            total: total_steps,
            desc: t!("phase.device_check").to_string(),
        });

        if options.reboot_first {
            emit_log(
                event_tx,
                captured_logs,
                LogLevel::Info,
                t!("log.reboot_pristine"),
            );
            transport.reboot_and_wait(120).await?;
            emit_log(event_tx, captured_logs, LogLevel::Ok, t!("log.reboot_done"));
        }

        let device = transport.get_device_info().await?;
        emit_log(
            event_tx,
            captured_logs,
            LogLevel::Ok,
            t!(
                "log.device_info",
                model = &device.model,
                device = &device.device,
                brand = &device.brand,
                kernel = device.gki_git_id.as_deref().unwrap_or("-")
            ),
        );

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

        Ok(device)
    }

    async fn stage2_resolve_payload<T: Transport>(
        &self,
        _transport: &T,
        options: &EngineOptions,
        device: &DeviceInfo,
        event_tx: &UnboundedSender<EngineEvent>,
        total_steps: usize,
    ) -> Result<PathBuf> {
        if let Some(custom) = &options.custom_payload {
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
            Ok(custom.clone())
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
                    .match_payload(device)
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
            CatalogV5::download_payload(&self.client, file_info, &target_file, Some(event_tx))
                .await?;

            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.hash_ok").to_string(),
            });

            Ok(target_file)
        }
    }

    async fn stage3_deploy_payload<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        payload_local_path: &Path,
        event_tx: &UnboundedSender<EngineEvent>,
        total_steps: usize,
    ) -> Result<()> {
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
        let prep_cmd = format!(
            "mkdir -p {} {}/rmv && rm -f {} /data/local/tmp/rmv/DONE /data/local/tmp/rmv/rmv/DONE /data/local/tmp/rmv/live.log",
            sh_quote(remote_dir),
            sh_quote(remote_dir),
            sh_quote(remote_so)
        );
        let _ = transport.exec(&prep_cmd).await?;
        transport.push(payload_local_path, remote_so).await?;
        let chmod_cmd = format!("chmod 755 {}", sh_quote(remote_so));
        let _ = transport.exec(&chmod_cmd).await?;
        Ok(())
    }

    async fn stage4_execute_exploit<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        device: &mut DeviceInfo,
        event_tx: &UnboundedSender<EngineEvent>,
        captured_logs: &mut Vec<String>,
        total_steps: usize,
    ) -> Result<bool> {
        let step_index = if options.custom_payload.is_some() {
            3
        } else {
            4
        };
        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Exploit,
            index: step_index,
            total: total_steps,
            desc: t!("log.exploit_start").to_string(),
        });

        wait_boot_completed(transport, event_tx).await;
        refresh_boot_id(transport, device).await;

        if check_root_status(transport).await?.is_rooted() {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.root_already").to_string(),
            });
            return Ok(true);
        }

        let remote_dir = "/data/local/tmp/rmv";
        let remote_so = "/data/local/tmp/rmv/preload.so";
        launch_exploit(transport, options, remote_dir, remote_so).await?;

        let timeout_limit = options.timeout_secs;
        let mut elapsed_sec = 0u64;
        let mut last_log_tail = String::new();
        let mut last_attempt: Option<u32> = None;
        let mut is_rooted = false;
        let mut boot_poisoned = false;
        let mut attempts_exhausted = false;
        let mut process_exited = false;
        let probe_cmd = build_probe_cmd(remote_dir);

        while timeout_limit == 0 || elapsed_sec < timeout_limit {
            sleep(Duration::from_secs(2)).await;
            elapsed_sec += 2;

            let probe_exec = transport.exec(&probe_cmd).await?;
            let probe = parse_probe_output(&probe_exec.combined());

            handle_probe_logs(
                &probe,
                &mut last_log_tail,
                &mut last_attempt,
                options.attempts,
                event_tx,
                captured_logs,
            );

            match probe.outcome {
                ProbeOutcome::Rooted => {
                    is_rooted = true;
                    break;
                }
                ProbeOutcome::BootPoisoned => {
                    boot_poisoned = true;
                }
                ProbeOutcome::DoneSuccess => {
                    if check_su_polling(transport).await {
                        is_rooted = true;
                        break;
                    }
                }
                ProbeOutcome::DoneFailed => {
                    attempts_exhausted = true;
                    break;
                }
                ProbeOutcome::DaemonExited if elapsed_sec >= 6 => {
                    process_exited = true;
                    let _ = event_tx.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        line: t!("log.exploit_gone").to_string(),
                    });
                    break;
                }
                ProbeOutcome::DaemonAlive | ProbeOutcome::DaemonExited => {}
            }
        }

        if !is_rooted {
            classify_failure(
                transport,
                last_attempt,
                &ExploitFailureState {
                    boot_poisoned,
                    attempts_exhausted,
                    process_exited,
                    max_attempts: options.attempts,
                    last_log_tail,
                },
                event_tx,
                captured_logs,
            )
            .await?;
        }

        Ok(false)
    }

    async fn stage5_setup_ksu<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        event_tx: &UnboundedSender<EngineEvent>,
        captured_logs: &mut Vec<String>,
        total_steps: usize,
    ) -> Result<bool> {
        if options.skip_ksu {
            return Ok(true);
        }

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
            emit_log(
                event_tx,
                captured_logs,
                LogLevel::Ok,
                t!("log.ksu_already_active"),
            );
            return Ok(true);
        }

        let _ = event_tx.send(EngineEvent::Step {
            phase: Phase::Ksu,
            index: ksu_step,
            total: total_steps,
            desc: t!("log.ksu_start", name = options.ksu_variant.display_name()).to_string(),
        });

        let host_apk = self
            .ensure_manager_apk(transport, options, event_tx)
            .await?;

        if options.install_manager {
            if let Some(apk_path) = host_apk.as_ref() {
                let pkg = options.ksu_variant.package_name();
                let _ = self
                    .install_manager_apk(transport, apk_path, pkg, event_tx)
                    .await;
            }
        }

        let ksu_ok = self
            .late_load_ksu(transport, options, host_apk.as_deref(), event_tx)
            .await?;

        if ksu_ok {
            emit_log(
                event_tx,
                captured_logs,
                LogLevel::Ok,
                t!("log.ksu_ok", name = options.ksu_variant.display_name()),
            );
        }

        Ok(ksu_ok)
    }

    async fn ensure_manager_apk<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        event_tx: &UnboundedSender<EngineEvent>,
    ) -> Result<Option<PathBuf>> {
        if options.manager_apk.is_some() {
            return Ok(options.manager_apk.clone());
        }

        let pkg_cmd = format!("pm path {}", sh_quote(options.ksu_variant.package_name()));
        let out = transport.exec(&pkg_cmd).await;
        let has_installed_app = out
            .as_ref()
            .is_ok_and(|o| o.success() && o.stdout.contains("package:"));

        if has_installed_app {
            return Ok(None);
        }

        let _ = event_tx.send(EngineEvent::Log {
            level: LogLevel::Info,
            line: t!(
                "log.manager_auto_download",
                name = options.ksu_variant.display_name()
            )
            .to_string(),
        });

        match ManagerDownloader::download_manager(
            &self.client,
            options.ksu_variant,
            options.manager_version.as_deref(),
            None,
            options.github_mirror.as_deref(),
            Some(event_tx),
        )
        .await
        {
            Ok(path) => Ok(Some(path)),
            Err(e) => {
                let _ = event_tx.send(EngineEvent::Log {
                    level: LogLevel::Warn,
                    line: t!("log.partial_ksu_skipped", error = e.to_string()).to_string(),
                });
                Ok(None)
            }
        }
    }

    async fn install_manager_apk<T: Transport>(
        &self,
        transport: &T,
        apk_path: &Path,
        pkg: &str,
        event_tx: &UnboundedSender<EngineEvent>,
    ) -> Result<bool> {
        let pkg_cmd = format!("pm path {}", sh_quote(pkg));
        let out = transport.exec(&pkg_cmd).await;
        let has_pkg = out
            .as_ref()
            .is_ok_and(|o| o.success() && o.stdout.contains("package:"));
        if has_pkg {
            return Ok(true);
        }

        let display_name = KsuVariant::all_variants()
            .iter()
            .find(|v| v.package_name() == pkg)
            .map_or(pkg, |v| v.display_name());

        let _ = event_tx.send(EngineEvent::Log {
            level: LogLevel::Info,
            line: t!("log.manager_installing", name = display_name).to_string(),
        });

        let lock_check_cmd = "sh -c 'dumpsys power 2>/dev/null | grep -iE \"mWakefulness=(Asleep|Dozing)\"; dumpsys window 2>/dev/null | grep -iE \"(mShowing=true|isStatusBarKeyguard=true|mDreamingLockscreen=true)\"; dumpsys trust 2>/dev/null | grep -i \"device is locked: true\"'";
        let is_locked = if let Ok(out) = transport.exec(lock_check_cmd).await {
            !out.combined().trim().is_empty()
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
                if let Ok(out) = transport.exec(lock_check_cmd).await {
                    if out.combined().trim().is_empty() {
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
        if transport.push(apk_path, remote_install_apk).await.is_err() {
            return Ok(false);
        }

        let quoted_apk = sh_quote(remote_install_apk);
        let install_cmd = format!(
            "sh -c 'if [ -x /data/local/tmp/rmv/su ]; then RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c \"pm install -r -d \\\"$1\\\"\" 2>/dev/null; elif [ -x /data/local/tmp/su ]; then /data/local/tmp/su -c \"pm install -r -d \\\"$1\\\"\" 2>/dev/null; elif [ -x /system/bin/su ]; then /system/bin/su -c \"pm install -r -d \\\"$1\\\"\" 2>/dev/null; else pm install -r -d \"$1\"; fi' _ {quoted_apk}"
        );
        let inst_out = transport.exec(&install_cmd).await;
        let rm_cmd = format!("rm -f {quoted_apk}");
        let _ = transport.exec(&rm_cmd).await;

        let inst_ok = inst_out.as_ref().is_ok_and(|o| {
            o.success() && (o.combined().contains("Success") || o.combined().trim().is_empty())
        });
        if inst_ok {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!("log.manager_install_ok", name = display_name).to_string(),
            });
            Ok(true)
        } else {
            let err_msg = inst_out.as_ref().map_or_else(
                std::string::ToString::to_string,
                super::transport::ExecOutput::combined,
            );
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Warn,
                line: t!(
                    "error.manager_install_failed",
                    name = display_name,
                    message = err_msg.trim()
                )
                .to_string(),
            });
            Ok(false)
        }
    }

    async fn late_load_ksu<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        manager_apk: Option<&Path>,
        event_tx: &UnboundedSender<EngineEvent>,
    ) -> Result<bool> {
        let late_load_res =
            KsuOrchestrator::late_load(transport, options.ksu_variant, None, manager_apk).await;

        if let Err(e) = late_load_res {
            let _ = Persistence::prune_empty_data_adb(transport).await;
            let partial_msg = t!("log.partial_success_temp_root").to_string();
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Warn,
                line: t!("log.partial_ksu_skipped", error = e.to_string()).to_string(),
            });
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Info,
                line: t!("log.partial_su_hint").to_string(),
            });
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Info,
                line: t!("log.partial_recovery_hint").to_string(),
            });
            let _ = event_tx.send(EngineEvent::Status(EngineStatus::Partial));
            let _ = event_tx.send(EngineEvent::Completed {
                success: true,
                status: Some(EngineStatus::Partial),
                message: partial_msg,
            });
            return Ok(false);
        }

        Ok(true)
    }

    async fn stage6_finalize<T: Transport>(
        &self,
        transport: &T,
        options: &EngineOptions,
        event_tx: &UnboundedSender<EngineEvent>,
        captured_logs: &mut Vec<String>,
    ) -> Result<String> {
        if options.soft_reboot {
            emit_log(
                event_tx,
                captured_logs,
                LogLevel::Info,
                t!("log.soft_reboot_pending"),
            );
            let soft_reboot_cmd = "if [ -x /data/adb/ksu/bin/ksud ]; then /data/adb/ksu/bin/ksud soft-reboot; elif [ -x /data/local/tmp/rmv/ksud ]; then /data/local/tmp/rmv/ksud soft-reboot; else setprop ctl.restart zygote; fi";
            let exec_cmd = format!(
                "/system/bin/su -c {} 2>/dev/null",
                sh_quote(soft_reboot_cmd)
            );
            let _ = transport.exec(&exec_cmd).await;

            let success_msg = t!("log.finished").to_string();
            let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
            let _ = event_tx.send(EngineEvent::Completed {
                success: true,
                status: Some(EngineStatus::Success),
                message: success_msg.clone(),
            });
            return Ok(success_msg);
        }

        // 清理设备端临时痕迹
        let _ = Persistence::clean_traces(transport).await;

        let success_msg = t!("log.finished").to_string();
        let _ = event_tx.send(EngineEvent::Status(EngineStatus::Success));
        let _ = event_tx.send(EngineEvent::Completed {
            success: true,
            status: Some(EngineStatus::Success),
            message: success_msg.clone(),
        });

        Ok(success_msg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    Rooted,
    BootPoisoned,
    DoneSuccess,
    DoneFailed,
    DaemonAlive,
    DaemonExited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExploitProbeResult {
    pub log_tail: String,
    pub attempt: Option<u32>,
    pub outcome: ProbeOutcome,
}

fn build_probe_cmd(remote_dir: &str) -> String {
    format!(
        "tail -n 15 {remote_dir}/live.log 2>/dev/null; \
         echo __RMV_DONE__; cat {remote_dir}/DONE {remote_dir}/rmv/DONE 2>/dev/null | head -n 1; \
         echo __RMV_ALIVE__; pgrep -x true 2>/dev/null || pgrep -f preload.so 2>/dev/null; \
         echo __RMV_SU__; [ -e {remote_dir}/temp_su.sock ] && [ ! -e /data/local/tmp/temp_su.sock ] && ln -sf {remote_dir}/temp_su.sock /data/local/tmp/temp_su.sock 2>/dev/null; [ -e {remote_dir}/su ] && [ ! -e /data/local/tmp/su ] && ln -sf {remote_dir}/su /data/local/tmp/su 2>/dev/null; RMV_HOME={remote_dir} {remote_dir}/su -c id 2>/dev/null || /data/local/tmp/su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null; \
         echo __RMV_END__"
    )
}

fn parse_probe_output(output: &str) -> ExploitProbeResult {
    let tail_part = output.split("__RMV_DONE__").next().unwrap_or("").trim();
    let done_part = output
        .split("__RMV_DONE__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_ALIVE__")
        .next()
        .unwrap_or("")
        .trim();
    let alive_part = output
        .split("__RMV_ALIVE__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_SU__")
        .next()
        .unwrap_or("")
        .trim();
    let su_part = output
        .split("__RMV_SU__")
        .nth(1)
        .unwrap_or("")
        .split("__RMV_END__")
        .next()
        .unwrap_or("")
        .trim();

    let attempt = ATTEMPT_RE
        .captures(tail_part)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse().ok());
    let outcome = if su_part.contains("uid=0") {
        ProbeOutcome::Rooted
    } else if tail_part.contains("boot_poisoned") {
        ProbeOutcome::BootPoisoned
    } else if done_part.contains('1') || done_part.contains("RMV_DONE") {
        ProbeOutcome::DoneSuccess
    } else if done_part.contains('0') {
        ProbeOutcome::DoneFailed
    } else if !alive_part.is_empty() {
        ProbeOutcome::DaemonAlive
    } else {
        ProbeOutcome::DaemonExited
    };

    ExploitProbeResult {
        log_tail: tail_part.to_string(),
        attempt,
        outcome,
    }
}

async fn refresh_boot_id<T: Transport>(transport: &T, device: &mut DeviceInfo) {
    if let Ok(out) = transport
        .exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null")
        .await
    {
        let cur = out.stdout.trim();
        if out.success() && !cur.is_empty() {
            device.boot_id = cur.to_string();
        }
    }
}

async fn launch_exploit<T: Transport>(
    transport: &T,
    options: &EngineOptions,
    remote_dir: &str,
    remote_so: &str,
) -> Result<()> {
    let _ = transport
        .exec("pkill -9 -x true 2>/dev/null; rm -f /data/local/tmp/rmv/DONE /data/local/tmp/rmv/rmv/DONE /data/local/tmp/rmv/live.log")
        .await;
    let run_cmd = format!(
        "cd {} && (RMV_HOME={} RMV_ATTEMPTS={} RMV_RETRY_DELAY={} LD_PRELOAD={} /system/bin/true > /data/local/tmp/rmv/live.log 2>&1 &)",
        sh_quote(remote_dir),
        sh_quote(remote_dir),
        sh_quote(&options.attempts.to_string()),
        sh_quote(&options.retry_delay.to_string()),
        sh_quote(remote_so)
    );
    transport.exec(&run_cmd).await?;
    Ok(())
}

fn handle_probe_logs(
    probe: &ExploitProbeResult,
    last_log_tail: &mut String,
    last_attempt: &mut Option<u32>,
    max_attempts: u32,
    event_tx: &UnboundedSender<EngineEvent>,
    captured_logs: &mut Vec<String>,
) {
    if !probe.log_tail.is_empty() && probe.log_tail != *last_log_tail {
        last_log_tail.clone_from(&probe.log_tail);
        if let Some(att) = probe.attempt {
            *last_attempt = Some(att);
        }
        let lines: Vec<String> = probe
            .log_tail
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for l in &lines {
            append_captured_log(captured_logs, l);
        }
        let _ = event_tx.send(EngineEvent::ExploitLive {
            attempt: *last_attempt,
            max: Some(max_attempts),
            lines,
        });
    }
}

async fn wait_boot_completed<T: Transport>(transport: &T, event_tx: &UnboundedSender<EngineEvent>) {
    if let Ok(out) = transport.exec("getprop sys.boot_completed").await {
        if !out.success() || out.stdout.trim() != "1" {
            let _ = event_tx.send(EngineEvent::Log {
                level: LogLevel::Info,
                line: t!("log.waiting_boot_complete").to_string(),
            });
            let boot_deadline = std::time::Instant::now();
            while boot_deadline.elapsed() < Duration::from_secs(120) {
                sleep(Duration::from_secs(2)).await;
                if let Ok(o) = transport.exec("getprop sys.boot_completed").await {
                    if o.success() && o.stdout.trim() == "1" {
                        break;
                    }
                }
            }
            sleep(Duration::from_secs(4)).await;
        }
    }
}

async fn check_su_polling<T: Transport>(transport: &T) -> bool {
    for _ in 0..10 {
        let su_exec = transport
            .exec("RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c id 2>/dev/null || /data/local/tmp/su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null")
            .await;
        let su_check = su_exec.map(|o| o.combined()).unwrap_or_default();
        if su_check.contains("uid=0") {
            return true;
        }
        sleep(Duration::from_millis(500)).await;
    }
    false
}

struct ExploitFailureState {
    pub boot_poisoned: bool,
    pub attempts_exhausted: bool,
    pub process_exited: bool,
    pub max_attempts: u32,
    pub last_log_tail: String,
}

async fn classify_failure<T: Transport>(
    transport: &T,
    last_attempt: Option<u32>,
    state: &ExploitFailureState,
    event_tx: &UnboundedSender<EngineEvent>,
    captured_logs: &mut Vec<String>,
) -> Result<()> {
    let _ = event_tx.send(EngineEvent::Status(EngineStatus::Failed));
    if let Ok(log_exec) = transport
        .exec("cat /data/local/tmp/rmv/live.log 2>/dev/null")
        .await
    {
        for line in log_exec.combined().lines() {
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

    if state.boot_poisoned {
        let _ = event_tx.send(EngineEvent::Log {
            level: LogLevel::Error,
            line: t!("log.boot_poisoned").to_string(),
        });
        return Err(RmvError::BootPoisoned);
    }

    if state.attempts_exhausted {
        let count = last_attempt.unwrap_or(state.max_attempts);
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

    if state.process_exited {
        let err_msg = t!("error.exploit_process_exited").to_string();
        return Err(RmvError::ExploitFailed(err_msg));
    }

    Err(RmvError::ExploitTimeout {
        last_attempt,
        log_tail: state.last_log_tail.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_probe_cmd() {
        let cmd = build_probe_cmd("/data/local/tmp/rmv");
        assert!(cmd.contains("/data/local/tmp/rmv/live.log"));
        assert!(cmd.contains("__RMV_DONE__"));
        assert!(cmd.contains("__RMV_ALIVE__"));
        assert!(cmd.contains("__RMV_SU__"));
        assert!(cmd.contains("__RMV_END__"));
    }

    #[test]
    fn test_parse_probe_output_normal() {
        let sample = "\
rmv exploit attempt 3/24
[+] scanning offsets
__RMV_DONE__
0
__RMV_ALIVE__
12345
__RMV_SU__
uid=2000(shell) gid=2000(shell)
__RMV_END__
";
        let res = parse_probe_output(sample);
        assert_eq!(res.attempt, Some(3));
        assert_eq!(res.outcome, ProbeOutcome::DoneFailed);
    }

    #[test]
    fn test_parse_probe_output_root_success() {
        let sample = "\
rmv exploit attempt 7/24
[+] kernel patched!
__RMV_DONE__
1
__RMV_ALIVE__
12345
__RMV_SU__
uid=0(root) gid=0(root) groups=0(root)
__RMV_END__
";
        let res = parse_probe_output(sample);
        assert_eq!(res.attempt, Some(7));
        assert_eq!(res.outcome, ProbeOutcome::Rooted);
    }

    #[test]
    fn test_parse_probe_output_sentinels_and_poisoned() {
        let sample = "\
rmv exploit attempt 1/24
[-] boot_poisoned detected
__RMV_DONE__
RMV_DONE
__RMV_ALIVE__

__RMV_SU__

__RMV_END__
";
        let res = parse_probe_output(sample);
        assert_eq!(res.attempt, Some(1));
        assert_eq!(res.outcome, ProbeOutcome::BootPoisoned);
    }
}
