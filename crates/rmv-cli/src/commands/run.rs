use super::resolve_transport;
use crate::ui::CliUi;
use anyhow::Result;
use colored::*;
use rmv_core::{
    EngineOptions, ExploitEngine, KsuVariant, Persistence, RootStatus, TransportBuilder,
    TransportExt, TransportMode,
};
use rust_i18n::t;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct RunArgs {
    pub serial: Option<String>,
    pub payload: Option<PathBuf>,
    pub catalog_url: Option<String>,
    pub ksu: String,
    pub skip_ksu: bool,
    pub attempts: u32,
    pub delay: u64,
    pub save_history: bool,
    pub reboot_first: bool,
    pub dry_run: bool,
    pub manager_apk: Option<PathBuf>,
    pub manager_version: Option<String>,
    pub mirror: Option<String>,
    pub no_install_manager: bool,
    pub timeout: u64,
    pub transport_mode: TransportMode,
    pub all_devices: bool,
    pub soft_reboot: bool,
}

pub async fn run_exploit(args: RunArgs) -> Result<()> {
    let ksu_variant = KsuVariant::from_id(&args.ksu);

    if args.all_devices {
        let transports = TransportBuilder::resolve_all(args.transport_mode).await?;
        let count = transports.len();
        println!(
            "{}",
            t!("cli.all_devices_starting", count = count.to_string())
                .bold()
                .cyan()
        );

        let mp = std::sync::Arc::new(indicatif::MultiProgress::new());

        struct DeviceSummary {
            serial: String,
            model: String,
            root_status: String,
            duration: f64,
            success: bool,
            error: String,
        }

        let mut join_set = tokio::task::JoinSet::new();

        for (dev_serial, transport) in transports.clone() {
            let opts = EngineOptions {
                custom_payload: args.payload.clone(),
                custom_catalog_url: args.catalog_url.clone(),
                ksu_variant,
                skip_ksu: args.skip_ksu,
                attempts: args.attempts,
                retry_delay: args.delay,
                save_history: args.save_history,
                reboot_first: args.reboot_first,
                force_payload: false,
                payload_dirs: Vec::new(),
                dry_run: args.dry_run,
                manager_apk: args.manager_apk.clone(),
                github_mirror: args.mirror.clone(),
                manager_version: args.manager_version.clone(),
                install_manager: !args.no_install_manager,
                timeout_secs: args.timeout,
                soft_reboot: args.soft_reboot,
            };
            let mp_clone = mp.clone();
            let s_tag = dev_serial.clone();

            join_set.spawn(async move {
                let start = std::time::Instant::now();
                let (event_tx, mut event_rx) = mpsc::unbounded_channel();
                let mut ui = CliUi::new_multi(mp_clone, s_tag.clone());

                let ui_handle = tokio::spawn(async move {
                    while let Some(event) = event_rx.recv().await {
                        ui.handle_event(event).await;
                    }
                    ui.flush().await;
                });

                let safe_serial = s_tag.replace(':', "_");
                let temp_dir = std::env::temp_dir().join(format!("rmv-work-{}", safe_serial));
                let engine = ExploitEngine::new(temp_dir);
                let res = engine.run(&transport, opts, event_tx).await;
                let _ = ui_handle.await;

                let duration = start.elapsed().as_secs_f64();
                let model = match transport.get_device_info().await {
                    Ok(info) => {
                        if info.device == info.model || info.device == "-" {
                            info.model
                        } else {
                            format!("{} ({})", info.model, info.device)
                        }
                    }
                    Err(_) => "-".to_string(),
                };

                let root_status_str = match rmv_core::check_root_status(&transport).await {
                    Ok(RootStatus::KernelSu { .. }) => "KernelSU".to_string(),
                    Ok(RootStatus::TempRoot { .. }) => "uid=0 (Temp)".to_string(),
                    Ok(RootStatus::NotRooted { .. }) => "未获取".to_string(),
                    Ok(_) | Err(_) => "-".to_string(),
                };

                let (success, error) = match res {
                    Ok(()) => (true, String::new()),
                    Err(e) => (false, e.to_string()),
                };

                DeviceSummary {
                    serial: s_tag,
                    model,
                    root_status: root_status_str,
                    duration,
                    success,
                    error,
                }
            });
        }

        let mut summaries = Vec::new();
        let mut interrupted = false;

        loop {
            tokio::select! {
                res = join_set.join_next() => {
                    match res {
                        Some(Ok(summary)) => summaries.push(summary),
                        Some(Err(join_err)) => {
                            eprintln!("[fail] 任务异常: {}", join_err);
                        }
                        None => break,
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    interrupted = true;
                    eprintln!("\n{}", "[warn] 收到中断信号，正在终止并发任务并清理现场...".yellow().bold());
                    join_set.abort_all();
                    break;
                }
            }
        }

        if interrupted {
            for (_, t) in transports {
                let _ = t
                    .exec("pkill -9 -x true 2>/dev/null; pkill -f preload.so 2>/dev/null")
                    .await;
                let _ = Persistence::clean_traces(&t).await;
            }
            return Err(rmv_core::RmvError::Cancelled.into());
        }

        println!("\n{}", "=".repeat(80).cyan());
        println!("  {}", t!("cli.all_devices_summary_title").bold().cyan());
        println!("{}", "-".repeat(80).cyan());
        println!(
            "  {:<18} {:<18} {:<12} {:<10} {}",
            "SERIAL".dimmed(),
            "DEVICE".dimmed(),
            "ROOT".dimmed(),
            "DURATION".dimmed(),
            "RESULT".dimmed()
        );

        let mut success_count = 0;
        let mut fail_count = 0;

        for s in &summaries {
            let status_badge = if s.success {
                success_count += 1;
                "PASS".green().bold()
            } else {
                fail_count += 1;
                "FAIL".red().bold()
            };
            let duration_str = format!("{:.1}s", s.duration);
            let result_col = if s.success {
                status_badge.to_string()
            } else {
                format!("{} ({})", status_badge, s.error.dimmed())
            };

            println!(
                "  {:<18} {:<18} {:<12} {:<10} {}",
                s.serial.yellow(),
                s.model,
                s.root_status,
                duration_str,
                result_col
            );
        }

        println!("{}", "=".repeat(80).cyan());
        println!(
            "  {}",
            t!(
                "cli.all_devices_summary_footer",
                total = summaries.len().to_string(),
                success = success_count.to_string(),
                failed = fail_count.to_string()
            )
            .bold()
        );
        println!();

        if fail_count > 0 {
            anyhow::bail!("多设备中有 {} 台提权失败。", fail_count);
        }

        return Ok(());
    }

    let transport = resolve_transport(args.serial, args.transport_mode).await?;

    let options = EngineOptions {
        custom_payload: args.payload,
        custom_catalog_url: args.catalog_url,
        ksu_variant,
        skip_ksu: args.skip_ksu,
        attempts: args.attempts,
        retry_delay: args.delay,
        save_history: args.save_history,
        reboot_first: args.reboot_first,
        force_payload: false,
        payload_dirs: Vec::new(),
        dry_run: args.dry_run,
        manager_apk: args.manager_apk,
        github_mirror: args.mirror,
        manager_version: args.manager_version,
        install_manager: !args.no_install_manager,
        timeout_secs: args.timeout,
        soft_reboot: args.soft_reboot,
    };

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut ui = CliUi::new();

    let ui_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            ui.handle_event(event).await;
        }
        ui.flush().await;
    });

    let temp_dir = std::env::temp_dir().join("rmv-work");
    let engine = ExploitEngine::new(temp_dir);

    let res = tokio::select! {
        engine_res = engine.run(&transport, options, event_tx) => {
            let _ = ui_handle.await;
            engine_res.map_err(Into::into)
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n{}", t!("cli.ctrl_c_interrupted").yellow().bold());
            let _ = transport
                .exec("pkill -9 -x true 2>/dev/null; pkill -f preload.so 2>/dev/null")
                .await;
            let _ = Persistence::clean_traces(&transport).await;
            eprintln!("{}", t!("cli.ctrl_c_cleaned").green());
            Err(rmv_core::RmvError::Cancelled.into())
        }
    };

    res
}
