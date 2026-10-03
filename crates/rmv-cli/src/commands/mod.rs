use crate::ui::CliUi;
use anyhow::{Context, Result};
use colored::*;
use rmv_core::{
    check_root_status, CatalogConfig, CatalogUrlSource, CatalogV5, CleanOutcome, EngineOptions,
    ExploitEngine, GateStatus, HistoryManager, KsuOrchestrator, KsuVariant, Persistence,
    RootStatus, Transport, TransportBuilder, TransportMode,
};
use rust_i18n::t;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn resolve_transport(
    serial: Option<String>,
    mode: TransportMode,
) -> Result<Arc<dyn Transport>> {
    if let Some(s) = serial {
        return TransportBuilder::resolve(Some(s), mode)
            .await
            .map_err(Into::into);
    }

    let devices = TransportBuilder::list_online_devices(mode).await?;
    if devices.is_empty() {
        return Err(rmv_core::RmvError::DeviceNotFound(
            t!("error.device_not_found_cli").to_string(),
        )
        .into());
    }

    if devices.len() == 1 {
        let (s, _) = &devices[0];
        return TransportBuilder::resolve(Some(s.clone()), mode)
            .await
            .map_err(Into::into);
    }

    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let items: Vec<String> = devices
            .iter()
            .map(|(s, model)| {
                if !model.is_empty() {
                    format!("{} ({})", s.bold().cyan(), model.green())
                } else {
                    s.bold().cyan().to_string()
                }
            })
            .collect();

        let prompt = t!("cli.multiple_devices_prompt");
        let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(prompt)
            .default(0)
            .items(&items)
            .interact_opt()?;

        if let Some(idx) = selection {
            let (chosen_serial, _) = &devices[idx];
            return TransportBuilder::resolve(Some(chosen_serial.clone()), mode)
                .await
                .map_err(Into::into);
        } else {
            anyhow::bail!(t!("error.cancelled"));
        }
    }

    let device_names: Vec<String> = devices.into_iter().map(|(s, _)| s).collect();
    anyhow::bail!(t!(
        "error.multiple_devices",
        devices = device_names.join(", ")
    ));
}

pub async fn run_check(serial: Option<String>, mode: TransportMode) -> Result<()> {
    println!("{}", t!("cli.probing_device").bold().cyan());
    let transport = resolve_transport(serial, mode).await?;
    let dev = transport.get_device_info().await?;

    println!("\n{}", t!("cli.device_summary").cyan().bold());
    println!(
        "  {} : {}",
        t!("cli.device_code"),
        dev.device.bold().green()
    );
    println!(
        "  {} : {}",
        t!("cli.device_model"),
        dev.model.bold().green()
    );
    println!(
        "  {} : {}",
        t!("cli.device_brand"),
        dev.brand.bold().green()
    );
    println!(
        "  {} : Linux {}.{}.{}",
        t!("cli.kernel_version"),
        dev.kernel_version.0,
        dev.kernel_version.1,
        dev.kernel_version.2
    );
    println!(
        "  {} : {}",
        t!("cli.gki_build"),
        dev.gki_git_id.as_deref().unwrap_or("-").yellow()
    );
    println!(
        "  {} : {}",
        t!("cli.build_fingerprint"),
        dev.abogki_fingerprint.as_deref().unwrap_or("-").yellow()
    );
    println!("  {} : {}", t!("cli.boot_id"), dev.boot_id.dimmed());

    let root_status = check_root_status(&transport)
        .await
        .unwrap_or(RootStatus::NotRooted {
            exploit_running: false,
        });
    let root_desc = match &root_status {
        RootStatus::KernelSu { su_path } => format!("{} ({})", t!("cli.root_ksu_active"), su_path)
            .bold()
            .green(),
        RootStatus::TempRoot {
            su_path,
            exploit_running,
        } => {
            if *exploit_running {
                format!(
                    "{} ({}, {})",
                    t!("cli.root_temp_active"),
                    su_path,
                    t!("cli.root_exploit_running")
                )
                .bold()
                .yellow()
            } else {
                format!("{} ({})", t!("cli.root_temp_active"), su_path)
                    .bold()
                    .yellow()
            }
        }
        RootStatus::NotRooted { exploit_running } => {
            if *exploit_running {
                format!(
                    "{} ({})",
                    t!("cli.root_not_rooted"),
                    t!("cli.root_exploit_running")
                )
                .bold()
                .yellow()
            } else {
                t!("cli.root_not_rooted").dimmed()
            }
        }
    };
    println!("  {} : {}", t!("cli.root_status"), root_desc);

    if KsuOrchestrator::is_module_loaded(&transport)
        .await
        .unwrap_or(false)
    {
        let modules = KsuOrchestrator::list_modules(&transport)
            .await
            .unwrap_or_default();
        if modules.is_empty() {
            println!(
                "  {} : {}",
                t!("cli.check_modules_title"),
                t!("cli.check_modules_empty").dimmed()
            );
        } else {
            println!(
                "  {} : {}",
                t!("cli.check_modules_title"),
                modules.join(", ").green().bold()
            );
        }
    }
    println!();

    match dev.evaluate_gate() {
        GateStatus::Vulnerable => {
            println!(
                "  {} : {} {}",
                t!("cli.security_gate"),
                t!("cli.gate_passed_badge").bold().green(),
                t!("cli.gate_passed_desc").dimmed()
            );
        }
        GateStatus::Patched { version, reason } => {
            println!(
                "  {} : {} {}",
                t!("cli.security_gate"),
                t!("cli.gate_blocked_badge").bold().red(),
                format!("(Linux {}: {})", version, reason).red()
            );
        }
        GateStatus::UnsupportedVersion(v) => {
            println!(
                "  {} : {} {}",
                t!("cli.security_gate"),
                t!("cli.gate_blocked_badge").bold().yellow(),
                t!("cli.gate_unsupported_desc", version = v).yellow()
            );
        }
    }
    println!();
    if root_status.is_exploit_running() {
        println!("[warn] {}", t!("cli.warn_exploit_running").yellow());
    }
    Ok(())
}

pub async fn run_catalog_show() -> Result<()> {
    let (url, source) = CatalogConfig::resolve_url(None);
    let source_str = match source {
        CatalogUrlSource::CliOverride => t!("cli.catalog_source_cli"),
        CatalogUrlSource::EnvVar => t!("cli.catalog_source_env"),
        CatalogUrlSource::ConfigFile => t!("cli.catalog_source_config"),
        CatalogUrlSource::Default => t!("cli.catalog_source_default"),
    };
    println!("{}", t!("cli.catalog_config_title").bold().cyan());
    println!(
        "  {} : {}",
        t!("cli.catalog_current_url"),
        url.green().bold()
    );
    println!("  {} : {}", t!("cli.catalog_current_source"), source_str);
    Ok(())
}

pub async fn run_catalog_set(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        anyhow::bail!(t!("error.invalid_url", url = url));
    }
    CatalogConfig::set_saved_url(trimmed)?;
    println!(
        "[ ok ] {}",
        t!("cli.catalog_url_saved", url = trimmed).green()
    );
    Ok(())
}

pub async fn run_catalog_reset() -> Result<()> {
    let existed = CatalogConfig::reset_saved_url()?;
    if existed {
        println!("[ ok ] {}", t!("cli.catalog_url_reset").green());
    } else {
        println!("[info] {}", t!("cli.catalog_url_already_default").dimmed());
    }
    Ok(())
}

pub async fn run_catalog(
    serial: Option<String>,
    catalog_url: Option<String>,
    mode: TransportMode,
) -> Result<()> {
    println!("{}", t!("cli.catalog_fetching").bold().cyan());
    let catalog = CatalogV5::fetch_default_with_url(catalog_url.as_deref())
        .await
        .context(t!("error.catalog_fetch_failed", message = "network"))?;
    if let Some(meta) = &catalog.cached_meta {
        if rmv_core::CatalogV5::is_fresh(meta.fetched_at, rmv_core::CATALOG_CACHE_MAX_AGE_SECS) {
            println!(
                "{}",
                t!("log.catalog_cache_used", url = meta.url.clone()).yellow()
            );
        } else {
            println!(
                "{}",
                t!("log.catalog_cache_expired", url = meta.url.clone()).red()
            );
        }
    }

    println!(
        "{}",
        t!(
            "cli.catalog_fetched",
            devices = catalog.devices.len().to_string(),
            builds = catalog.builds.len().to_string()
        )
    );

    println!(
        "{}",
        t!(
            "cli.catalog_devices_title",
            count = catalog.devices.len().to_string()
        )
        .bold()
        .cyan()
    );
    println!("{}", "-".repeat(78).cyan());
    println!(
        "  {:<20} {:<10} {:<24} {}",
        "MARKET NAME".dimmed(),
        "CODE".dimmed(),
        "MODELS".dimmed(),
        "KERNELS".dimmed()
    );
    println!("{}", "-".repeat(78).cyan());

    for dev in &catalog.devices {
        let code = if dev.code.is_empty() { "-" } else { &dev.code };
        let mut all_models: Vec<String> =
            dev.models.iter().chain(dev.names.iter()).cloned().collect();
        all_models.sort();
        all_models.dedup();
        all_models.retain(|m| m != &dev.market_name);

        let models_str = if all_models.is_empty() {
            code.to_string()
        } else {
            let joined = all_models.join(", ");
            if joined.len() > 24 {
                format!("{}...", &joined[..21])
            } else {
                joined
            }
        };

        let kernel_builds: Vec<&str> = dev.kernels.iter().map(|k| k.build.as_str()).collect();
        let kernels_str = if kernel_builds.is_empty() {
            "-".dimmed().to_string()
        } else {
            kernel_builds.join(", ").yellow().to_string()
        };

        println!(
            "  {:<20} {:<10} {:<24} {}",
            dev.market_name.green().bold(),
            code,
            models_str,
            kernels_str
        );
    }
    println!("{}\n", "-".repeat(78).cyan());
    if let Ok(transport) = resolve_transport(serial, mode).await {
        if let Ok(dev) = transport.get_device_info().await {
            println!("{}", t!("cli.matching_device").bold().cyan());
            match catalog.match_payload(&dev) {
                Some((device_entry, kernel_build)) => {
                    println!(
                        "  {} : {}",
                        t!("cli.matched_device"),
                        device_entry.market_name.bold().green()
                    );
                    let status_display = if kernel_build.status.eq_ignore_ascii_case("patched") {
                        kernel_build.status.bold().red()
                    } else {
                        kernel_build.status.bold().yellow()
                    };
                    println!("  {} : {}", t!("cli.payload_status"), status_display);
                    if let Some(file) = &kernel_build.file {
                        println!(
                            "  {} : {} ({} bytes)",
                            t!("cli.payload_file"),
                            file.name.green(),
                            file.size
                        );
                        println!("  {} : {}", t!("cli.download_url"), file.url.dimmed());
                    }
                }
                None => {
                    println!("  {}", t!("cli.no_payload_matched").yellow());
                }
            }
        } else {
            println!("{}", t!("cli.no_device_connected").dimmed());
        }
    } else {
        println!("{}", t!("cli.no_device_connected").dimmed());
    }

    Ok(())
}

pub async fn run_exploit(
    serial: Option<String>,
    payload: Option<PathBuf>,
    catalog_url: Option<String>,
    ksu: String,
    skip_ksu: bool,
    attempts: u32,
    delay: u64,
    save_history: bool,
    reboot_first: bool,
    force_payload: bool,
    payload_dirs: Vec<PathBuf>,
    dry_run: bool,
    manager_apk: Option<PathBuf>,
    manager_version: Option<String>,
    mirror: Option<String>,
    no_install_manager: bool,
    timeout_secs: u64,
    mode: TransportMode,
    all_devices: bool,
    soft_reboot: bool,
) -> Result<()> {
    let ksu_variant = KsuVariant::from_id(&ksu);

    if all_devices {
        let transports = TransportBuilder::resolve_all(mode).await?;
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
                custom_payload: payload.clone(),
                custom_catalog_url: catalog_url.clone(),
                ksu_variant,
                skip_ksu,
                attempts,
                retry_delay: delay,
                save_history,
                reboot_first,
                force_payload,
                payload_dirs: payload_dirs.clone(),
                dry_run,
                manager_apk: manager_apk.clone(),
                github_mirror: mirror.clone(),
                manager_version: manager_version.clone(),
                install_manager: !no_install_manager,
                timeout_secs,
                soft_reboot,
            };
            let mp_clone = mp.clone();
            let s_tag = dev_serial.clone();

            join_set.spawn(async move {
                let start = std::time::Instant::now();
                let (event_tx, mut event_rx) = mpsc::unbounded_channel();
                let mut ui = CliUi::new_multi(mp_clone, s_tag.clone());

                let ui_handle = tokio::spawn(async move {
                    while let Some(event) = event_rx.recv().await {
                        ui.handle_event(event);
                    }
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
                    Err(_) => "-".to_string(),
                };

                let (success, error) = match res {
                    Ok(_) => (true, String::new()),
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
                let _ = Persistence::clean_traces(&t).await;
            }
            anyhow::bail!("提权任务被用户中断。");
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

    let transport = resolve_transport(serial, mode).await?;

    let options = EngineOptions {
        custom_payload: payload,
        custom_catalog_url: catalog_url,
        ksu_variant,
        skip_ksu,
        attempts,
        retry_delay: delay,
        save_history,
        reboot_first,
        force_payload,
        payload_dirs,
        dry_run,
        manager_apk,
        github_mirror: mirror,
        manager_version,
        install_manager: !no_install_manager,
        timeout_secs,
        soft_reboot,
    };

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut ui = CliUi::new();

    let ui_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            ui.handle_event(event);
        }
    });

    let temp_dir = std::env::temp_dir().join("rmv-work");
    let engine = ExploitEngine::new(temp_dir);

    let res = engine.run(&transport, options, event_tx).await;
    let _ = ui_handle.await;

    res.map_err(Into::into)
}

pub async fn run_clean(serial: Option<String>, mode: TransportMode) -> Result<()> {
    println!("{} {}", "[ .. ]".cyan(), t!("cli.cleaning_traces"));
    let transport = resolve_transport(serial, mode).await?;
    let outcome = Persistence::clean_traces(&transport)
        .await
        .context(t!("error.exploit_failed", message = "clean"))?;
    match outcome {
        CleanOutcome::WithRoot => {
            println!(
                "{} {}",
                "[ ok ]".green().bold(),
                t!("cli.cleaned_root").green()
            );
        }
        CleanOutcome::ShellOnly => {
            println!(
                "{} {}",
                "[ ok ]".green().bold(),
                t!("cli.cleaned_shell").green()
            );
            println!(
                "{} {}",
                "[warn]".yellow().bold(),
                t!("cli.cleaned_shell_warn").yellow()
            );
        }
    }
    Ok(())
}
pub async fn run_pair(list: bool, addr: Option<String>, code: Option<String>) -> Result<()> {
    if list {
        println!("{} {}", "[ .. ]".cyan(), t!("cli.pairing_scanning"));
        let services = rmv_core::AdbMdnsDiscovery::scan_services(3)?;
        if services.is_empty() {
            println!(
                "{} {}",
                "[warn]".yellow().bold(),
                t!("cli.pairing_no_devices")
            );
            return Ok(());
        }
        println!(
            "{} {}",
            "[ ok ]".green().bold(),
            t!(
                "cli.pairing_found_count",
                count = services.len().to_string()
            )
            .bold()
        );
        let prog = std::env::args().next().unwrap_or_else(|| "rmv".to_string());
        for (i, svc) in services.iter().enumerate() {
            let (tag, hint) = match svc.kind {
                rmv_core::AdbServiceKind::Pairing => (
                    t!("cli.pairing_kind_pairing").yellow().bold(),
                    t!("cli.pairing_hint_pairing", prog = &prog).dimmed(),
                ),
                rmv_core::AdbServiceKind::Connect => (
                    t!("cli.pairing_kind_connect").green().bold(),
                    t!("cli.pairing_hint_connect", prog = &prog).dimmed(),
                ),
            };
            println!(
                "       {}. [{}] {} -> {}  {}",
                i + 1,
                tag,
                svc.name.cyan(),
                svc.addr.to_string().white().bold(),
                hint
            );
        }
        return Ok(());
    }

    let (socket_addr, target_code) = match (addr, code) {
        (Some(a), Some(c)) => {
            let parsed: std::net::SocketAddrV4 = a.parse().map_err(|e| {
                anyhow::anyhow!("Invalid IP:Port format (e.g. 192.168.1.50:37123): {}", e)
            })?;
            (parsed, c)
        }
        (Some(single), None) => {
            let prog = std::env::args().next().unwrap_or_else(|| "rmv".to_string());
            if single.contains(':') {
                anyhow::bail!(t!("cli.pairing_missing_code", prog = prog));
            }
            println!("{} {}", "[ .. ]".cyan(), t!("cli.pairing_scanning"));
            match rmv_core::AdbMdnsDiscovery::discover_single_pairing_device(3)? {
                Some(dev) => {
                    println!(
                        "{} {}",
                        "[ ok ]".green().bold(),
                        t!(
                            "cli.pairing_found_single",
                            name = &dev.name,
                            addr = &dev.addr.to_string()
                        )
                        .green()
                    );
                    (dev.addr, single)
                }
                None => {
                    anyhow::bail!(t!("cli.pairing_no_devices"));
                }
            }
        }
        _ => {
            let prog = std::env::args().next().unwrap_or_else(|| "rmv".to_string());
            anyhow::bail!(t!("cli.pairing_missing_code", prog = prog));
        }
    };

    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("cli.pairing_connecting", addr = &socket_addr.to_string())
    );

    let mut server = rmv_core::ADBServer::default();
    server
        .pair(socket_addr, target_code)
        .map_err(|e| anyhow::anyhow!("Pairing failed: {}", e))?;

    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.pairing_success").green().bold()
    );

    // Auto connect to the paired device
    println!(
        "{} {}",
        "[ .. ]".cyan(),
        format!("Connecting to {}...", socket_addr)
    );
    let _ = server.connect_device(socket_addr);

    Ok(())
}

pub async fn run_history_list(limit: usize) -> Result<()> {
    let dir = HistoryManager::default_dir();
    let records = HistoryManager::list_records(&dir).await?;

    if records.is_empty() {
        println!("{}", t!("cli.history_empty").dimmed());
        return Ok(());
    }

    let total = records.len();
    let display_count = limit.min(total);

    println!("\n{}", t!("cli.history_title").cyan().bold());
    println!(
        "  {:<10} {:<8} {:<20} {:<18} {:<16} {}",
        "ID".dimmed(),
        "STATUS".dimmed(),
        "TIMESTAMP".dimmed(),
        "DEVICE".dimmed(),
        "KSU".dimmed(),
        "PAYLOAD".dimmed()
    );

    for rec in records.iter().take(display_count) {
        let status = match rec.resolved_status() {
            rmv_core::RunStatus::Pass => "PASS".green().bold(),
            rmv_core::RunStatus::Partial => "PARTIAL".yellow().bold(),
            rmv_core::RunStatus::Fail => "FAIL".red().bold(),
        };

        let short_payload = std::path::Path::new(&rec.payload)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| rec.payload.clone());

        let dev_str = if rec.device_code == rec.device_model || rec.device_code == "-" {
            rec.device_model.clone()
        } else {
            format!("{} ({})", rec.device_model, rec.device_code)
        };

        println!(
            "  {:<10} {:<8} {:<20} {:<18} {:<16} {}",
            rec.id.yellow(),
            status,
            rec.timestamp,
            dev_str,
            rec.ksu_variant,
            short_payload
        );
    }

    println!();
    println!("  {}", t!("cli.history_show_hint").dimmed());
    println!();
    Ok(())
}

pub async fn run_history_show(id: &str) -> Result<()> {
    let dir = HistoryManager::default_dir();
    let rec = match HistoryManager::get_record(&dir, id).await? {
        Some(r) => r,
        None => {
            eprintln!(
                "{} {}",
                "[fail]".red().bold(),
                t!("cli.history_not_found", id = id)
            );
            std::process::exit(1);
        }
    };

    println!(
        "\n{} [{}]",
        t!("cli.history_record_title").cyan().bold(),
        rec.id.yellow().bold()
    );
    println!("  Timestamp  : {}", rec.timestamp);
    let status_str = match rec.resolved_status() {
        rmv_core::RunStatus::Pass => "PASS".green().bold(),
        rmv_core::RunStatus::Partial => "PARTIAL".yellow().bold(),
        rmv_core::RunStatus::Fail => "FAIL".red().bold(),
    };
    println!("  Status     : {}", status_str);
    println!("  Device     : {} ({})", rec.device_model, rec.device_code);
    println!("  Kernel     : {}", rec.kernel);
    println!("  Payload    : {}", rec.payload);
    println!("  KernelSU   : {}", rec.ksu_variant);
    println!("  Message    : {}", rec.message);

    println!(
        "\n{} ({} lines):",
        t!("cli.history_logs_title").cyan().bold(),
        rec.logs.len()
    );
    if rec.logs.is_empty() {
        println!("  {}", "(no log lines captured)".dimmed());
    } else {
        for line in &rec.logs {
            println!("    {}", line.dimmed());
        }
    }
    println!();
    Ok(())
}

pub async fn run_history_clear() -> Result<()> {
    let dir = HistoryManager::default_dir();
    let count = HistoryManager::clear_records(&dir).await?;
    println!(
        "{}",
        t!("cli.history_cleared", count = count.to_string())
            .green()
            .bold()
    );
    Ok(())
}

pub async fn run_stats(limit: Option<usize>) -> Result<()> {
    let dir = HistoryManager::default_dir();
    let records = HistoryManager::list_records(&dir).await?;

    if records.is_empty() {
        println!("{}", t!("cli.stats_empty").dimmed());
        return Ok(());
    }

    let max_len = limit.unwrap_or(500).min(records.len());
    let slice = &records[..max_len];

    let total = slice.len();
    let successes = slice.iter().filter(|r| r.success).count();
    let failures = total - successes;
    let rate = if total > 0 {
        (successes as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    println!("\n{}", t!("cli.stats_title").cyan().bold());
    println!(
        "  {:<24} {}",
        t!("cli.stats_total_runs"),
        total.to_string().bold()
    );
    println!(
        "  {:<24} {}",
        t!("cli.stats_success"),
        successes.to_string().green().bold()
    );
    println!(
        "  {:<24} {}",
        t!("cli.stats_failure"),
        failures.to_string().red().bold()
    );
    println!("  {:<24} {:.1}%", t!("cli.stats_success_rate"), rate);

    let mut by_variant: std::collections::BTreeMap<&str, (usize, usize)> =
        std::collections::BTreeMap::new();
    for rec in slice {
        let entry = by_variant.entry(rec.ksu_variant.as_str()).or_insert((0, 0));
        entry.0 += 1;
        if rec.success {
            entry.1 += 1;
        }
    }

    println!("\n{}", t!("cli.stats_by_variant").cyan().bold());
    println!(
        "  {:<16} {:<10} {:<10} {}",
        "VARIANT".dimmed(),
        "TOTAL".dimmed(),
        "SUCCESS".dimmed(),
        "RATE".dimmed()
    );
    for (variant, (v_tot, v_succ)) in by_variant {
        let v_rate = (v_succ as f64 / v_tot as f64) * 100.0;
        println!(
            "  {:<16} {:<10} {:<10} {:.1}%",
            variant.yellow(),
            v_tot,
            v_succ.to_string().green(),
            v_rate
        );
    }

    let mut by_day: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for rec in slice {
        let day = rec
            .timestamp
            .split([' ', 'T'])
            .next()
            .unwrap_or("unknown")
            .to_string();
        let entry = by_day.entry(day).or_insert((0, 0));
        entry.0 += 1;
        if rec.success {
            entry.1 += 1;
        }
    }

    let recent_days: Vec<_> = by_day.into_iter().rev().take(7).collect();
    println!("\n{}", t!("cli.stats_recent_days").cyan().bold());
    println!(
        "  {:<14} {:<10} {:<10} {}",
        "DATE".dimmed(),
        "RUNS".dimmed(),
        "PASS".dimmed(),
        "FAIL".dimmed()
    );
    for (day, (d_tot, d_succ)) in recent_days.into_iter().rev() {
        let d_fail = d_tot - d_succ;
        println!(
            "  {:<14} {:<10} {:<10} {}",
            day,
            d_tot,
            d_succ.to_string().green(),
            d_fail.to_string().red()
        );
    }

    if let Some(last_succ) = slice.iter().find(|r| r.success) {
        println!(
            "\n  {} {} ({})",
            t!("cli.stats_last_success").dimmed(),
            last_succ.id.yellow(),
            last_succ.timestamp
        );
    }
    println!();

    Ok(())
}

pub async fn run_diagnose(
    serial: Option<String>,
    mode: TransportMode,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!("{} {}", "[ .. ]".cyan(), t!("cli.diagnose_collecting"));
    let transport = resolve_transport(serial, mode).await?;

    let mut report = String::with_capacity(8192);
    report.push_str(
        "================================================================================\n",
    );
    report.push_str(&format!(
        "RootMyVivo-RS Diagnostics Report - v{}\n",
        env!("CARGO_PKG_VERSION")
    ));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    report.push_str(&format!("Timestamp: {} (epoch seconds)\n", now));
    report.push_str(
        "================================================================================\n\n",
    );

    report.push_str("--- [1. Device Information] ---\n");
    match transport.get_device_info().await {
        Ok(dev) => {
            report.push_str(&format!("Brand:             {}\n", dev.brand));
            report.push_str(&format!("Model:             {}\n", dev.model));
            report.push_str(&format!("Device Code:       {}\n", dev.device));
            report.push_str(&format!("Kernel Version:    {}\n", dev.kernel_full));
            report.push_str(&format!("Boot ID:           {}\n", dev.boot_id));
            report.push_str(&format!(
                "GKI Commit ID:     {}\n",
                dev.gki_git_id.as_deref().unwrap_or("-")
            ));
            report.push_str(&format!(
                "ABOGKI Fingerprint:{}\n",
                dev.abogki_fingerprint.as_deref().unwrap_or("-")
            ));
        }
        Err(e) => {
            report.push_str(&format!("<unavailable: get_device_info error: {}>\n", e));
        }
    }
    report.push('\n');

    report.push_str("--- [2. Boot & Security Properties] ---\n");
    match transport.exec("getprop sys.boot_completed").await {
        Ok((_, out)) => report.push_str(&format!("sys.boot_completed: {}\n", out.trim())),
        Err(e) => report.push_str(&format!("sys.boot_completed: <error: {}>\n", e)),
    }
    match transport.exec("getenforce").await {
        Ok((_, out)) => report.push_str(&format!("SELinux Enforce:    {}\n", out.trim())),
        Err(e) => report.push_str(&format!("SELinux Enforce:    <error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [3. Root Status & Kernel Modules] ---\n");
    match rmv_core::check_root_status(&transport).await {
        Ok(st) => report.push_str(&format!("Root Status: {:?}\n", st)),
        Err(e) => report.push_str(&format!("Root Status: <error: {}>\n", e)),
    }
    match transport
        .exec("cat /proc/modules 2>/dev/null | grep -iE 'kernelsu|linjector'")
        .await
    {
        Ok((_, out)) if !out.trim().is_empty() => {
            report.push_str(&format!("Modules (shell):\n{}\n", out.trim()))
        }
        _ => {
            match transport.exec("/system/bin/su -c 'cat /proc/modules' 2>/dev/null | grep -iE 'kernelsu|linjector'").await {
                Ok((_, out)) if !out.trim().is_empty() => report.push_str(&format!("Modules (su):\n{}\n", out.trim())),
                _ => report.push_str("Modules: <none or unreadable>\n"),
            }
        }
    }
    report.push('\n');

    report.push_str("--- [4. /data/local/tmp/rmv Residue] ---\n");
    match transport.exec("ls -la /data/local/tmp/rmv/ 2>&1").await {
        Ok((_, out)) => report.push_str(&format!("{}\n", out.trim())),
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [5. Ksud Status] ---\n");
    let ksud_cmd = "if [ -f /data/adb/ksu/bin/ksud ]; then /data/adb/ksu/bin/ksud debug info 2>&1; elif [ -f /data/local/tmp/rmv/ksud ]; then /data/local/tmp/rmv/ksud debug info 2>&1; else echo 'ksud not found'; fi";
    match transport.exec(ksud_cmd).await {
        Ok((_, out)) => report.push_str(&format!("{}\n", out.trim())),
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [6. Installed KSU Managers] ---\n");
    let pm_cmd = "for p in com.resukisu.resukisu com.sukisu.ultra me.weishu.kernelsu com.rifsxd.ksunext; do if path=$(pm path $p 2>/dev/null) && [ -n \"$path\" ]; then echo \"$p: $path\"; fi; done";
    match transport.exec(pm_cmd).await {
        Ok((_, out)) => {
            if out.trim().is_empty() {
                report.push_str("<no supported manager app installed>\n");
            } else {
                report.push_str(&format!("{}\n", out.trim()));
            }
        }
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [7. Recent Logcat (last 200 lines)] ---\n");
    match transport.exec("logcat -d -t 200 2>&1").await {
        Ok((_, out)) => report.push_str(&format!("{}\n", out.trim())),
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [8. Kernel Dmesg (last 200 lines)] ---\n");
    match transport.exec("dmesg 2>/dev/null | tail -n 200").await {
        Ok((_, out)) if !out.trim().is_empty() => report.push_str(&format!("{}\n", out.trim())),
        _ => match transport
            .exec("/system/bin/su -c 'dmesg' 2>/dev/null | tail -n 200")
            .await
        {
            Ok((_, out)) if !out.trim().is_empty() => report.push_str(&format!("{}\n", out.trim())),
            _ => report.push_str("<dmesg restricted or empty>\n"),
        },
    }
    report.push('\n');

    let out_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir)?;

    let zip_filename = format!("rmv-diagnose-{}.zip", now);
    let zip_path = out_dir.join(&zip_filename);

    let file = std::fs::File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    use std::io::Write;
    zip.start_file("report.txt", options)?;
    zip.write_all(report.as_bytes())?;

    let hist_dir = HistoryManager::default_dir();
    if let Ok(records) = HistoryManager::list_records(&hist_dir).await {
        for rec in records.iter().take(5) {
            let fname = format!("history/{}.json", rec.id);
            if let Ok(json) = serde_json::to_vec_pretty(rec) {
                let _ = zip.start_file(fname, options);
                let _ = zip.write_all(&json);
            }
        }
    }

    zip.finish()?;

    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.diagnose_done", path = zip_path.display().to_string()).green()
    );

    Ok(())
}

pub async fn run_manager_download(
    ksu: String,
    version: Option<String>,
    mirror: Option<String>,
) -> Result<()> {
    let variant = KsuVariant::from_id(&ksu);
    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("log.manager_auto_download", name = variant.display_name())
    );
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut ui = CliUi::new();
    let ui_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            ui.handle_event(event);
        }
    });

    let path = rmv_core::ManagerDownloader::download_manager_default(
        variant,
        version.as_deref(),
        None,
        mirror.as_deref(),
        Some(&event_tx),
    )
    .await?;

    drop(event_tx);
    let _ = ui_handle.await;
    println!(
        "{} {} -> {}",
        "[ ok ]".green().bold(),
        variant.display_name(),
        path.display()
    );
    Ok(())
}

pub async fn run_manager_list() -> Result<()> {
    let list = rmv_core::ManagerDownloader::list_cached_managers(None);
    println!("\n{}", t!("cli.manager_list_about").cyan().bold());
    if list.is_empty() {
        println!("  {}", t!("cli.manager_empty").dimmed());
        return Ok(());
    }
    for item in list {
        let name = item.variant.map(|v| v.display_name()).unwrap_or("Unknown");
        println!(
            "  - {} : {} ({:.1} MB)",
            name.green().bold(),
            item.file_name,
            item.size as f32 / 1024.0 / 1024.0
        );
        println!("    {}", item.path.display().to_string().dimmed());
    }
    println!();
    Ok(())
}

pub async fn run_manager_install(
    serial: Option<String>,
    ksu: String,
    mode: TransportMode,
) -> Result<()> {
    let variant = KsuVariant::from_id(&ksu);
    let list = rmv_core::ManagerDownloader::list_cached_managers(None);
    let found = list.into_iter().find(|m| m.variant == Some(variant));

    let apk_path = match found {
        Some(item) => item.path,
        None => {
            println!(
                "{} {}",
                "[ .. ]".cyan(),
                t!("log.manager_auto_download", name = variant.display_name())
            );
            rmv_core::ManagerDownloader::download_manager_default(variant, None, None, None, None)
                .await?
        }
    };

    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("log.manager_installing", name = variant.display_name())
    );
    let transport = resolve_transport(serial, mode).await?;
    let remote_path = "/data/local/tmp/rmv/manager_install.apk";
    transport.push(&apk_path, remote_path).await?;
    let (code, out) = transport
        .exec(&format!("pm install -r -d {}", remote_path))
        .await?;
    let _ = transport.exec(&format!("rm -f {}", remote_path)).await;

    if code == 0 && (out.contains("Success") || out.is_empty()) {
        println!(
            "{} {}",
            "[ ok ]".green().bold(),
            t!("log.manager_install_ok", name = variant.display_name()).green()
        );
        Ok(())
    } else {
        anyhow::bail!(t!(
            "error.manager_install_failed",
            name = variant.display_name(),
            message = out.trim()
        ))
    }
}

pub async fn run_config_set_mirror(mirror: &str) -> Result<()> {
    rmv_core::MirrorConfig::set_saved_mirror(mirror)?;
    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.config_mirror_saved", mirror = mirror).green()
    );
    Ok(())
}

pub async fn run_config_get_mirror() -> Result<()> {
    println!("\n{}", t!("cli.config_mirror_title").cyan().bold());
    let saved = rmv_core::MirrorConfig::get_saved_mirror();
    let current = saved.as_deref().unwrap_or("Default (direct + mirrors)");
    println!(
        "  {} : {}",
        t!("cli.config_mirror_current"),
        current.green().bold()
    );
    println!();
    Ok(())
}

pub async fn run_config_reset_mirror() -> Result<()> {
    if rmv_core::MirrorConfig::reset_saved_mirror()? {
        println!(
            "{} {}",
            "[ ok ]".green().bold(),
            t!("cli.config_mirror_reset").green()
        );
    } else {
        println!(
            "{} {}",
            "[info]".cyan(),
            t!("cli.config_mirror_already_default")
        );
    }
    Ok(())
}
