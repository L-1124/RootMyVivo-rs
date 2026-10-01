use crate::ui::CliUi;
use anyhow::{Context, Result};
use colored::*;
use rmv_core::{
    check_root_status, CatalogConfig, CatalogUrlSource, CatalogV5, CleanOutcome, EngineOptions,
    ExploitEngine, GateStatus, HistoryManager, KsuVariant, Persistence, RootStatus, Transport,
    TransportBuilder, TransportMode,
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
    let (resolved_url, _) = CatalogConfig::resolve_url(catalog_url.as_deref());
    let catalog = CatalogV5::fetch_default_with_url(Some(&resolved_url))
        .await
        .context(t!("error.catalog_fetch_failed", message = "network"))?;

    println!(
        "{}",
        t!(
            "cli.catalog_fetched",
            devices = catalog.devices.len().to_string(),
            builds = catalog.builds.len().to_string()
        )
    );

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
) -> Result<()> {
    let transport = resolve_transport(serial, mode).await?;
    let ksu_variant = KsuVariant::from_id(&ksu);

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

    // 失败的后果与动作已由引擎以 [fail] 行给出，这里只透出精确原因。
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
        let status = if rec.success {
            "PASS".green().bold()
        } else {
            "FAIL".red().bold()
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
    let status_str = if rec.success {
        "PASS".green().bold()
    } else {
        "FAIL".red().bold()
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
