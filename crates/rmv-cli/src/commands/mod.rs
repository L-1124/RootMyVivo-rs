use crate::ui::CliUi;
use anyhow::{Context, Result};
use colored::*;
use rmv_core::{
    check_root_status, CatalogV5, CleanOutcome, EngineOptions, ExploitEngine, GateStatus,
    HistoryManager, KsuVariant, Persistence, RootStatus, Transport, TransportBuilder,
    TransportMode,
};
use rust_i18n::t;
use std::path::PathBuf;
use tokio::sync::mpsc;

pub async fn run_check(serial: Option<String>, mode: TransportMode) -> Result<()> {
    println!("{}", t!("cli.probing_device").bold().cyan());
    let transport = TransportBuilder::resolve(serial, mode).await?;
    let dev = transport
        .get_device_info()
        .await
        .context(t!("error.device_not_found", message = "ADB"))?;

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
        RootStatus::KernelSu { su_path } => {
            format!("{} (KernelSU Live, {})", t!("cli.root_ksu_active"), su_path)
                .bold()
                .green()
        }
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
    } else if root_status.is_rooted() {
        println!("[info] {}", t!("cli.info_root_already").cyan());
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

    println!(
        "{}",
        t!(
            "cli.catalog_fetched",
            devices = catalog.devices.len().to_string(),
            builds = catalog.builds.len().to_string()
        )
    );

    if let Ok(transport) = TransportBuilder::resolve(serial, mode).await {
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
    timeout_secs: u64,
    mode: TransportMode,
) -> Result<()> {
    let transport = TransportBuilder::resolve(serial, mode).await?;
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
    let transport = TransportBuilder::resolve(serial, mode).await?;
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
pub async fn run_pair(addr: &str, code: &str) -> Result<()> {
    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("cli.pairing_connecting", addr = addr)
    );
    rmv_core::AdbPairing::pair(addr, code)
        .await
        .context(t!("error.pairing_failed"))?;
    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.pairing_success").green().bold()
    );
    println!(
        "{} {}",
        "[info]".cyan(),
        t!("cli.pairing_saved_hint").dimmed()
    );
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
