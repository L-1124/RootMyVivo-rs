use crate::ui::CliUi;
use anyhow::{Context, Result};
use colored::*;
use rmv_core::{
    AdbCliTransport, CatalogV5, CleanOutcome, EngineOptions, ExploitEngine, GateStatus,
    HistoryManager, KsuVariant, Persistence, Transport,
};
use rust_i18n::t;
use std::path::PathBuf;
use tokio::sync::mpsc;

pub async fn run_check(serial: Option<String>) -> Result<()> {
    println!("{}", t!("cli.probing_device").bold().cyan());
    let transport = AdbCliTransport::resolve(serial).await?;
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
    Ok(())
}

pub async fn run_catalog(serial: Option<String>, catalog_url: Option<String>) -> Result<()> {
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

    let transport = AdbCliTransport::resolve(serial)
        .await
        .unwrap_or_else(|_| AdbCliTransport::new(None));
    if let Ok(dev) = transport.get_device_info().await {
        println!("{}", t!("cli.matching_device").bold().cyan());
        match catalog.match_payload(&dev) {
            Some((device_entry, kernel_build)) => {
                println!(
                    "  {} : {}",
                    t!("cli.matched_device"),
                    device_entry.market_name.bold().green()
                );
                println!(
                    "  {} : {}",
                    t!("cli.payload_status"),
                    kernel_build.status.bold().yellow()
                );
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
) -> Result<()> {
    let transport = AdbCliTransport::resolve(serial).await?;
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

pub async fn run_clean(serial: Option<String>, deep: bool) -> Result<()> {
    let start_msg = if deep {
        t!("cli.cleaning_traces_deep")
    } else {
        t!("cli.cleaning_traces")
    };
    println!("{} {}", "[ .. ]".cyan(), start_msg);
    let transport = AdbCliTransport::resolve(serial).await?;
    let outcome = Persistence::clean_traces(&transport, deep)
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

pub async fn run_history_list() -> Result<()> {
    let dir = HistoryManager::default_dir();
    let records = HistoryManager::list_records(&dir).await?;

    if records.is_empty() {
        println!("{}", t!("cli.history_empty").dimmed());
        return Ok(());
    }

    println!("\n{}", t!("cli.history_title").cyan().bold());
    for rec in records {
        let status = if rec.success {
            "PASS".green().bold()
        } else {
            "FAIL".red().bold()
        };
        println!(
            "  [{}] {} | Device: {} ({}) | KSU: {} | Payload: {}",
            rec.id.yellow(),
            status,
            rec.device_model,
            rec.device_code,
            rec.ksu_variant,
            rec.payload
        );
    }
    println!();
    println!(
        "{} {}",
        t!("cli.history_stored_at"),
        dir.display().to_string().dimmed()
    );
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
