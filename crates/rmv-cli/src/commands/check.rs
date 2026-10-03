use super::resolve_transport;
use anyhow::Result;
use colored::*;
use rmv_core::{
    check_root_status, GateStatus, KsuOrchestrator, RootStatus, TransportExt, TransportMode,
};
use rust_i18n::t;

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
        _ => format!("{}", t!("cli.root_not_rooted")).bold().yellow(),
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
        _ => {}
    }
    println!();
    if root_status.is_exploit_running() {
        println!("[warn] {}", t!("cli.warn_exploit_running").yellow());
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn check_device(serial: Option<String>, mode: TransportMode) -> Result<()> {
    run_check(serial, mode).await
}
