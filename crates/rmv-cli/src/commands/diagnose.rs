use super::resolve_transport;
use anyhow::Result;
use colored::Colorize;
use rmv_core::{HistoryManager, TransportExt, TransportMode};
use rust_i18n::t;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;

pub async fn run_diagnose(
    serial: Option<String>,
    mode: TransportMode,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    println!("{} {}", "[ .. ]".cyan(), t!("cli.diagnose_collecting"));

    let transport = resolve_transport(serial, mode).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let report = collect_diagnostics_report(&transport, now).await;

    let out_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let zip_path = build_zip(&out_dir, now, &report).await?;

    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.diagnose_done", path = zip_path.display().to_string()).green()
    );

    Ok(())
}

async fn collect_diagnostics_report(
    transport: &std::sync::Arc<dyn rmv_core::Transport>,
    now: u64,
) -> String {
    let mut report = String::with_capacity(8192);
    append_report_header(&mut report, now);
    append_device_section(&mut report, transport).await;
    append_boot_and_root_section(&mut report, transport).await;
    append_residue_and_ksud_section(&mut report, transport).await;
    append_logs_section(&mut report, transport).await;
    report
}

fn append_report_header(report: &mut String, now: u64) {
    let _ = writeln!(
        report,
        "================================================================================"
    );
    let _ = writeln!(
        report,
        "RootMyVivo-RS Diagnostics Report - v{}",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(report, "Timestamp: {now} (epoch seconds)");
    let _ = writeln!(
        report,
        "================================================================================\n"
    );
}

async fn append_device_section(
    report: &mut String,
    transport: &std::sync::Arc<dyn rmv_core::Transport>,
) {
    let _ = writeln!(report, "--- [1. Device Information] ---");
    match transport.get_device_info().await {
        Ok(dev) => {
            let _ = writeln!(report, "Brand:             {}", dev.brand);
            let _ = writeln!(report, "Model:             {}", dev.model);
            let _ = writeln!(report, "Device Code:       {}", dev.device);
            let _ = writeln!(report, "Kernel Version:    {}", dev.kernel_full);
            let _ = writeln!(report, "Boot ID:           {}", dev.boot_id);
            let _ = writeln!(
                report,
                "GKI Commit ID:     {}",
                dev.gki_git_id.as_deref().unwrap_or("-")
            );
            let _ = writeln!(
                report,
                "ABOGKI Fingerprint:{}",
                dev.abogki_fingerprint.as_deref().unwrap_or("-")
            );
        }
        Err(e) => {
            let _ = writeln!(report, "<unavailable: get_device_info error: {e}>");
        }
    }
    report.push('\n');

    let _ = writeln!(report, "--- [2. Boot & Security Properties] ---");
    match transport.exec("getprop sys.boot_completed").await {
        Ok(out) => {
            let _ = writeln!(report, "sys.boot_completed: {}", out.stdout.trim());
        }
        Err(e) => {
            let _ = writeln!(report, "sys.boot_completed: <error: {e}>");
        }
    }
    match transport.exec("getenforce").await {
        Ok(out) => {
            let _ = writeln!(report, "SELinux Enforce:    {}", out.stdout.trim());
        }
        Err(e) => {
            let _ = writeln!(report, "SELinux Enforce:    <error: {e}>");
        }
    }
    report.push('\n');
}

async fn append_boot_and_root_section(
    report: &mut String,
    transport: &std::sync::Arc<dyn rmv_core::Transport>,
) {
    let _ = writeln!(report, "--- [3. Root Status & Kernel Modules] ---");
    match rmv_core::check_root_status(transport).await {
        Ok(st) => {
            let _ = writeln!(report, "Root Status: {st:?}");
        }
        Err(e) => {
            let _ = writeln!(report, "Root Status: <error: {e}>");
        }
    }
    match transport
        .exec("cat /proc/modules 2>/dev/null | grep -iE 'kernelsu|linjector'")
        .await
    {
        Ok(out) if !out.combined().trim().is_empty() => {
            let _ = writeln!(report, "Modules (shell):\n{}", out.combined().trim());
        }
        _ => {
            match transport.exec("/system/bin/su -c 'cat /proc/modules' 2>/dev/null | grep -iE 'kernelsu|linjector'").await {
                Ok(out) if !out.combined().trim().is_empty() => {
                    let _ = writeln!(report, "Modules (su):\n{}", out.combined().trim());
                }
                _ => {
                    let _ = writeln!(report, "Modules: <none or unreadable>");
                }
            }
        }
    }
    report.push('\n');
}

async fn append_residue_and_ksud_section(
    report: &mut String,
    transport: &std::sync::Arc<dyn rmv_core::Transport>,
) {
    let _ = writeln!(report, "--- [4. /data/local/tmp/rmv Residue] ---");
    match transport.exec("ls -la /data/local/tmp/rmv/ 2>&1").await {
        Ok(out) => {
            let _ = writeln!(report, "{}", out.combined().trim());
        }
        Err(e) => {
            let _ = writeln!(report, "<error: {e}>");
        }
    }
    report.push('\n');

    let _ = writeln!(report, "--- [5. Ksud Status] ---");
    let ksud_cmd = "if [ -f /data/adb/ksu/bin/ksud ]; then /data/adb/ksu/bin/ksud debug info 2>&1; elif [ -f /data/local/tmp/rmv/ksud ]; then /data/local/tmp/rmv/ksud debug info 2>&1; else echo 'ksud not found'; fi";
    match transport.exec(ksud_cmd).await {
        Ok(out) => {
            let _ = writeln!(report, "{}", out.combined().trim());
        }
        Err(e) => {
            let _ = writeln!(report, "<error: {e}>");
        }
    }
    report.push('\n');
}

async fn append_logs_section(
    report: &mut String,
    transport: &std::sync::Arc<dyn rmv_core::Transport>,
) {
    let _ = writeln!(report, "--- [6. Installed KSU Managers] ---");
    let pm_cmd = "for p in com.resukisu.resukisu com.sukisu.ultra me.weishu.kernelsu com.rifsxd.ksunext; do if path=$(pm path $p 2>/dev/null) && [ -n \"$path\" ]; then echo \"$p: $path\"; fi; done";
    match transport.exec(pm_cmd).await {
        Ok(out) => {
            if out.stdout.trim().is_empty() {
                let _ = writeln!(report, "<no supported manager app installed>");
            } else {
                let _ = writeln!(report, "{}", out.stdout.trim());
            }
        }
        Err(e) => {
            let _ = writeln!(report, "<error: {e}>");
        }
    }
    report.push('\n');

    let _ = writeln!(report, "--- [7. Recent Logcat (last 200 lines)] ---");
    match transport.exec("logcat -d -t 200 2>&1").await {
        Ok(out) => {
            let _ = writeln!(report, "{}", out.combined().trim());
        }
        Err(e) => {
            let _ = writeln!(report, "<error: {e}>");
        }
    }
    report.push('\n');

    let _ = writeln!(report, "--- [8. Kernel Dmesg (last 200 lines)] ---");
    match transport.exec("dmesg 2>/dev/null | tail -n 200").await {
        Ok(out) if !out.stdout.trim().is_empty() => {
            let _ = writeln!(report, "{}", out.stdout.trim());
        }
        _ => match transport
            .exec("/system/bin/su -c 'dmesg' 2>/dev/null | tail -n 200")
            .await
        {
            Ok(out) if !out.combined().trim().is_empty() => {
                let _ = writeln!(report, "{}", out.combined().trim());
            }
            _ => {
                let _ = writeln!(report, "<dmesg restricted or empty>");
            }
        },
    }
    report.push('\n');
}

async fn build_zip(out_dir: &std::path::Path, now: u64, report: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;

    let zip_filename = format!("rmv-diagnose-{now}.zip");
    let zip_path = out_dir.join(&zip_filename);

    let file = std::fs::File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

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
    Ok(zip_path)
}
