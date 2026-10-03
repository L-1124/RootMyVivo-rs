use super::resolve_transport;
use anyhow::Result;
use colored::*;
use rmv_core::{HistoryManager, TransportExt, TransportMode};
use rust_i18n::t;
use std::path::PathBuf;

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
        .map_or(0, |d| d.as_secs());
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
        Ok(out) => report.push_str(&format!("sys.boot_completed: {}\n", out.stdout.trim())),
        Err(e) => report.push_str(&format!("sys.boot_completed: <error: {}>\n", e)),
    }
    match transport.exec("getenforce").await {
        Ok(out) => report.push_str(&format!("SELinux Enforce:    {}\n", out.stdout.trim())),
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
        Ok(out) if !out.combined().trim().is_empty() => {
            report.push_str(&format!("Modules (shell):\n{}\n", out.combined().trim()));
        }
        _ => {
            match transport.exec("/system/bin/su -c 'cat /proc/modules' 2>/dev/null | grep -iE 'kernelsu|linjector'").await {
                Ok(out) if !out.combined().trim().is_empty() => report.push_str(&format!("Modules (su):\n{}\n", out.combined().trim())),
                _ => report.push_str("Modules: <none or unreadable>\n"),
            }
        }
    }
    report.push('\n');

    report.push_str("--- [4. /data/local/tmp/rmv Residue] ---\n");
    match transport.exec("ls -la /data/local/tmp/rmv/ 2>&1").await {
        Ok(out) => report.push_str(&format!("{}\n", out.combined().trim())),
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [5. Ksud Status] ---\n");
    let ksud_cmd = "if [ -f /data/adb/ksu/bin/ksud ]; then /data/adb/ksu/bin/ksud debug info 2>&1; elif [ -f /data/local/tmp/rmv/ksud ]; then /data/local/tmp/rmv/ksud debug info 2>&1; else echo 'ksud not found'; fi";
    match transport.exec(ksud_cmd).await {
        Ok(out) => report.push_str(&format!("{}\n", out.combined().trim())),
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [6. Installed KSU Managers] ---\n");
    let pm_cmd = "for p in com.resukisu.resukisu com.sukisu.ultra me.weishu.kernelsu com.rifsxd.ksunext; do if path=$(pm path $p 2>/dev/null) && [ -n \"$path\" ]; then echo \"$p: $path\"; fi; done";
    match transport.exec(pm_cmd).await {
        Ok(out) => {
            if out.stdout.trim().is_empty() {
                report.push_str("<no supported manager app installed>\n");
            } else {
                report.push_str(&format!("{}\n", out.stdout.trim()));
            }
        }
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [7. Recent Logcat (last 200 lines)] ---\n");
    match transport.exec("logcat -d -t 200 2>&1").await {
        Ok(out) => report.push_str(&format!("{}\n", out.combined().trim())),
        Err(e) => report.push_str(&format!("<error: {}>\n", e)),
    }
    report.push('\n');

    report.push_str("--- [8. Kernel Dmesg (last 200 lines)] ---\n");
    match transport.exec("dmesg 2>/dev/null | tail -n 200").await {
        Ok(out) if !out.stdout.trim().is_empty() => {
            report.push_str(&format!("{}\n", out.stdout.trim()));
        }
        _ => match transport
            .exec("/system/bin/su -c 'dmesg' 2>/dev/null | tail -n 200")
            .await
        {
            Ok(out) if !out.combined().trim().is_empty() => {
                report.push_str(&format!("{}\n", out.combined().trim()));
            }
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
