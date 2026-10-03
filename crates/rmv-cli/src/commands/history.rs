use anyhow::Result;
use colored::*;
use rmv_core::HistoryManager;
use rust_i18n::t;

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
            rmv_core::RunStatus::Running => "RUNNING".cyan().bold(),
            rmv_core::RunStatus::Fail => "FAIL".red().bold(),
            _ => "UNKNOWN".dimmed(),
        };

        let short_payload = std::path::Path::new(&rec.payload)
            .file_name()
            .map_or_else(|| rec.payload.clone(), |f| f.to_string_lossy().to_string());

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
            anyhow::bail!(t!("cli.history_not_found", id = id));
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
        rmv_core::RunStatus::Running => "RUNNING".cyan().bold(),
        rmv_core::RunStatus::Fail => "FAIL".red().bold(),
        _ => "UNKNOWN".dimmed(),
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
