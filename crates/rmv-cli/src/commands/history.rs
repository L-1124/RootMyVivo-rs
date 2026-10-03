use anyhow::Result;
use colored::Colorize;
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
    let Some(rec) = HistoryManager::get_record(&dir, id).await? else {
        anyhow::bail!(t!("cli.history_not_found", id = id));
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
    println!("  Status     : {status_str}");
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

#[derive(Debug, Clone, PartialEq)]
pub struct VariantStats {
    pub total: usize,
    pub success: usize,
    pub rate: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DayStats {
    pub date: String,
    pub total: usize,
    pub success: usize,
    pub failure: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatsSummary {
    pub total: usize,
    pub successes: usize,
    pub failures: usize,
    pub rate: f64,
    pub by_variant: std::collections::BTreeMap<String, VariantStats>,
    pub recent_days: Vec<DayStats>,
    pub last_success: Option<(String, String)>,
}

#[expect(
    clippy::cast_precision_loss,
    reason = "Percentage rate calculations from small record counts"
)]
pub fn aggregate_stats(slice: &[rmv_core::RunRecord]) -> StatsSummary {
    let total = slice.len();
    let successes = slice.iter().filter(|r| r.success).count();
    let failures = total - successes;
    let rate = if total > 0 {
        (successes as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let mut variant_map: std::collections::BTreeMap<&str, (usize, usize)> =
        std::collections::BTreeMap::new();
    for rec in slice {
        let entry = variant_map
            .entry(rec.ksu_variant.as_str())
            .or_insert((0, 0));
        entry.0 += 1;
        if rec.success {
            entry.1 += 1;
        }
    }

    let mut by_variant = std::collections::BTreeMap::new();
    for (variant, (v_tot, v_succ)) in variant_map {
        let v_rate = if v_tot > 0 {
            (v_succ as f64 / v_tot as f64) * 100.0
        } else {
            0.0
        };
        by_variant.insert(
            variant.to_string(),
            VariantStats {
                total: v_tot,
                success: v_succ,
                rate: v_rate,
            },
        );
    }

    let mut day_map: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for rec in slice {
        let day = rec
            .timestamp
            .split([' ', 'T'])
            .next()
            .unwrap_or("unknown")
            .to_string();
        let entry = day_map.entry(day).or_insert((0, 0));
        entry.0 += 1;
        if rec.success {
            entry.1 += 1;
        }
    }

    let raw_recent: Vec<_> = day_map.into_iter().rev().take(7).collect();
    let recent_days = raw_recent
        .into_iter()
        .rev()
        .map(|(date, (d_tot, d_succ))| DayStats {
            date,
            total: d_tot,
            success: d_succ,
            failure: d_tot - d_succ,
        })
        .collect();

    let last_success = slice
        .iter()
        .find(|r| r.success)
        .map(|r| (r.id.clone(), r.timestamp.clone()));

    StatsSummary {
        total,
        successes,
        failures,
        rate,
        by_variant,
        recent_days,
        last_success,
    }
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
    let summary = aggregate_stats(slice);

    println!("\n{}", t!("cli.stats_title").cyan().bold());
    println!(
        "  {:<24} {}",
        t!("cli.stats_total_runs"),
        summary.total.to_string().bold()
    );
    println!(
        "  {:<24} {}",
        t!("cli.stats_success"),
        summary.successes.to_string().green().bold()
    );
    println!(
        "  {:<24} {}",
        t!("cli.stats_failure"),
        summary.failures.to_string().red().bold()
    );
    println!(
        "  {:<24} {:.1}%",
        t!("cli.stats_success_rate"),
        summary.rate
    );

    println!("\n{}", t!("cli.stats_by_variant").cyan().bold());
    println!(
        "  {:<16} {:<10} {:<10} {}",
        "VARIANT".dimmed(),
        "TOTAL".dimmed(),
        "SUCCESS".dimmed(),
        "RATE".dimmed()
    );
    for (variant, v_stat) in &summary.by_variant {
        println!(
            "  {:<16} {:<10} {:<10} {:.1}%",
            variant.yellow(),
            v_stat.total,
            v_stat.success.to_string().green(),
            v_stat.rate
        );
    }

    println!("\n{}", t!("cli.stats_recent_days").cyan().bold());
    println!(
        "  {:<14} {:<10} {:<10} {}",
        "DATE".dimmed(),
        "RUNS".dimmed(),
        "PASS".dimmed(),
        "FAIL".dimmed()
    );
    for d in &summary.recent_days {
        println!(
            "  {:<14} {:<10} {:<10} {}",
            d.date,
            d.total,
            d.success.to_string().green(),
            d.failure.to_string().red()
        );
    }

    if let Some((id, ts)) = &summary.last_success {
        println!(
            "\n  {} {} ({})",
            t!("cli.stats_last_success").dimmed(),
            id.yellow(),
            ts
        );
    }
    println!();

    Ok(())
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::expect_used))]
mod tests {
    use super::*;
    use rmv_core::RunRecord;

    #[test]
    fn test_aggregate_stats_empty_and_populated() {
        let empty_summary = aggregate_stats(&[]);
        assert_eq!(empty_summary.total, 0);
        assert_eq!(empty_summary.successes, 0);
        assert_eq!(empty_summary.failures, 0);
        assert!(empty_summary.rate.abs() < f64::EPSILON);
        assert!(empty_summary.by_variant.is_empty());
        assert_eq!(empty_summary.recent_days, [] as [DayStats; 0]);
        assert_eq!(empty_summary.last_success, None);

        let r1 = RunRecord {
            id: "run-1".to_string(),
            timestamp: "2026-03-30 12:00:00".to_string(),
            device_model: "vivo X Note".to_string(),
            device_code: "V2183A".to_string(),
            kernel: "5.10.101".to_string(),
            payload: "payload.so".to_string(),
            ksu_variant: "kernelsu".to_string(),
            success: true,
            status: None,
            message: "ok".to_string(),
            logs: vec![],
        };

        let r2 = RunRecord {
            id: "run-2".to_string(),
            timestamp: "2026-03-30 12:05:00".to_string(),
            device_model: "vivo X Note".to_string(),
            device_code: "V2183A".to_string(),
            kernel: "5.10.101".to_string(),
            payload: "payload.so".to_string(),
            ksu_variant: "kernelsu".to_string(),
            success: false,
            status: None,
            message: "fail".to_string(),
            logs: vec![],
        };

        let r3 = RunRecord {
            id: "run-3".to_string(),
            timestamp: "2026-03-31 09:00:00".to_string(),
            device_model: "vivo X90".to_string(),
            device_code: "V2241A".to_string(),
            kernel: "5.15.78".to_string(),
            payload: "payload2.so".to_string(),
            ksu_variant: "sukisu".to_string(),
            success: true,
            status: None,
            message: "ok".to_string(),
            logs: vec![],
        };
        let records = vec![r1.clone(), r2, r3];
        let summary = aggregate_stats(&records);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.successes, 2);
        assert_eq!(summary.failures, 1);
        assert!((summary.rate - 66.666).abs() < 0.1);

        let ksu_stats = summary
            .by_variant
            .get("kernelsu")
            .expect("kernelsu stats must exist");
        assert_eq!(ksu_stats.total, 2);
        assert_eq!(ksu_stats.success, 1);
        assert!((ksu_stats.rate - 50.0).abs() < f64::EPSILON);

        let suki_stats = summary
            .by_variant
            .get("sukisu")
            .expect("sukisu stats must exist");
        assert_eq!(suki_stats.total, 1);
        assert_eq!(suki_stats.success, 1);
        assert!((suki_stats.rate - 100.0).abs() < f64::EPSILON);
        assert_eq!(summary.recent_days.len(), 2);
        assert_eq!(summary.last_success, Some((r1.id, r1.timestamp)));
    }
}
