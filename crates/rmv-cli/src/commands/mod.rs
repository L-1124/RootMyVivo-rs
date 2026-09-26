use std::path::PathBuf;
use anyhow::{Context, Result};
use colored::*;
use rmv_core::{
    AdbCliTransport, CatalogV5, CleanOutcome, EngineOptions, ExploitEngine, GateStatus,
    HistoryManager, KsuVariant, Persistence, Transport,
};
use tokio::sync::mpsc;
use crate::ui::CliUi;

pub async fn run_check(serial: Option<String>) -> Result<()> {
    println!("{}", "正在检测 ADB 连接与设备环境...".bold().cyan());
    let transport = AdbCliTransport::new(serial);
    let dev = transport
        .get_device_info()
        .await
        .context("获取设备环境失败，请确认手机已开启 USB 调试且已授权电脑")?;

    println!("\n{}", "设备环境摘要".cyan().bold());
    println!("  设备代号 : {}", dev.device.bold().green());
    println!("  营销型号 : {}", dev.model.bold().green());
    println!("  品牌厂商 : {}", dev.brand.bold().green());
    println!(
        "  内核版本 : Linux {}.{}.{}",
        dev.kernel_version.0, dev.kernel_version.1, dev.kernel_version.2
    );
    println!(
        "  GKI 构建 : {}",
        dev.gki_git_id.as_deref().unwrap_or("未识别").yellow()
    );
    println!(
        "  Build 指纹: {}",
        dev.abogki_fingerprint.as_deref().unwrap_or("未识别").yellow()
    );
    println!("  Boot ID  : {}", dev.boot_id.dimmed());
    println!();

    match dev.evaluate_gate() {
        GateStatus::Vulnerable => {
            println!(
                "  安全门禁 : {} {}",
                "通过".bold().green(),
                "(CVE-2026-43499 未修补，支持免解锁提权)".dimmed()
            );
        }
        GateStatus::Patched { version, reason } => {
            println!(
                "  安全门禁 : {} {}",
                "拦截".bold().red(),
                format!("(内核版本 {}: {})", version, reason).red()
            );
        }
        GateStatus::UnsupportedVersion(v) => {
            println!(
                "  安全门禁 : {} {}",
                "拦截".bold().yellow(),
                format!("(内核版本 {} 不在受支持序列)", v).yellow()
            );
        }
    }
    println!();
    Ok(())
}

pub async fn run_catalog(serial: Option<String>, catalog_url: Option<String>) -> Result<()> {
    println!("{}", "正在从载荷目录源获取最新清单...".bold().cyan());
    let catalog = CatalogV5::fetch_default_with_url(catalog_url.as_deref())
        .await
        .context("拉取 devices.json 目录清单失败")?;

    println!(
        "成功拉取编目，共收录 {} 款设备、{} 个内核载荷构建。\n",
        catalog.devices.len(),
        catalog.builds.len()
    );

    let transport = AdbCliTransport::new(serial);
    if let Ok(dev) = transport.get_device_info().await {
        println!("{}", "正在比对当前连接设备:".bold().cyan());
        match catalog.match_payload(&dev) {
            Some((device_entry, kernel_build)) => {
                println!("  匹配设备 : {}", device_entry.market_name.bold().green());
                println!("  载荷状态 : {}", kernel_build.status.bold().yellow());
                if let Some(file) = &kernel_build.file {
                    println!("  载荷文件 : {} ({} 字节)", file.name.green(), file.size);
                    println!("  下载地址 : {}", file.url.dimmed());
                }
            }
            None => {
                println!(
                    "  {}",
                    "未在当前目录中匹配到此设备的专用载荷。".yellow()
                );
            }
        }
    } else {
        println!("{}", "（当前未检测到 ADB 手机连接，可单独运行 `rmv check` 诊断）".dimmed());
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
) -> Result<()> {
    let transport = AdbCliTransport::new(serial);
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

    res.context("提权执行异常")
}

pub async fn run_clean(serial: Option<String>, deep: bool) -> Result<()> {
    let mode_desc = if deep { "深度清理模式 (含残留 su/socket/daemon 日志)" } else { "基础清理模式" };
    println!("{} ({})", "正在清理手机上的临时提权痕迹...".bold().cyan(), mode_desc);
    let transport = AdbCliTransport::new(serial);
    let outcome = Persistence::clean_traces(&transport, deep)
        .await
        .context("清理痕迹失败")?;
    match outcome {
        CleanOutcome::WithRoot => {
            println!("{}", "设备临时目录与残留已清理完成（root 权限）".bold().green());
        }
        CleanOutcome::ShellOnly => {
            println!("{}", "已以 shell 身份清理当前临时文件".bold().green());
            println!(
                "{}",
                "  设备当前无 root，root 属主的残留（旧 su / socket）未被移除".yellow()
            );
        }
    }
    Ok(())
}

pub async fn run_history_list() -> Result<()> {
    let dir = HistoryManager::default_dir();
    let records = HistoryManager::list_records(&dir).await?;

    if records.is_empty() {
        println!("{}", "暂无历史运行记录。".dimmed());
        return Ok(());
    }

    println!("\n{}", "运行历史记录".cyan().bold());
    for rec in records {
        let status = if rec.success {
            "成功".green().bold()
        } else {
            "失败".red().bold()
        };
        println!(
            "  [{}] {} | 设备: {} ({}) | KSU: {} | 载荷: {}",
            rec.id.yellow(),
            status,
            rec.device_model,
            rec.device_code,
            rec.ksu_variant,
            rec.payload
        );
    }
    println!();
    println!("历史文件存储在: {}", dir.display().to_string().dimmed());
    println!();
    Ok(())
}

pub async fn run_history_clear() -> Result<()> {
    let dir = HistoryManager::default_dir();
    let count = HistoryManager::clear_records(&dir).await?;
    println!("已清除 {} 条历史运行记录。", count.to_string().green().bold());
    Ok(())
}
