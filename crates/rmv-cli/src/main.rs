mod commands;
mod ui;

use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rmv",
    version,
    about = "RootMyVivo-RS: vivo/iQOO 免解锁临时提权与 KernelSU 编排工具 (Rust 版)",
    long_about = "RootMyVivo-RS 为锁定 Bootloader 的 vivo/iQOO 机型提供全自动免解锁提权、KernelSU/SukiSU 动态加载以及本地 ADB 鉴权固化。"
)]
struct Cli {
    /// 目标设备 ADB 序列号（多设备连接时使用）
    #[arg(short, long, global = true)]
    serial: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 检查手机硬件型号、内核版本并评估 CVE-2026-43499 门禁
    Check,

    /// 拉取远程载荷目录并比对当前设备的可用载荷
    Catalog {
        /// 自定义远程 devices.json 目录 URL（支持自建镜像或私有源）
        #[arg(long)]
        catalog_url: Option<String>,
    },

    /// 执行免解锁提权并加载 KernelSU
    Run {
        /// 自定义本地 preload.so 载荷路径（忽略远程目录）
        #[arg(short, long)]
        payload: Option<PathBuf>,

        /// 自定义远程 devices.json 目录 URL（支持自建镜像或私有源）
        #[arg(long)]
        catalog_url: Option<String>,

        /// 指定加载的 KernelSU 变体 (sukisu, kernelsu, next, resukisu)
        #[arg(short, long, default_value = "sukisu")]
        ksu: String,

        /// 仅获取临时 Root，跳过 KernelSU LKM 驱动加载
        #[arg(long, default_value_t = false)]
        skip_ksu: bool,

        /// 最大重试次数
        #[arg(long, default_value_t = 3)]
        attempts: u32,

        /// 重试间隔等待秒数
        #[arg(long, default_value_t = 8)]
        delay: u64,

        /// 是否保存运行历史记录
        #[arg(long, default_value_t = true)]
        save_history: bool,

        /// 执行前先重启手机，确保在全新的干净状态（pristine boot_id）下运行
        #[arg(long, default_value_t = false)]
        reboot_first: bool,

        /// 跳过载荷身份闸门，强制下发该载荷（明知载荷与设备不匹配时使用）
        #[arg(long, default_value_t = false)]
        force_payload: bool,

        /// 本地载荷库目录（可重复指定），身份闸门失败时按本机内核指纹在此回退配对
        #[arg(long = "payload-dir", value_name = "DIR")]
        payload_dirs: Vec<PathBuf>,

        /// 只解析并校验载荷，不下发、不执行
        #[arg(long, default_value_t = false)]
        dry_run: bool,


        /// PC 本地提供的 KernelSU/SukiSU 管理器 APK 路径（用于免预装就地提取 ksud）
        #[arg(long = "manager-apk", value_name = "APK_PATH")]
        manager_apk: Option<PathBuf>,
    },

    /// 清理手机端的临时运行文件与日志
    Clean {
        /// 是否执行深度清理（彻底删除残留 socket、旧 su 守护进程、缓存等）
        #[arg(long, default_value_t = false)]
        deep: bool,
    },

    /// 查看或管理本地提权运行历史记录
    History {
        #[command(subcommand)]
        action: Option<HistoryAction>,
    },
}

#[derive(Subcommand)]
enum HistoryAction {
    /// 列出所有历史运行记录
    List,
    /// 清除所有历史运行记录
    Clear,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check => commands::run_check(cli.serial).await?,
        Commands::Catalog { catalog_url } => commands::run_catalog(cli.serial, catalog_url).await?,
        Commands::Run {
            payload,
            catalog_url,
            ksu,
            skip_ksu,
            attempts,
            delay,
            save_history,
            reboot_first,
            force_payload,
            payload_dirs,
            dry_run,
            manager_apk,
        } => {
            commands::run_exploit(
                cli.serial,
                payload,
                catalog_url,
                ksu,
                skip_ksu,
                attempts,
                delay,
                save_history,
                reboot_first,
                force_payload,
                payload_dirs,
                dry_run,
                manager_apk,
            )
            .await?
        }
        Commands::Clean { deep } => commands::run_clean(cli.serial, deep).await?,
        Commands::History { action } => match action.unwrap_or(HistoryAction::List) {
            HistoryAction::List => commands::run_history_list().await?,
            HistoryAction::Clear => commands::run_history_clear().await?,
        },
    }

    Ok(())
}
