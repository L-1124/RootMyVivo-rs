rust_i18n::i18n!("../rmv-core/locales", fallback = "en");

mod commands;
mod ui;

use std::path::PathBuf;
use clap::{Arg, ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand};
use rmv_core::{set_current_language, Language};
use rust_i18n::t;

#[derive(Parser)]
#[command(name = "rmv", version)]
struct Cli {
    #[arg(short, long, global = true)]
    serial: Option<String>,

    #[arg(short = 'L', long, global = true)]
    lang: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Check,

    Catalog {
        #[arg(long)]
        catalog_url: Option<String>,
    },

    Run {
        #[arg(short, long)]
        payload: Option<PathBuf>,

        #[arg(long)]
        catalog_url: Option<String>,

        #[arg(short, long, default_value = "sukisu")]
        ksu: String,

        #[arg(long, default_value_t = false)]
        skip_ksu: bool,

        #[arg(long, default_value_t = 3)]
        attempts: u32,

        #[arg(long, default_value_t = 8)]
        delay: u64,

        #[arg(long, default_value_t = true)]
        save_history: bool,

        #[arg(long, default_value_t = false)]
        reboot_first: bool,

        #[arg(long, default_value_t = false)]
        force_payload: bool,

        #[arg(long = "payload-dir", value_name = "DIR")]
        payload_dirs: Vec<PathBuf>,

        #[arg(long, default_value_t = false)]
        dry_run: bool,

        #[arg(long = "manager-apk", value_name = "APK_PATH")]
        manager_apk: Option<PathBuf>,

        #[arg(long, default_value_t = 900)]
        timeout: u64,

        #[arg(long, default_value_t = false)]
        allow_dirty_boot: bool,
    },

    Clean {
        #[arg(long, default_value_t = false)]
        deep: bool,
    },

    History {
        #[command(subcommand)]
        action: Option<HistoryAction>,
    },
}

#[derive(Subcommand)]
enum HistoryAction {
    List,
    Clear,
}

fn early_detect_language() -> Language {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if (args[i] == "-L" || args[i] == "--lang") && i + 1 < args.len() {
            return Language::from_code(&args[i + 1]);
        }
        if let Some(rest) = args[i].strip_prefix("--lang=") {
            return Language::from_code(rest);
        }
    }
    Language::detect_system()
}

fn localize_command(cmd: clap::Command) -> clap::Command {
    cmd.about(t!("cli.app_about").to_string())
        .long_about(t!("cli.app_long_about").to_string())
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .global(true)
                .help(t!("cli.arg_help").to_string()),
        )
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help(t!("cli.arg_version").to_string()),
        )
        .disable_help_subcommand(true)
        .subcommand(
            clap::Command::new("help")
                .about(t!("cli.help_subcmd").to_string()),
        )
        .mut_arg("serial", |a| a.help(t!("cli.arg_serial").to_string()))
        .mut_arg("lang", |a| a.help(t!("cli.arg_lang").to_string()))
        .mut_subcommand("check", |sc| sc.about(t!("cli.check_about").to_string()))
        .mut_subcommand("catalog", |sc| {
            sc.about(t!("cli.catalog_about").to_string())
                .mut_arg("catalog_url", |a| a.help(t!("cli.arg_catalog_url").to_string()))
        })
        .mut_subcommand("run", |sc| {
            sc.about(t!("cli.run_about").to_string())
                .mut_arg("payload", |a| a.help(t!("cli.arg_payload").to_string()))
                .mut_arg("catalog_url", |a| a.help(t!("cli.arg_catalog_url").to_string()))
                .mut_arg("ksu", |a| a.help(t!("cli.arg_ksu").to_string()))
                .mut_arg("skip_ksu", |a| a.help(t!("cli.arg_skip_ksu").to_string()))
                .mut_arg("attempts", |a| a.help(t!("cli.arg_attempts").to_string()))
                .mut_arg("delay", |a| a.help(t!("cli.arg_delay").to_string()))
                .mut_arg("save_history", |a| a.help(t!("cli.arg_save_history").to_string()))
                .mut_arg("reboot_first", |a| a.help(t!("cli.arg_reboot_first").to_string()))
                .mut_arg("force_payload", |a| a.help(t!("cli.arg_force_payload").to_string()))
                .mut_arg("payload_dirs", |a| a.help(t!("cli.arg_payload_dir").to_string()))
                .mut_arg("dry_run", |a| a.help(t!("cli.arg_dry_run").to_string()))
                .mut_arg("manager_apk", |a| a.help(t!("cli.arg_manager_apk").to_string()))
                .mut_arg("timeout", |a| a.help(t!("cli.arg_timeout").to_string()))
                .mut_arg("allow_dirty_boot", |a| a.help(t!("cli.arg_allow_dirty_boot").to_string()))
        })
        .mut_subcommand("clean", |sc| {
            sc.about(t!("cli.clean_about").to_string())
                .mut_arg("deep", |a| a.help(t!("cli.arg_deep").to_string()))
        })
        .mut_subcommand("history", |sc| {
            sc.about(t!("cli.history_about").to_string())
                .mut_subcommand("list", |s| s.about(t!("cli.history_list_about").to_string()))
                .mut_subcommand("clear", |s| s.about(t!("cli.history_clear_about").to_string()))
        })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let initial_lang = early_detect_language();
    set_current_language(initial_lang);
    rust_i18n::set_locale(initial_lang.code());

    let cmd = localize_command(Cli::command());
    let matches = cmd.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    if let Some(l) = &cli.lang {
        let selected = Language::from_code(l);
        set_current_language(selected);
        rust_i18n::set_locale(selected.code());
    }

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
            timeout,
            allow_dirty_boot,
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
                timeout,
                allow_dirty_boot,
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
