use colored::Colorize;
rust_i18n::i18n!("../rmv-core/locales", fallback = "en");

mod commands;
mod ui;

use clap::{Arg, ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand};
use rmv_core::{set_current_language, Language};
use rust_i18n::t;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rmv", version)]
struct Cli {
    #[arg(short, long, global = true)]
    serial: Option<String>,

    #[arg(short = 'L', long, global = true)]
    lang: Option<String>,

    #[arg(short = 't', long, global = true, default_value = "auto")]
    transport: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Check,

    Catalog {
        #[arg(long)]
        catalog_url: Option<String>,

        #[command(subcommand)]
        action: Option<CatalogAction>,
    },
    Pair {
        #[arg(short, long)]
        list: bool,

        addr: Option<String>,
        code: Option<String>,
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
    },

    Clean,

    History {
        #[command(subcommand)]
        action: Option<HistoryAction>,
    },
}

#[derive(Subcommand)]
enum CatalogAction {
    Show,
    Set {
        #[arg(value_name = "URL")]
        url: String,
    },
    Reset,
}

#[derive(Subcommand)]
enum HistoryAction {
    List {
        #[arg(short, long, default_value_t = 15)]
        limit: usize,
    },
    Show {
        id: String,
    },
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
        .subcommand(clap::Command::new("help").about(t!("cli.help_subcmd").to_string()))
        .mut_arg("serial", |a| a.help(t!("cli.arg_serial").to_string()))
        .mut_arg("lang", |a| a.help(t!("cli.arg_lang").to_string()))
        .mut_arg("transport", |a| a.help(t!("cli.arg_transport").to_string()))
        .mut_subcommand("check", |sc| sc.about(t!("cli.check_about").to_string()))
        .mut_subcommand("catalog", |sc| {
            sc.about(t!("cli.catalog_about").to_string())
                .mut_arg("catalog_url", |a| {
                    a.help(t!("cli.arg_catalog_url").to_string())
                })
                .mut_subcommand("show", |s| {
                    s.about(t!("cli.catalog_show_about").to_string())
                })
                .mut_subcommand("set", |s| {
                    s.about(t!("cli.catalog_set_about").to_string())
                        .mut_arg("url", |a| a.help(t!("cli.arg_catalog_set_url").to_string()))
                })
                .mut_subcommand("reset", |s| {
                    s.about(t!("cli.catalog_reset_about").to_string())
                })
        })
        .mut_subcommand("run", |sc| {
            sc.about(t!("cli.run_about").to_string())
                .mut_arg("payload", |a| a.help(t!("cli.arg_payload").to_string()))
                .mut_arg("catalog_url", |a| {
                    a.help(t!("cli.arg_catalog_url").to_string())
                })
                .mut_arg("ksu", |a| a.help(t!("cli.arg_ksu").to_string()))
                .mut_arg("skip_ksu", |a| a.help(t!("cli.arg_skip_ksu").to_string()))
                .mut_arg("attempts", |a| a.help(t!("cli.arg_attempts").to_string()))
                .mut_arg("delay", |a| a.help(t!("cli.arg_delay").to_string()))
                .mut_arg("save_history", |a| {
                    a.help(t!("cli.arg_save_history").to_string())
                })
                .mut_arg("reboot_first", |a| {
                    a.help(t!("cli.arg_reboot_first").to_string())
                })
                .mut_arg("force_payload", |a| {
                    a.help(t!("cli.arg_force_payload").to_string())
                })
                .mut_arg("payload_dirs", |a| {
                    a.help(t!("cli.arg_payload_dir").to_string())
                })
                .mut_arg("dry_run", |a| a.help(t!("cli.arg_dry_run").to_string()))
                .mut_arg("manager_apk", |a| {
                    a.help(t!("cli.arg_manager_apk").to_string())
                })
                .mut_arg("timeout", |a| a.help(t!("cli.arg_timeout").to_string()))
        })
        .mut_subcommand("clean", |sc| sc.about(t!("cli.clean_about").to_string()))
        .mut_subcommand("history", |sc| {
            sc.about(t!("cli.history_about").to_string())
                .mut_subcommand("list", |s| {
                    s.about(t!("cli.history_list_about").to_string())
                        .mut_arg("limit", |a| a.help(t!("cli.arg_history_limit").to_string()))
                })
                .mut_subcommand("show", |s| {
                    s.about(t!("cli.history_show_about").to_string())
                        .mut_arg("id", |a| a.help(t!("cli.arg_history_id").to_string()))
                })
                .mut_subcommand("clear", |s| {
                    s.about(t!("cli.history_clear_about").to_string())
                })
        })
        .mut_subcommand("pair", |sc| {
            sc.about(t!("cli.pair_about").to_string())
                .mut_arg("list", |a| a.help(t!("cli.arg_pair_list").to_string()))
                .mut_arg("addr", |a| a.help(t!("cli.arg_pair_addr").to_string()))
                .mut_arg("code", |a| a.help(t!("cli.arg_pair_code").to_string()))
        })
}

#[tokio::main]
async fn main() {
    let initial_lang = early_detect_language();
    set_current_language(initial_lang);
    rust_i18n::set_locale(initial_lang.code());

    let cmd = localize_command(Cli::command());
    let matches = cmd.get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            std::process::exit(1);
        }
    };

    if let Some(l) = &cli.lang {
        let selected = Language::from_code(l);
        set_current_language(selected);
        rust_i18n::set_locale(selected.code());
    }

    let transport_mode = rmv_core::TransportMode::from_str_opt(Some(&cli.transport));

    let result = match cli.command {
        Commands::Check => commands::run_check(cli.serial, transport_mode).await,
        Commands::Catalog {
            catalog_url,
            action,
        } => match action {
            Some(CatalogAction::Show) => commands::run_catalog_show().await,
            Some(CatalogAction::Set { url }) => commands::run_catalog_set(&url).await,
            Some(CatalogAction::Reset) => commands::run_catalog_reset().await,
            None => commands::run_catalog(cli.serial, catalog_url, transport_mode).await,
        },
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
                transport_mode,
            )
            .await
        }
        Commands::Clean => commands::run_clean(cli.serial, transport_mode).await,
        Commands::Pair { list, addr, code } => commands::run_pair(list, addr, code).await,
        Commands::History { action } => match action.unwrap_or(HistoryAction::List { limit: 15 }) {
            HistoryAction::List { limit } => commands::run_history_list(limit).await,
            HistoryAction::Show { id } => commands::run_history_show(&id).await,
            HistoryAction::Clear => commands::run_history_clear().await,
        },
    };

    if let Err(err) = result {
        eprintln!("{} {:#}", "[fail]".red().bold(), err);
        std::process::exit(1);
    }
}
