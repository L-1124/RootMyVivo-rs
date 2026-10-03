//! `RootMyVivo` command-line interface entry point.
#![forbid(unsafe_code)]
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

    #[arg(long, global = true, default_value_t = false)]
    log_json: bool,

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

        #[arg(long = "no-save-history", default_value_t = false)]
        no_save_history: bool,

        #[arg(long, default_value_t = false)]
        reboot_first: bool,

        #[arg(long, default_value_t = false)]
        dry_run: bool,

        #[arg(long = "manager-apk", value_name = "APK_PATH")]
        manager_apk: Option<PathBuf>,

        #[arg(long = "manager-version", value_name = "TAG")]
        manager_version: Option<String>,

        #[arg(long = "mirror", value_name = "URL_PREFIX")]
        mirror: Option<String>,

        #[arg(long = "no-install-manager", default_value_t = false)]
        no_install_manager: bool,

        #[arg(long, default_value_t = 900)]
        timeout: u64,

        #[arg(
            long = "all-devices",
            default_value_t = false,
            conflicts_with = "payload",
            conflicts_with = "serial"
        )]
        all_devices: bool,

        #[arg(long = "soft-reboot", default_value_t = false)]
        soft_reboot: bool,
    },

    Clean,

    Manager {
        #[command(subcommand)]
        action: ManagerAction,
    },

    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    History {
        #[command(subcommand)]
        action: Option<HistoryAction>,
    },
    Stats {
        #[arg(long)]
        limit: Option<usize>,
    },
    Diagnose {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CatalogAction {
    List,
    Show,
    Set {
        #[arg(value_name = "URL")]
        url: String,
    },
    Reset,
}

#[derive(Subcommand)]
enum ManagerAction {
    Download {
        #[arg(short, long, default_value = "sukisu")]
        ksu: String,
        #[arg(long = "version")]
        version: Option<String>,
        #[arg(long)]
        mirror: Option<String>,
    },
    List,
    Install {
        #[arg(short, long, default_value = "sukisu")]
        ksu: String,
    },
}

#[derive(Subcommand)]
#[expect(
    clippy::enum_variant_names,
    reason = "Clap subcommand naming conventions"
)]
enum ConfigAction {
    SetMirror {
        #[arg(value_name = "URL")]
        mirror: String,
    },
    GetMirror,
    ResetMirror,
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

const ARG_HELPS: &[(&str, &str)] = &[
    ("serial", "cli.arg_serial"),
    ("lang", "cli.arg_lang"),
    ("transport", "cli.arg_transport"),
    ("log_json", "cli.arg_log_json"),
];

const SUBCOMMAND_HELPS: &[(&str, &str)] = &[
    ("check", "cli.check_about"),
    ("catalog", "cli.catalog_about"),
    ("pair", "cli.pair_about"),
    ("run", "cli.run_about"),
    ("clean", "cli.clean_about"),
    ("manager", "cli.manager_about"),
    ("config", "cli.config_about"),
    ("history", "cli.history_about"),
    ("stats", "cli.stats_about"),
    ("diagnose", "cli.diagnose_about"),
];

const CATALOG_ARG_HELPS: &[(&str, &str)] = &[("catalog_url", "cli.arg_catalog_url")];

const CATALOG_SUBCOMMAND_HELPS: &[(&str, &str)] = &[
    ("list", "cli.catalog_list_about"),
    ("show", "cli.catalog_show_about"),
    ("set", "cli.catalog_set_about"),
    ("reset", "cli.catalog_reset_about"),
];

const PAIR_ARG_HELPS: &[(&str, &str)] = &[
    ("list", "cli.arg_pair_list"),
    ("addr", "cli.arg_pair_addr"),
    ("code", "cli.arg_pair_code"),
];

const RUN_ARG_HELPS: &[(&str, &str)] = &[
    ("payload", "cli.arg_payload"),
    ("catalog_url", "cli.arg_catalog_url"),
    ("ksu", "cli.arg_ksu"),
    ("skip_ksu", "cli.arg_skip_ksu"),
    ("attempts", "cli.arg_attempts"),
    ("delay", "cli.arg_delay"),
    ("no_save_history", "cli.arg_no_save_history"),
    ("reboot_first", "cli.arg_reboot_first"),
    ("dry_run", "cli.arg_dry_run"),
    ("manager_apk", "cli.arg_manager_apk"),
    ("manager_version", "cli.arg_manager_version"),
    ("mirror", "cli.arg_mirror"),
    ("no_install_manager", "cli.arg_no_install_manager"),
    ("timeout", "cli.arg_timeout"),
    ("all_devices", "cli.arg_all_devices"),
    ("soft_reboot", "cli.arg_soft_reboot"),
];

const MANAGER_SUBCOMMAND_HELPS: &[(&str, &str)] = &[
    ("download", "cli.manager_download_about"),
    ("list", "cli.manager_list_about"),
    ("install", "cli.manager_install_about"),
];

const MANAGER_DOWNLOAD_ARG_HELPS: &[(&str, &str)] = &[
    ("ksu", "cli.arg_ksu"),
    ("version", "cli.arg_manager_version"),
    ("mirror", "cli.arg_mirror"),
];

const CONFIG_SUBCOMMAND_HELPS: &[(&str, &str)] = &[
    ("set-mirror", "cli.config_set_mirror_about"),
    ("get-mirror", "cli.config_get_mirror_about"),
    ("reset-mirror", "cli.config_reset_mirror_about"),
];

const HISTORY_SUBCOMMAND_HELPS: &[(&str, &str)] = &[
    ("list", "cli.history_list_about"),
    ("show", "cli.history_show_about"),
    ("clear", "cli.history_clear_about"),
];

fn apply_args(mut cmd: clap::Command, args: &[(&str, &str)]) -> clap::Command {
    for &(arg_name, help_key) in args {
        cmd = cmd.mut_arg(arg_name, |a| a.help(t!(help_key).to_string()));
    }
    cmd
}

fn apply_subcommands(mut cmd: clap::Command, subcmds: &[(&str, &str)]) -> clap::Command {
    for &(cmd_name, about_key) in subcmds {
        cmd = cmd.mut_subcommand(cmd_name, |s| s.about(t!(about_key).to_string()));
    }
    cmd
}

fn localize_command(mut cmd: clap::Command) -> clap::Command {
    cmd = cmd
        .about(t!("cli.app_about").to_string())
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
        .subcommand(clap::Command::new("help").about(t!("cli.help_subcmd").to_string()));

    cmd = apply_args(cmd, ARG_HELPS);
    cmd = apply_subcommands(cmd, SUBCOMMAND_HELPS);

    cmd = cmd.mut_subcommand("catalog", |sc| {
        let sc = apply_args(sc, CATALOG_ARG_HELPS);
        let sc = apply_subcommands(sc, CATALOG_SUBCOMMAND_HELPS);
        sc.mut_subcommand("set", |s| {
            apply_args(s, &[("url", "cli.arg_catalog_set_url")])
        })
    });

    cmd = cmd.mut_subcommand("pair", |sc| apply_args(sc, PAIR_ARG_HELPS));

    cmd = cmd.mut_subcommand("run", |sc| apply_args(sc, RUN_ARG_HELPS));

    cmd = cmd.mut_subcommand("manager", |sc| {
        let sc = apply_subcommands(sc, MANAGER_SUBCOMMAND_HELPS);
        sc.mut_subcommand("download", |s| apply_args(s, MANAGER_DOWNLOAD_ARG_HELPS))
            .mut_subcommand("install", |s| apply_args(s, &[("ksu", "cli.arg_ksu")]))
    });

    cmd = cmd.mut_subcommand("config", |sc| {
        apply_subcommands(sc, CONFIG_SUBCOMMAND_HELPS)
    });

    cmd = cmd.mut_subcommand("history", |sc| {
        let sc = apply_subcommands(sc, HISTORY_SUBCOMMAND_HELPS);
        sc.mut_subcommand("list", |s| {
            apply_args(s, &[("limit", "cli.arg_history_limit")])
        })
        .mut_subcommand("show", |s| apply_args(s, &[("id", "cli.arg_history_id")]))
    });

    cmd = cmd.mut_subcommand("stats", |sc| {
        apply_args(sc, &[("limit", "cli.arg_stats_limit")])
    });

    cmd = cmd.mut_subcommand("diagnose", |sc| {
        apply_args(sc, &[("output", "cli.arg_diagnose_output")])
    });

    cmd
}

#[expect(
    clippy::too_many_lines,
    reason = "Central CLI argument dispatcher and top-level error boundary"
)]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    ui::init_tracing();

    let initial_lang = early_detect_language();
    set_current_language(initial_lang);
    rust_i18n::set_locale(initial_lang.code());

    let cmd = localize_command(Cli::command());
    let matches = cmd.get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return std::process::ExitCode::from(1);
        }
    };
    if cli.log_json {
        let path = ui::init_global_jsonl(None);
        println!(
            "{} {} {}",
            "[info]".cyan(),
            t!("cli.log_json_started"),
            path.display()
        );
    }

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
            Some(CatalogAction::Show) => {
                commands::run_catalog_show();
                Ok(())
            }
            Some(CatalogAction::Set { url }) => commands::run_catalog_set(&url),
            Some(CatalogAction::Reset) => commands::run_catalog_reset(),
            Some(CatalogAction::List) | None => {
                commands::run_catalog(cli.serial, catalog_url, transport_mode).await
            }
        },
        Commands::Run {
            payload,
            catalog_url,
            ksu,
            skip_ksu,
            attempts,
            delay,
            no_save_history,
            reboot_first,
            dry_run,
            manager_apk,
            manager_version,
            mirror,
            no_install_manager,
            timeout,
            all_devices,
            soft_reboot,
        } => {
            commands::run_exploit(commands::RunArgs {
                serial: cli.serial,
                payload,
                catalog_url,
                ksu,
                skip_ksu,
                attempts,
                delay,
                save_history: !no_save_history,
                reboot_first,
                dry_run,
                manager_apk,
                manager_version,
                mirror,
                no_install_manager,
                timeout,
                transport_mode,
                all_devices,
                soft_reboot,
            })
            .await
        }
        Commands::Manager { action } => match action {
            ManagerAction::Download {
                ksu,
                version,
                mirror,
            } => commands::run_manager_download(ksu, version, mirror).await,
            ManagerAction::List => {
                commands::run_manager_list();
                Ok(())
            }
            ManagerAction::Install { ksu } => {
                commands::run_manager_install(cli.serial, ksu, transport_mode).await
            }
        },
        Commands::Config { action } => match action {
            ConfigAction::SetMirror { mirror } => commands::run_config_set_mirror(&mirror),
            ConfigAction::GetMirror => {
                commands::run_config_get_mirror();
                Ok(())
            }
            ConfigAction::ResetMirror => commands::run_config_reset_mirror(),
        },
        Commands::Clean => commands::run_clean(cli.serial, transport_mode).await,
        Commands::Pair { list, addr, code } => commands::run_pair(list, addr, code).await,
        Commands::History { action } => match action.unwrap_or(HistoryAction::List { limit: 15 }) {
            HistoryAction::List { limit } => commands::run_history_list(limit).await,
            HistoryAction::Show { id } => commands::run_history_show(&id).await,
            HistoryAction::Clear => commands::run_history_clear().await,
        },
        Commands::Stats { limit } => commands::run_stats(limit).await,
        Commands::Diagnose { output } => {
            commands::run_diagnose(cli.serial, transport_mode, output).await
        }
    };

    if let Err(err) = result {
        if matches!(
            err.downcast_ref::<rmv_core::RmvError>(),
            Some(rmv_core::RmvError::Cancelled)
        ) {
            return std::process::ExitCode::from(130);
        }
        if let Some(rmv_err) = err.downcast_ref::<rmv_core::RmvError>() {
            eprintln!("{} {}", "[fail]".red().bold(), rmv_err.localized());
        } else {
            eprintln!("{} {:#}", "[fail]".red().bold(), err);
        }
        return std::process::ExitCode::from(1);
    }

    std::process::ExitCode::SUCCESS
}

#[cfg_attr(test, allow(clippy::expect_used))]
#[cfg(test)]
mod tests {
    use super::*;

    fn assert_args_match(cmd: &clap::Command, args: &[(&str, &str)], ctx: &str) {
        for &(arg_id, _) in args {
            assert!(
                cmd.get_arguments().any(|a| a.get_id() == arg_id),
                "Argument '{arg_id}' not found in {ctx}"
            );
        }
    }

    fn assert_subcommands_match(cmd: &clap::Command, subcmds: &[(&str, &str)], ctx: &str) {
        for &(sub_name, _) in subcmds {
            assert!(
                cmd.get_subcommands().any(|s| s.get_name() == sub_name),
                "Subcommand '{sub_name}' not found in {ctx}"
            );
        }
    }

    #[test]
    fn test_clap_arguments_table_match() {
        let cmd = Cli::command();

        assert_args_match(&cmd, ARG_HELPS, "root command");
        assert_subcommands_match(&cmd, SUBCOMMAND_HELPS, "root command");

        let catalog_cmd = cmd.find_subcommand("catalog").expect("catalog subcommand");
        assert_args_match(catalog_cmd, CATALOG_ARG_HELPS, "catalog subcommand");
        assert_subcommands_match(catalog_cmd, CATALOG_SUBCOMMAND_HELPS, "catalog subcommand");

        let pair_cmd = cmd.find_subcommand("pair").expect("pair subcommand");
        assert_args_match(pair_cmd, PAIR_ARG_HELPS, "pair subcommand");

        let run_cmd = cmd.find_subcommand("run").expect("run subcommand");
        assert_args_match(run_cmd, RUN_ARG_HELPS, "run subcommand");

        let manager_cmd = cmd.find_subcommand("manager").expect("manager subcommand");
        assert_subcommands_match(manager_cmd, MANAGER_SUBCOMMAND_HELPS, "manager subcommand");

        let manager_download_cmd = manager_cmd
            .find_subcommand("download")
            .expect("manager download subcommand");
        assert_args_match(
            manager_download_cmd,
            MANAGER_DOWNLOAD_ARG_HELPS,
            "manager download subcommand",
        );

        let config_cmd = cmd.find_subcommand("config").expect("config subcommand");
        assert_subcommands_match(config_cmd, CONFIG_SUBCOMMAND_HELPS, "config subcommand");

        let history_cmd = cmd.find_subcommand("history").expect("history subcommand");
        assert_subcommands_match(history_cmd, HISTORY_SUBCOMMAND_HELPS, "history subcommand");
    }
}
