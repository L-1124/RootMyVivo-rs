use super::resolve_transport;
use anyhow::{Context, Result};
use colored::*;
use rmv_core::{CleanOutcome, Persistence, TransportMode};
use rust_i18n::t;

pub async fn run_clean(serial: Option<String>, mode: TransportMode) -> Result<()> {
    println!("{} {}", "[ .. ]".cyan(), t!("cli.cleaning_traces"));
    let transport = resolve_transport(serial, mode).await?;
    let outcome = Persistence::clean_traces(&transport)
        .await
        .context(t!("error.exploit_failed", message = "clean"))?;
    match outcome {
        CleanOutcome::WithRoot => {
            println!(
                "{} {}",
                "[ ok ]".green().bold(),
                t!("cli.cleaned_root").green()
            );
        }
        CleanOutcome::ShellOnly => {
            println!(
                "{} {}",
                "[ ok ]".green().bold(),
                t!("cli.cleaned_shell").green()
            );
            println!(
                "{} {}",
                "[warn]".yellow().bold(),
                t!("cli.cleaned_shell_warn").yellow()
            );
        }
    }
    Ok(())
}
