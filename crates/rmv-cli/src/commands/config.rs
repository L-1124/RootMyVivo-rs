use anyhow::Result;
use colored::*;
use rust_i18n::t;

pub async fn run_config_set_mirror(mirror: &str) -> Result<()> {
    rmv_core::MirrorConfig::set_saved_mirror(mirror)?;
    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.config_mirror_saved", mirror = mirror).green()
    );
    Ok(())
}

pub async fn run_config_get_mirror() -> Result<()> {
    println!("\n{}", t!("cli.config_mirror_title").cyan().bold());
    let saved = rmv_core::MirrorConfig::get_saved_mirror();
    let current = saved.as_deref().unwrap_or("Default (direct + mirrors)");
    println!(
        "  {} : {}",
        t!("cli.config_mirror_current"),
        current.green().bold()
    );
    println!();
    Ok(())
}

pub async fn run_config_reset_mirror() -> Result<()> {
    if rmv_core::MirrorConfig::reset_saved_mirror()? {
        println!(
            "{} {}",
            "[ ok ]".green().bold(),
            t!("cli.config_mirror_reset").green()
        );
    } else {
        println!(
            "{} {}",
            "[info]".cyan(),
            t!("cli.config_mirror_already_default")
        );
    }
    Ok(())
}
