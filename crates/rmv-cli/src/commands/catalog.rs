use super::resolve_transport;
use anyhow::{Context, Result};
use colored::Colorize;
use rmv_core::{CatalogConfig, CatalogUrlSource, CatalogV5, TransportExt, TransportMode};
use rust_i18n::t;

pub async fn run_catalog_show() -> Result<()> {
    let (url, source) = CatalogConfig::resolve_url(None);
    let source_str = match source {
        CatalogUrlSource::CliOverride => t!("cli.catalog_source_cli"),
        CatalogUrlSource::EnvVar => t!("cli.catalog_source_env"),
        CatalogUrlSource::ConfigFile => t!("cli.catalog_source_config"),
        CatalogUrlSource::Default => t!("cli.catalog_source_default"),
    };
    println!("{}", t!("cli.catalog_config_title").bold().cyan());
    println!(
        "  {} : {}",
        t!("cli.catalog_current_url"),
        url.green().bold()
    );
    println!("  {} : {}", t!("cli.catalog_current_source"), source_str);
    Ok(())
}

pub async fn run_catalog_set(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        anyhow::bail!(t!("error.invalid_url", url = url));
    }
    CatalogConfig::set_saved_url(trimmed)?;
    println!(
        "[ ok ] {}",
        t!("cli.catalog_url_saved", url = trimmed).green()
    );
    Ok(())
}

pub async fn run_catalog_reset() -> Result<()> {
    let existed = CatalogConfig::reset_saved_url()?;
    if existed {
        println!("[ ok ] {}", t!("cli.catalog_url_reset").green());
    } else {
        println!("[info] {}", t!("cli.catalog_url_already_default").dimmed());
    }
    Ok(())
}

pub async fn run_catalog(
    serial: Option<String>,
    catalog_url: Option<String>,
    mode: TransportMode,
) -> Result<()> {
    println!("{}", t!("cli.catalog_fetching").bold().cyan());
    let catalog = CatalogV5::fetch_default_with_url(catalog_url.as_deref())
        .await
        .context(t!("error.catalog_fetch_failed", message = "network"))?;
    if let Some(meta) = &catalog.cached_meta {
        if rmv_core::CatalogV5::is_fresh(meta.fetched_at, rmv_core::CATALOG_CACHE_MAX_AGE_SECS) {
            println!(
                "{}",
                t!("log.catalog_cache_used", url = meta.url.clone()).yellow()
            );
        } else {
            println!(
                "{}",
                t!("log.catalog_cache_expired", url = meta.url.clone()).red()
            );
        }
    }

    println!(
        "{}",
        t!(
            "cli.catalog_fetched",
            devices = catalog.devices.len().to_string(),
            builds = catalog.builds.len().to_string()
        )
    );

    println!(
        "{}",
        t!(
            "cli.catalog_devices_title",
            count = catalog.devices.len().to_string()
        )
        .bold()
        .cyan()
    );
    println!("{}", "-".repeat(78).cyan());
    println!(
        "  {:<20} {:<10} {:<24} {}",
        "MARKET NAME".dimmed(),
        "CODE".dimmed(),
        "MODELS".dimmed(),
        "KERNELS".dimmed()
    );
    println!("{}", "-".repeat(78).cyan());

    for dev in &catalog.devices {
        let code = if dev.code.is_empty() { "-" } else { &dev.code };
        let mut all_models: Vec<String> =
            dev.models.iter().chain(dev.names.iter()).cloned().collect();
        all_models.sort();
        all_models.dedup();
        all_models.retain(|m| m != &dev.market_name);

        let models_str = if all_models.is_empty() {
            code.to_string()
        } else {
            let joined = all_models.join(", ");
            if joined.len() > 24 {
                format!("{}...", &joined[..21])
            } else {
                joined
            }
        };

        let kernel_builds: Vec<&str> = dev.kernels.iter().map(|k| k.build.as_str()).collect();
        let kernels_str = if kernel_builds.is_empty() {
            "-".dimmed().to_string()
        } else {
            kernel_builds.join(", ").yellow().to_string()
        };

        println!(
            "  {:<20} {:<10} {:<24} {}",
            dev.market_name.green().bold(),
            code,
            models_str,
            kernels_str
        );
    }
    println!("{}\n", "-".repeat(78).cyan());
    if let Ok(transport) = resolve_transport(serial, mode).await {
        if let Ok(dev) = transport.get_device_info().await {
            println!("{}", t!("cli.matching_device").bold().cyan());
            match catalog.match_payload(&dev) {
                Some((device_entry, kernel_build)) => {
                    println!(
                        "  {} : {}",
                        t!("cli.matched_device"),
                        device_entry.market_name.bold().green()
                    );
                    let status_display = if kernel_build.status.eq_ignore_ascii_case("patched") {
                        kernel_build.status.bold().red()
                    } else {
                        kernel_build.status.bold().yellow()
                    };
                    println!("  {} : {}", t!("cli.payload_status"), status_display);
                    if let Some(file) = &kernel_build.file {
                        println!(
                            "  {} : {} ({} bytes)",
                            t!("cli.payload_file"),
                            file.name.green(),
                            file.size
                        );
                        println!("  {} : {}", t!("cli.download_url"), file.url.dimmed());
                    }
                }
                None => {
                    println!("  {}", t!("cli.no_payload_matched").yellow());
                }
            }
        } else {
            println!("{}", t!("cli.no_device_connected").dimmed());
        }
    } else {
        println!("{}", t!("cli.no_device_connected").dimmed());
    }

    Ok(())
}
