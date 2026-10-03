use super::resolve_transport;
use crate::ui::CliUi;
use anyhow::Result;
use colored::Colorize;
use rmv_core::{KsuVariant, TransportMode};
use rust_i18n::t;
use tokio::sync::mpsc;

pub async fn run_manager_download(
    ksu: String,
    version: Option<String>,
    mirror: Option<String>,
) -> Result<()> {
    let variant = KsuVariant::from_id(&ksu);
    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("log.manager_auto_download", name = variant.display_name())
    );
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut ui = CliUi::new();
    let ui_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            ui.handle_event(event).await;
        }
        ui.flush().await;
    });

    let path = rmv_core::ManagerDownloader::download_manager_default(
        variant,
        version.as_deref(),
        None,
        mirror.as_deref(),
        Some(&event_tx),
    )
    .await?;

    drop(event_tx);
    let _ = ui_handle.await;
    println!(
        "{} {} -> {}",
        "[ ok ]".green().bold(),
        variant.display_name(),
        path.display()
    );
    Ok(())
}

pub fn run_manager_list() {
    let list = rmv_core::ManagerDownloader::list_cached_managers(None);
    println!("\n{}", t!("cli.manager_list_about").cyan().bold());
    if list.is_empty() {
        println!("  {}", t!("cli.manager_empty").dimmed());
        return;
    }
    for item in list {
        let name = item.variant.map_or("Unknown", |v| v.display_name());
        #[expect(
            clippy::cast_precision_loss,
            reason = "Displaying APK byte size in megabytes"
        )]
        let size_mb = (item.size as f64) / (1024.0 * 1024.0);
        println!(
            "  - {} : {} ({:.1} MB)",
            name.green().bold(),
            item.file_name,
            size_mb
        );
        println!("    {}", item.path.display().to_string().dimmed());
    }
    println!();
}

pub async fn run_manager_install(
    serial: Option<String>,
    ksu: String,
    mode: TransportMode,
) -> Result<()> {
    let variant = KsuVariant::from_id(&ksu);
    let list = rmv_core::ManagerDownloader::list_cached_managers(None);
    let found = list.into_iter().find(|m| m.variant == Some(variant));

    let apk_path = if let Some(item) = found {
        item.path
    } else {
        println!(
            "{} {}",
            "[ .. ]".cyan(),
            t!("log.manager_auto_download", name = variant.display_name())
        );
        rmv_core::ManagerDownloader::download_manager_default(variant, None, None, None, None)
            .await?
    };

    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("log.manager_installing", name = variant.display_name())
    );
    let transport = resolve_transport(serial, mode).await?;
    let remote_path = "/data/local/tmp/rmv/manager_install.apk";
    transport.push(&apk_path, remote_path).await?;
    let out = transport
        .exec(&format!("pm install -r -d {remote_path}"))
        .await?;
    let _ = transport.exec(&format!("rm -f {remote_path}")).await;

    if out.success() && (out.combined().contains("Success") || out.combined().trim().is_empty()) {
        println!(
            "{} {}",
            "[ ok ]".green().bold(),
            t!("log.manager_install_ok", name = variant.display_name()).green()
        );
        Ok(())
    } else {
        anyhow::bail!(t!(
            "error.manager_install_failed",
            name = variant.display_name(),
            message = out.combined().trim()
        ))
    }
}
