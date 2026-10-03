pub mod catalog;
pub mod check;
pub mod clean;
pub mod config;
pub mod diagnose;
pub mod history;
pub mod manager;
pub mod pair;
pub mod run;

pub use catalog::*;
pub use check::*;
pub use clean::*;
pub use config::*;
pub use diagnose::*;
pub use history::*;
pub use manager::*;
pub use pair::*;
pub use run::*;

use anyhow::Result;
use colored::*;
use rmv_core::{Transport, TransportBuilder, TransportMode};
use rust_i18n::t;
use std::sync::Arc;

pub async fn resolve_transport(
    serial: Option<String>,
    mode: TransportMode,
) -> Result<Arc<dyn Transport>> {
    if let Some(s) = serial {
        return TransportBuilder::resolve(Some(s), mode)
            .await
            .map_err(Into::into);
    }

    let devices = TransportBuilder::list_online_devices(mode).await?;
    if devices.is_empty() {
        return Err(rmv_core::RmvError::DeviceNotFound(
            t!("error.device_not_found_cli").to_string(),
        )
        .into());
    }

    if devices.len() == 1 {
        let (s, _) = &devices[0];
        return TransportBuilder::resolve(Some(s.clone()), mode)
            .await
            .map_err(Into::into);
    }

    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let items: Vec<String> = devices
            .iter()
            .map(|(s, model)| {
                if model.is_empty() {
                    s.bold().cyan().to_string()
                } else {
                    format!("{} ({})", s.bold().cyan(), model.green())
                }
            })
            .collect();

        let prompt = t!("cli.multiple_devices_prompt");
        let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(prompt)
            .default(0)
            .items(&items)
            .interact_opt()?;

        if let Some(idx) = selection {
            let (chosen_serial, _) = &devices[idx];
            return TransportBuilder::resolve(Some(chosen_serial.clone()), mode)
                .await
                .map_err(Into::into);
        } else {
            return Err(rmv_core::RmvError::Cancelled.into());
        }
    }

    let device_names: Vec<String> = devices.into_iter().map(|(s, _)| s).collect();
    anyhow::bail!(t!(
        "error.multiple_devices",
        devices = device_names.join(", ")
    ));
}
