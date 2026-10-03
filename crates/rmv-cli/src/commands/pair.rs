use anyhow::Result;
use colored::*;
use rust_i18n::t;

pub async fn run_pair(list: bool, addr: Option<String>, code: Option<String>) -> Result<()> {
    if list {
        println!("{} {}", "[ .. ]".cyan(), t!("cli.pairing_scanning"));
        let services = tokio::task::spawn_blocking(|| rmv_core::AdbMdnsDiscovery::scan_services(3))
            .await
            .map_err(|e| anyhow::anyhow!("mDNS scan task failed: {e}"))??;
        if services.is_empty() {
            println!(
                "{} {}",
                "[warn]".yellow().bold(),
                t!("cli.pairing_no_devices")
            );
            return Ok(());
        }
        println!(
            "{} {}",
            "[ ok ]".green().bold(),
            t!(
                "cli.pairing_found_count",
                count = services.len().to_string()
            )
            .bold()
        );
        let prog = std::env::args().next().unwrap_or_else(|| "rmv".to_string());
        for (i, svc) in services.iter().enumerate() {
            let (tag, hint) = match svc.kind {
                rmv_core::AdbServiceKind::Pairing => (
                    t!("cli.pairing_kind_pairing").yellow().bold(),
                    t!("cli.pairing_hint_pairing", prog = &prog).dimmed(),
                ),
                rmv_core::AdbServiceKind::Connect => (
                    t!("cli.pairing_kind_connect").green().bold(),
                    t!("cli.pairing_hint_connect", prog = &prog).dimmed(),
                ),
            };
            println!(
                "       {}. [{}] {} -> {}  {}",
                i + 1,
                tag,
                svc.name.cyan(),
                svc.addr.to_string().white().bold(),
                hint
            );
        }
        return Ok(());
    }

    let (socket_addr, target_code) = match (addr, code) {
        (Some(a), Some(c)) => {
            let parsed: std::net::SocketAddrV4 = a.parse().map_err(|e| {
                anyhow::anyhow!("Invalid IP:Port format (e.g. 192.168.1.50:37123): {}", e)
            })?;
            (parsed, c)
        }
        (Some(single), None) => {
            let prog = std::env::args().next().unwrap_or_else(|| "rmv".to_string());
            if single.contains(':') {
                anyhow::bail!(t!("cli.pairing_missing_code", prog = prog));
            }
            println!("{} {}", "[ .. ]".cyan(), t!("cli.pairing_scanning"));
            let discovered = tokio::task::spawn_blocking(|| {
                rmv_core::AdbMdnsDiscovery::discover_single_pairing_device(3)
            })
            .await
            .map_err(|e| anyhow::anyhow!("mDNS discovery task failed: {e}"))??;
            match discovered {
                Some(dev) => {
                    println!(
                        "{} {}",
                        "[ ok ]".green().bold(),
                        t!(
                            "cli.pairing_found_single",
                            name = &dev.name,
                            addr = &dev.addr.to_string()
                        )
                        .green()
                    );
                    (dev.addr, single)
                }
                None => {
                    anyhow::bail!(t!("cli.pairing_no_devices"));
                }
            }
        }
        _ => {
            let prog = std::env::args().next().unwrap_or_else(|| "rmv".to_string());
            anyhow::bail!(t!("cli.pairing_missing_code", prog = prog));
        }
    };

    println!(
        "{} {}",
        "[ .. ]".cyan(),
        t!("cli.pairing_connecting", addr = &socket_addr.to_string())
    );

    let mut server = rmv_core::ADBServer::default();
    server
        .pair(socket_addr, target_code)
        .map_err(|e| anyhow::anyhow!("Pairing failed: {}", e))?;

    println!(
        "{} {}",
        "[ ok ]".green().bold(),
        t!("cli.pairing_success").green().bold()
    );

    // Auto connect to the paired device
    println!("{} Connecting to {}...", "[ .. ]".cyan(), socket_addr);
    let _ = server.connect_device(socket_addr);

    Ok(())
}
