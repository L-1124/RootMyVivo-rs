use crate::error::{Result, RmvError};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdbServiceKind {
    Pairing,
    Connect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAdbService {
    pub name: String,
    pub addr: SocketAddrV4,
    pub kind: AdbServiceKind,
}

pub struct AdbMdnsDiscovery;

impl AdbMdnsDiscovery {
    pub fn discover_single_pairing_device(
        timeout_secs: u64,
    ) -> Result<Option<DiscoveredAdbService>> {
        let services = Self::scan_services(timeout_secs)?;
        let pairing_devices: Vec<_> = services
            .into_iter()
            .filter(|s| s.kind == AdbServiceKind::Pairing)
            .collect();

        if pairing_devices.is_empty() {
            Ok(None)
        } else if pairing_devices.len() == 1 {
            Ok(Some(pairing_devices.into_iter().next().unwrap()))
        } else {
            Err(RmvError::Adb {
                message: format!(
                    "Found {} pairing devices, please specify target address explicitly",
                    pairing_devices.len()
                ),
                code: None,
            })
        }
    }

    pub fn scan_services(timeout_secs: u64) -> Result<Vec<DiscoveredAdbService>> {
        let mdns = ServiceDaemon::new().map_err(|e| RmvError::Adb {
            message: format!("Failed to create mDNS daemon: {}", e),
            code: None,
        })?;

        let pairing_receiver =
            mdns.browse("_adb-tls-pairing._tcp.local.")
                .map_err(|e| RmvError::Adb {
                    message: format!("Failed to browse pairing service: {}", e),
                    code: None,
                })?;
        let connect_receiver =
            mdns.browse("_adb-tls-connect._tcp.local.")
                .map_err(|e| RmvError::Adb {
                    message: format!("Failed to browse connect service: {}", e),
                    code: None,
                })?;

        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_secs(timeout_secs);
        let mut services = Vec::new();

        while start.elapsed() < timeout_dur {
            while let Ok(event) = pairing_receiver.recv_timeout(Duration::from_millis(50)) {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let port = info.get_port();
                    let raw_name = info.get_fullname();
                    let clean_name = raw_name
                        .strip_suffix("._adb-tls-pairing._tcp.local.")
                        .unwrap_or(raw_name)
                        .to_string();

                    for addr in info.get_addresses() {
                        if let std::net::IpAddr::V4(ipv4) = addr {
                            let socket_addr = SocketAddrV4::new(*ipv4, port);
                            if !services.iter().any(|s: &DiscoveredAdbService| {
                                s.addr == socket_addr && s.kind == AdbServiceKind::Pairing
                            }) {
                                services.push(DiscoveredAdbService {
                                    name: clean_name.clone(),
                                    addr: socket_addr,
                                    kind: AdbServiceKind::Pairing,
                                });
                            }
                        }
                    }
                }
            }

            while let Ok(event) = connect_receiver.recv_timeout(Duration::from_millis(50)) {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let port = info.get_port();
                    let raw_name = info.get_fullname();
                    let clean_name = raw_name
                        .strip_suffix("._adb-tls-connect._tcp.local.")
                        .unwrap_or(raw_name)
                        .to_string();

                    for addr in info.get_addresses() {
                        if let std::net::IpAddr::V4(ipv4) = addr {
                            let socket_addr = SocketAddrV4::new(*ipv4, port);
                            if !services.iter().any(|s: &DiscoveredAdbService| {
                                s.addr == socket_addr && s.kind == AdbServiceKind::Connect
                            }) {
                                services.push(DiscoveredAdbService {
                                    name: clean_name.clone(),
                                    addr: socket_addr,
                                    kind: AdbServiceKind::Connect,
                                });
                            }
                        }
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = mdns.shutdown();
        Ok(services)
    }
}
