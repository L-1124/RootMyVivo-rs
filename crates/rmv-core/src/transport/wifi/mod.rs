pub mod cert;
pub mod pairing;

use async_trait::async_trait;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use rust_i18n::t;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_rustls::TlsConnector;

use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};
use crate::transport::wifi::cert::AdbTlsCredential;
use crate::transport::Transport;

use webadb_rs::protocol::{Command, Message, ADB_CNXN_MAXDATA, ADB_VERSION, CNXN_HOST_BANNER};
use webadb_rs::sync::{SyncCommand, SyncPacket};

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

enum WifiStream {
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    Plain(TcpStream),
}

impl WifiStream {
    async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Tls(s) => s.write_all(data).await,
            Self::Plain(s) => s.write_all(data).await,
        }
        .map_err(|e| RmvError::Adb {
            message: format!("Network write failed: {}", e),
            code: None,
        })
    }

    async fn read_raw(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        match self {
            Self::Tls(s) => s.read_exact(&mut buf).await,
            Self::Plain(s) => s.read_exact(&mut buf).await,
        }
        .map_err(|e| RmvError::Adb {
            message: format!("Network read failed: {}", e),
            code: None,
        })?;
        Ok(buf)
    }

    async fn send_msg(&mut self, msg: &Message, data: &[u8]) -> Result<()> {
        let mut payload = msg.to_bytes();
        payload.extend_from_slice(data);
        self.write_raw(&payload).await
    }

    async fn read_msg(&mut self) -> Result<(Message, Vec<u8>)> {
        let header_bytes = self.read_raw(24).await?;
        let msg = Message::from_bytes(&header_bytes).map_err(|e| RmvError::Adb {
            message: format!("Invalid ADB header over Wi-Fi: {}", e),
            code: None,
        })?;

        let mut body = Vec::new();
        let mut remaining = msg.data_length as usize;
        while remaining > 0 {
            let chunk = self.read_raw(remaining).await?;
            if chunk.is_empty() {
                break;
            }
            remaining -= chunk.len();
            body.extend_from_slice(&chunk);
        }

        Ok((msg, body))
    }
}

pub struct AdbWifiTransport {
    pub addr: Option<String>,
    stream: Arc<Mutex<Option<WifiStream>>>,
    next_local_id: AtomicU32,
}

impl AdbWifiTransport {
    pub fn new(addr: Option<String>) -> Self {
        Self {
            addr,
            stream: Arc::new(Mutex::new(None)),
            next_local_id: AtomicU32::new(1),
        }
    }

    pub fn discover_connect_service(
        target_ip: Option<&str>,
        timeout_secs: u64,
    ) -> Result<(String, u16)> {
        let mdns = ServiceDaemon::new().map_err(|e| RmvError::Adb {
            message: format!("Failed to create mDNS daemon: {}", e),
            code: None,
        })?;

        let service_type = "_adb-tls-connect._tcp.local.";
        let receiver = mdns.browse(service_type).map_err(|e| RmvError::Adb {
            message: format!("Failed to browse mDNS service {}: {}", service_type, e),
            code: None,
        })?;

        let start = std::time::Instant::now();
        let timeout_dur = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout_dur {
            if let Ok(event) = receiver.recv_timeout(Duration::from_millis(500)) {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let port = info.get_port();
                    for addr in info.get_addresses() {
                        let ip_str = addr.to_string();
                        if let Some(target) = target_ip {
                            if ip_str == target {
                                return Ok((ip_str, port));
                            }
                        } else {
                            return Ok((ip_str, port));
                        }
                    }
                }
            }
        }

        Err(RmvError::DeviceNotFound(
            t!("error.device_offline").to_string(),
        ))
    }

    pub async fn connect(&self) -> Result<()> {
        let mut guard = self.stream.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let target_addr = if let Some(a) = &self.addr {
            a.clone()
        } else {
            let (ip, port) = Self::discover_connect_service(None, 5)?;
            format!("{}:{}", ip, port)
        };

        // If target is port 5555, try plain TCP first
        let is_plain_5555 = target_addr.ends_with(":5555");

        let mut wifi_stream = if is_plain_5555 {
            let tcp = TcpStream::connect(&target_addr)
                .await
                .map_err(|e| RmvError::Adb {
                    message: format!("Failed to connect to TCP {}: {}", target_addr, e),
                    code: None,
                })?;
            WifiStream::Plain(tcp)
        } else {
            // Wireless Debugging (TLS 1.3)
            let cred = AdbTlsCredential::load_or_generate()?;
            let client_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_client_auth_cert(
                    vec![CertificateDer::from(cred.cert_der)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cred.key_der)),
                )
                .map_err(|e| RmvError::Adb {
                    message: format!("TLS client config error: {}", e),
                    code: None,
                })?;

            let connector = TlsConnector::from(Arc::new(client_config));
            let tcp = TcpStream::connect(&target_addr)
                .await
                .map_err(|e| RmvError::Adb {
                    message: format!(
                        "Failed to connect to wireless debug port {}: {}",
                        target_addr, e
                    ),
                    code: None,
                })?;

            let domain =
                ServerName::try_from("localhost".to_string()).map_err(|e| RmvError::Adb {
                    message: format!("Invalid server name: {:?}", e),
                    code: None,
                })?;

            let tls_stream = connector
                .connect(domain, tcp)
                .await
                .map_err(|e| RmvError::Adb {
                    message: format!(
                        "TLS handshake failed (ensure device is paired via 'rmv pair'): {}",
                        e
                    ),
                    code: None,
                })?;

            WifiStream::Tls(tls_stream)
        };

        // 1. 发送 CNXN 握手帧
        let cnxn_msg = Message::new(
            Command::Cnxn,
            ADB_VERSION,
            ADB_CNXN_MAXDATA,
            CNXN_HOST_BANNER,
        );
        wifi_stream.send_msg(&cnxn_msg, CNXN_HOST_BANNER).await?;

        // 2. 接收握手回应
        loop {
            let (msg, _) = wifi_stream.read_msg().await?;
            if msg.command == Command::Cnxn {
                break;
            }
        }

        *guard = Some(wifi_stream);
        Ok(())
    }

    async fn ensure_connected(&self) -> Result<()> {
        if self.stream.lock().await.is_none() {
            self.connect().await?;
        }
        Ok(())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Transport for AdbWifiTransport {
    async fn exec(&self, cmd: &str) -> Result<(i32, String)> {
        self.ensure_connected().await?;
        let local_id = self.next_local_id.fetch_add(1, Ordering::SeqCst);
        let service = format!("shell:{}\0", cmd);
        let service_bytes = service.as_bytes();

        let mut guard = self.stream.lock().await;
        let stream = guard.as_mut().ok_or_else(|| RmvError::Adb {
            message: "Wi-Fi connection lost".to_string(),
            code: None,
        })?;

        let open_msg = Message::new(Command::Open, local_id, 0, service_bytes);
        stream.send_msg(&open_msg, service_bytes).await?;

        let mut remote_id = 0;
        let mut output = Vec::new();

        loop {
            let (msg, body) = stream.read_msg().await?;
            if msg.arg1 == local_id {
                match msg.command {
                    Command::Okay => {
                        remote_id = msg.arg0;
                    }
                    Command::Wrte => {
                        output.extend_from_slice(&body);
                        let ack = Message::new(Command::Okay, local_id, remote_id, &[]);
                        stream.send_msg(&ack, &[]).await?;
                    }
                    Command::Clse => {
                        let close_ack = Message::new(Command::Clse, local_id, remote_id, &[]);
                        let _ = stream.send_msg(&close_ack, &[]).await;
                        break;
                    }
                    _ => {}
                }
            }
        }

        let text = String::from_utf8_lossy(&output).to_string();
        Ok((0, text))
    }

    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        let data = tokio::fs::read(local_path).await?;
        self.push_bytes(&data, remote_path, 0o755).await
    }

    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let data = self.pull_bytes(remote_path).await?;
        tokio::fs::write(local_path, data).await?;
        Ok(())
    }

    async fn push_bytes(&self, data: &[u8], remote_path: &str, mode: u32) -> Result<()> {
        self.ensure_connected().await?;
        let local_id = self.next_local_id.fetch_add(1, Ordering::SeqCst);
        let service = b"sync:\0";

        let mut guard = self.stream.lock().await;
        let stream = guard.as_mut().ok_or_else(|| RmvError::Adb {
            message: "Wi-Fi connection lost".to_string(),
            code: None,
        })?;

        let open_msg = Message::new(Command::Open, local_id, 0, service);
        stream.send_msg(&open_msg, service).await?;

        let remote_id;
        loop {
            let (msg, _) = stream.read_msg().await?;
            if msg.arg1 == local_id && msg.command == Command::Okay {
                remote_id = msg.arg0;
                break;
            }
        }

        // 1. 发送 SEND 包
        let send_spec = format!("{},{}", remote_path, mode);
        let send_packet = SyncPacket::new(SyncCommand::Send, send_spec.into_bytes());
        let send_bytes = send_packet.to_bytes();
        let wrte_msg = Message::new(Command::Wrte, local_id, remote_id, &send_bytes);
        stream.send_msg(&wrte_msg, &send_bytes).await?;

        // 2. 分块发送 DATA 包 (64KB chunks)
        for chunk in data.chunks(64 * 1024) {
            let data_packet = SyncPacket::new(SyncCommand::Data, chunk.to_vec());
            let bytes = data_packet.to_bytes();
            let wrte_data = Message::new(Command::Wrte, local_id, remote_id, &bytes);
            stream.send_msg(&wrte_data, &bytes).await?;
        }

        // 3. 发送 DONE 包
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let done_packet = SyncPacket::new(SyncCommand::Done, now.to_le_bytes().to_vec());
        let done_bytes = done_packet.to_bytes();
        let wrte_done = Message::new(Command::Wrte, local_id, remote_id, &done_bytes);
        stream.send_msg(&wrte_done, &done_bytes).await?;

        // 4. 关闭 sync 流
        let close_msg = Message::new(Command::Clse, local_id, remote_id, &[]);
        let _ = stream.send_msg(&close_msg, &[]).await;

        Ok(())
    }

    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let (_, out) = self.exec(&format!("cat {}", remote_path)).await?;
        Ok(out.into_bytes())
    }

    async fn is_alive(&self) -> bool {
        match self.exec("echo ping").await {
            Ok((code, out)) => code == 0 && out.contains("ping"),
            Err(_) => false,
        }
    }

    async fn get_device_info(&self) -> Result<DeviceInfo> {
        let (_, model) = self.exec("getprop ro.product.model").await?;
        let (_, device) = self.exec("getprop ro.product.device").await?;
        let (_, brand) = self.exec("getprop ro.product.brand").await?;
        let (_, proc_ver) = self.exec("cat /proc/version").await?;
        let (_, boot_id) = self.exec("cat /proc/sys/kernel/random/boot_id").await?;

        if proc_ver.trim().is_empty() || proc_ver.contains("device offline") {
            return Err(RmvError::DeviceNotFound(
                t!("error.cannot_read_proc_version").to_string(),
            ));
        }

        DeviceInfo::parse(
            model.trim(),
            device.trim(),
            brand.trim(),
            proc_ver.trim(),
            boot_id.trim(),
        )
    }

    async fn reboot_and_wait(&self, timeout_sec: u64) -> Result<()> {
        let _ = self.exec("reboot").await;
        {
            let mut guard = self.stream.lock().await;
            *guard = None; // 连接断开
        }

        sleep(Duration::from_secs(10)).await;
        let mut elapsed = 10;
        while elapsed < timeout_sec {
            sleep(Duration::from_secs(3)).await;
            elapsed += 3;
            if self.connect().await.is_ok() {
                let (_, out) = self
                    .exec("getprop sys.boot_completed")
                    .await
                    .unwrap_or((-1, String::new()));
                if out.trim() == "1" {
                    return Ok(());
                }
            }
        }

        Err(RmvError::Adb {
            message: t!(
                "error.adb_timeout",
                action = "reboot",
                seconds = timeout_sec.to_string()
            )
            .to_string(),
            code: None,
        })
    }
}
