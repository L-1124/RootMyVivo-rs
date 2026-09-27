#[cfg(feature = "native-usb")]
pub mod native_usb {
    use async_trait::async_trait;
    use rust_i18n::t;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::sleep;

    use crate::device::DeviceInfo;
    use crate::error::{Result, RmvError};
    use crate::transport::Transport;

    use webadb_rs::auth::AdbKeyPair;
    use webadb_rs::protocol::{Command, Message, ADB_CNXN_MAXDATA, ADB_VERSION, CNXN_HOST_BANNER};
    use webadb_rs::sync::{SyncCommand, SyncPacket};

    pub struct AdbUsbTransport {
        pub serial: Option<String>,
        device_handle: Arc<Mutex<Option<ConnectedUsb>>>,
        next_local_id: AtomicU32,
    }

    struct ConnectedUsb {
        interface: nusb::Interface,
        in_ep: u8,
        out_ep: u8,
        _max_payload: u32,
    }

    impl ConnectedUsb {
        async fn write_raw(&self, data: &[u8]) -> Result<()> {
            let res = self.interface.bulk_out(self.out_ep, data.to_vec()).await;
            res.status.map_err(|e| RmvError::Adb {
                message: format!("USB write failed: {}", e),
                code: None,
            })?;
            Ok(())
        }

        async fn read_raw(&self, len: usize) -> Result<Vec<u8>> {
            let buf = nusb::transfer::RequestBuffer::new(len);
            let res = self.interface.bulk_in(self.in_ep, buf).await;
            res.status.map_err(|e| RmvError::Adb {
                message: format!("USB read failed: {}", e),
                code: None,
            })?;
            Ok(res.data)
        }

        async fn send_msg(&self, msg: &Message, data: &[u8]) -> Result<()> {
            let mut payload = msg.to_bytes();
            payload.extend_from_slice(data);
            self.write_raw(&payload).await
        }

        async fn read_msg(&self) -> Result<(Message, Vec<u8>)> {
            let header_bytes = self.read_raw(24).await?;
            let msg = Message::from_bytes(&header_bytes).map_err(|e| RmvError::Adb {
                message: format!("Invalid ADB header: {}", e),
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

    fn find_adb_device(serial_filter: Option<&str>) -> Result<(nusb::DeviceInfo, u8, u8, u8)> {
        let devices = nusb::list_devices().map_err(|e| RmvError::Adb {
            message: format!("Failed to list USB devices: {}", e),
            code: None,
        })?;

        for dev_info in devices {
            if let Some(target) = serial_filter {
                if let Some(ser) = dev_info.serial_number() {
                    if ser != target {
                        continue;
                    }
                }
            }

            if let Ok(dev) = dev_info.open() {
                if let Ok(config) = dev.active_configuration() {
                    for alt in config.interface_alt_settings() {
                        if alt.class() == 0xFF && alt.subclass() == 0x42 && alt.protocol() == 0x01 {
                            let mut in_ep = None;
                            let mut out_ep = None;
                            for ep in alt.endpoints() {
                                if ep.transfer_type() == nusb::transfer::EndpointType::Bulk {
                                    match ep.direction() {
                                        nusb::transfer::Direction::In => in_ep = Some(ep.address()),
                                        nusb::transfer::Direction::Out => {
                                            out_ep = Some(ep.address())
                                        }
                                    }
                                }
                            }
                            if let (Some(in_e), Some(out_e)) = (in_ep, out_ep) {
                                return Ok((dev_info, alt.interface_number(), in_e, out_e));
                            }
                        }
                    }
                }
            }
        }

        Err(RmvError::DeviceNotFound(
            t!("error.device_offline").to_string(),
        ))
    }

    fn get_or_create_adb_key() -> Result<AdbKeyPair> {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());

        let standard_key = PathBuf::from(&home).join(".android").join("adbkey");
        if standard_key.exists() {
            if let Ok(content) = std::fs::read_to_string(&standard_key) {
                if let Ok(key) = AdbKeyPair::from_pem(&content) {
                    return Ok(key);
                }
            }
        }

        let custom_dir = PathBuf::from(&home).join(".rmv");
        let custom_key = custom_dir.join("adbkey");
        if custom_key.exists() {
            if let Ok(content) = std::fs::read_to_string(&custom_key) {
                if let Ok(key) = AdbKeyPair::from_pem(&content) {
                    return Ok(key);
                }
            }
        }

        let key = AdbKeyPair::generate().map_err(|e| RmvError::Adb {
            message: format!("Failed to generate RSA key: {}", e),
            code: None,
        })?;

        let _ = std::fs::create_dir_all(&custom_dir);
        if let Ok(pem) = key.private_key_pem() {
            let _ = std::fs::write(&custom_key, pem);
        }

        Ok(key)
    }

    impl AdbUsbTransport {
        pub fn new(serial: Option<String>) -> Self {
            Self {
                serial,
                device_handle: Arc::new(Mutex::new(None)),
                next_local_id: AtomicU32::new(1),
            }
        }

        pub async fn connect(&self) -> Result<()> {
            let mut handle_guard = self.device_handle.lock().await;
            if handle_guard.is_some() {
                return Ok(());
            }

            let (dev_info, iface_num, in_ep, out_ep) = find_adb_device(self.serial.as_deref())?;
            let device = dev_info.open().map_err(|e| RmvError::Adb {
                message: format!("Failed to open USB device: {}", e),
                code: None,
            })?;

            let interface = device
                .claim_interface(iface_num)
                .map_err(|e| RmvError::Adb {
                    message: format!(
                        "Failed to claim USB ADB interface (busy or occupied): {}",
                        e
                    ),
                    code: None,
                })?;

            let conn = ConnectedUsb {
                interface,
                in_ep,
                out_ep,
                _max_payload: ADB_CNXN_MAXDATA,
            };

            // 1. 发送 CNXN 握手
            let cnxn_msg = Message::new(
                Command::Cnxn,
                ADB_VERSION,
                ADB_CNXN_MAXDATA,
                CNXN_HOST_BANNER,
            );
            conn.send_msg(&cnxn_msg, CNXN_HOST_BANNER).await?;

            let keypair = get_or_create_adb_key()?;

            // 2. 握手认证循环
            loop {
                let (msg, body) = conn.read_msg().await?;
                match msg.command {
                    Command::Cnxn => {
                        // 握手成功
                        break;
                    }
                    Command::Auth => {
                        if msg.arg0 == 1 {
                            // Token 挑战
                            if let Ok(sig) = keypair.sign_token(&body) {
                                let auth_msg = Message::new(Command::Auth, 2, 0, &sig);
                                conn.send_msg(&auth_msg, &sig).await?;
                            } else {
                                let pubkey = keypair.get_public_key("rootmyvivo").map_err(|e| {
                                    RmvError::Adb {
                                        message: format!("Public key format error: {}", e),
                                        code: None,
                                    }
                                })?;
                                let auth_msg = Message::new(Command::Auth, 3, 0, &pubkey);
                                conn.send_msg(&auth_msg, &pubkey).await?;
                            }
                        } else {
                            // 签名被拒绝，发送公钥弹窗
                            let pubkey = keypair.get_public_key("rootmyvivo").map_err(|e| {
                                RmvError::Adb {
                                    message: format!("Public key format error: {}", e),
                                    code: None,
                                }
                            })?;
                            let auth_msg = Message::new(Command::Auth, 3, 0, &pubkey);
                            conn.send_msg(&auth_msg, &pubkey).await?;
                        }
                    }
                    _ => {}
                }
            }

            *handle_guard = Some(conn);
            Ok(())
        }

        async fn ensure_connected(&self) -> Result<()> {
            if self.device_handle.lock().await.is_none() {
                self.connect().await?;
            }
            Ok(())
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl Transport for AdbUsbTransport {
        async fn exec(&self, cmd: &str) -> Result<(i32, String)> {
            self.ensure_connected().await?;
            let local_id = self.next_local_id.fetch_add(1, Ordering::SeqCst);
            let service = format!("shell:{}\0", cmd);
            let service_bytes = service.as_bytes();

            let guard = self.device_handle.lock().await;
            let conn = guard.as_ref().ok_or_else(|| RmvError::Adb {
                message: "USB connection lost".to_string(),
                code: None,
            })?;

            let open_msg = Message::new(Command::Open, local_id, 0, service_bytes);
            conn.send_msg(&open_msg, service_bytes).await?;

            let mut remote_id = 0;
            let mut output = Vec::new();

            loop {
                let (msg, body) = conn.read_msg().await?;
                if msg.arg1 == local_id {
                    match msg.command {
                        Command::Okay => {
                            remote_id = msg.arg0;
                        }
                        Command::Wrte => {
                            output.extend_from_slice(&body);
                            let ack = Message::new(Command::Okay, local_id, remote_id, &[]);
                            conn.send_msg(&ack, &[]).await?;
                        }
                        Command::Clse => {
                            let close_ack = Message::new(Command::Clse, local_id, remote_id, &[]);
                            let _ = conn.send_msg(&close_ack, &[]).await;
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

            let guard = self.device_handle.lock().await;
            let conn = guard.as_ref().ok_or_else(|| RmvError::Adb {
                message: "USB connection lost".to_string(),
                code: None,
            })?;

            let open_msg = Message::new(Command::Open, local_id, 0, service);
            conn.send_msg(&open_msg, service).await?;

            let remote_id;
            loop {
                let (msg, _) = conn.read_msg().await?;
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
            conn.send_msg(&wrte_msg, &send_bytes).await?;

            // 2. 分块发送 DATA 包 (64KB chunks)
            for chunk in data.chunks(64 * 1024) {
                let data_packet = SyncPacket::new(SyncCommand::Data, chunk.to_vec());
                let bytes = data_packet.to_bytes();
                let wrte_data = Message::new(Command::Wrte, local_id, remote_id, &bytes);
                conn.send_msg(&wrte_data, &bytes).await?;
            }

            // 3. 发送 DONE 包
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let done_packet = SyncPacket::new(SyncCommand::Done, now.to_le_bytes().to_vec());
            let done_bytes = done_packet.to_bytes();
            let wrte_done = Message::new(Command::Wrte, local_id, remote_id, &done_bytes);
            conn.send_msg(&wrte_done, &done_bytes).await?;

            // 4. 关闭 sync 流
            let close_msg = Message::new(Command::Clse, local_id, remote_id, &[]);
            let _ = conn.send_msg(&close_msg, &[]).await;

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
                let mut guard = self.device_handle.lock().await;
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
}
