use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{Result, RmvError};
use crate::transport::wifi::cert::AdbTlsCredential;

pub const PAIRING_PACKET_VERSION: u8 = 1;
pub const PACKET_TYPE_SPAKE2_MSG: u8 = 0;
pub const PACKET_TYPE_PEER_INFO: u8 = 1;

pub struct AdbPairing;

impl AdbPairing {
    pub async fn pair(addr: &str, code: &str) -> Result<()> {
        let cred = AdbTlsCredential::load_or_generate()?;

        let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| RmvError::Adb {
                message: format!("Connection timed out connecting to pairing port {}", addr),
                code: None,
            })?
            .map_err(|e| RmvError::Adb {
                message: format!("Failed to connect to pairing port {}: {}", addr, e),
                code: None,
            })?;

        // 1. 初始化 SPAKE2 对称端
        let id = Identity::new(b"adb-pairing");
        let (spake, client_spake_msg) =
            Spake2::<Ed25519Group>::start_symmetric(&Password::new(code.as_bytes()), &id);
        // 2. 发送客户端 SPAKE2 报文
        Self::write_packet(&mut stream, PACKET_TYPE_SPAKE2_MSG, &client_spake_msg).await?;

        // 3. 读取服务端 SPAKE2 报文
        let (pkt_type, server_spake_msg) = Self::read_packet(&mut stream).await?;
        if pkt_type != PACKET_TYPE_SPAKE2_MSG {
            return Err(RmvError::Adb {
                message: format!(
                    "Unexpected pairing packet type: expected SPAKE2, got {}",
                    pkt_type
                ),
                code: None,
            });
        }

        // 4. 派生对称共享密钥
        let shared_secret = spake.finish(&server_spake_msg).map_err(|e| RmvError::Adb {
            message: format!(
                "SPAKE2 key derivation failed (incorrect PIN code?): {:?}",
                e
            ),
            code: None,
        })?;

        // 5. HKDF 派生 AES 密钥 (16 bytes) 与 IV (12 bytes)
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key_iv = [0u8; 28];
        hk.expand(b"adb-pairing-keys", &mut key_iv)
            .map_err(|e| RmvError::Adb {
                message: format!("HKDF expand failed: {:?}", e),
                code: None,
            })?;

        let (key_bytes, iv_bytes) = key_iv.split_at(16);
        let cipher = Aes128Gcm::new_from_slice(key_bytes).map_err(|e| RmvError::Adb {
            message: format!("Cipher init failed: {:?}", e),
            code: None,
        })?;
        let nonce = Nonce::from_slice(&iv_bytes[..12]);

        // 6. 加密发送客户端证书 (PEER_INFO)
        let encrypted_peer_info = cipher
            .encrypt(nonce, cred.cert_pem.as_bytes())
            .map_err(|e| RmvError::Adb {
                message: format!("Certificate encryption failed: {:?}", e),
                code: None,
            })?;
        Self::write_packet(&mut stream, PACKET_TYPE_PEER_INFO, &encrypted_peer_info).await?;

        // 7. 读取服务端回显证书
        let (info_type, resp_enc) = Self::read_packet(&mut stream).await?;
        if info_type != PACKET_TYPE_PEER_INFO {
            return Err(RmvError::Adb {
                message: format!("Unexpected pairing response packet type: {}", info_type),
                code: None,
            });
        }

        let _ = cipher
            .decrypt(nonce, resp_enc.as_slice())
            .map_err(|e| RmvError::Adb {
                message: format!("Failed to decrypt device peer info: {:?}", e),
                code: None,
            })?;

        Ok(())
    }

    async fn write_packet(stream: &mut TcpStream, pkt_type: u8, payload: &[u8]) -> Result<()> {
        let mut header = [0u8; 6];
        header[0] = PAIRING_PACKET_VERSION;
        header[1] = pkt_type;
        header[2..6].copy_from_slice(&(payload.len() as u32).to_be_bytes());

        stream.write_all(&header).await.map_err(|e| RmvError::Adb {
            message: format!("Failed to write pairing packet header: {}", e),
            code: None,
        })?;
        stream.write_all(payload).await.map_err(|e| RmvError::Adb {
            message: format!("Failed to write pairing packet payload: {}", e),
            code: None,
        })?;
        stream.flush().await.map_err(|e| RmvError::Adb {
            message: format!("Failed to flush stream: {}", e),
            code: None,
        })?;
        Ok(())
    }

    async fn read_packet(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
        let mut header = [0u8; 6];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("Failed to read pairing packet header: {}", e),
                code: None,
            })?;

        let _ver = header[0];
        let pkt_type = header[1];
        let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;

        let mut payload = vec![0u8; len];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| RmvError::Adb {
                message: format!("Failed to read pairing packet payload: {}", e),
                code: None,
            })?;

        Ok((pkt_type, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spake2_pairing_handshake_success() {
        let code = "876543";
        let id = Identity::new(b"adb-pairing");

        // Client side
        let (client, client_msg) =
            Spake2::<Ed25519Group>::start_symmetric(&Password::new(code.as_bytes()), &id);

        // Server side
        let (server, server_msg) =
            Spake2::<Ed25519Group>::start_symmetric(&Password::new(code.as_bytes()), &id);

        // Exchange messages
        let client_secret = client
            .finish(&server_msg)
            .expect("Client derivation failed");
        let server_secret = server
            .finish(&client_msg)
            .expect("Server derivation failed");

        assert_eq!(client_secret, server_secret);

        // HKDF derivation
        let hk = Hkdf::<Sha256>::new(None, &client_secret);
        let mut key_iv = [0u8; 28];
        hk.expand(b"adb-pairing-keys", &mut key_iv).unwrap();
        let (key_bytes, iv_bytes) = key_iv.split_at(16);

        let cipher = Aes128Gcm::new_from_slice(key_bytes).unwrap();
        let nonce = Nonce::from_slice(&iv_bytes[..12]);

        let cert_data = b"-----BEGIN CERTIFICATE-----\nMIIB...fake_cert\n-----END CERTIFICATE-----";
        let enc = cipher.encrypt(nonce, cert_data.as_ref()).unwrap();

        // Decrypt on server side with same derived secret
        let hk_server = Hkdf::<Sha256>::new(None, &server_secret);
        let mut server_key_iv = [0u8; 28];
        hk_server
            .expand(b"adb-pairing-keys", &mut server_key_iv)
            .unwrap();
        let server_cipher = Aes128Gcm::new_from_slice(&server_key_iv[..16]).unwrap();
        let server_nonce = Nonce::from_slice(&server_key_iv[16..28]);

        let dec = server_cipher.decrypt(server_nonce, enc.as_slice()).unwrap();
        assert_eq!(dec, cert_data);
    }

    #[test]
    fn test_spake2_pairing_wrong_code_fails() {
        let id = Identity::new(b"adb-pairing");

        let (client, _client_msg) =
            Spake2::<Ed25519Group>::start_symmetric(&Password::new(b"123456"), &id);
        let (server, server_msg) =
            Spake2::<Ed25519Group>::start_symmetric(&Password::new(b"654321"), &id);

        let client_secret = client.finish(&server_msg).expect("Derivation executes");
        let server_secret = server.finish(&_client_msg).expect("Derivation executes");

        // Mismatched passwords produce different derived secrets
        assert_ne!(client_secret, server_secret);
    }
}
