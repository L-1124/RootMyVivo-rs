use crate::error::{Result, RmvError};
use std::path::PathBuf;

#[derive(Clone)]
pub struct AdbTlsCredential {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

impl AdbTlsCredential {
    pub fn default_dir() -> PathBuf {
        let base = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join(".rmv").join("adb_tls")
    }

    pub fn load_or_generate() -> Result<Self> {
        let dir = Self::default_dir();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        if cert_path.exists() && key_path.exists() {
            if let (Ok(cert_pem), Ok(key_pem)) = (
                std::fs::read_to_string(&cert_path),
                std::fs::read_to_string(&key_path),
            ) {
                // Parse existing PEMs
                if let (Ok(cert_ders), Ok(key_der)) = (
                    rustls_pemfile::certs(&mut cert_pem.as_bytes())
                        .collect::<std::result::Result<Vec<_>, _>>(),
                    rustls_pemfile::private_key(&mut key_pem.as_bytes()),
                ) {
                    if let (Some(cert), Some(key)) = (cert_ders.first(), key_der) {
                        return Ok(Self {
                            cert_der: cert.to_vec(),
                            key_der: key.secret_der().to_vec(),
                            cert_pem,
                            key_pem,
                        });
                    }
                }
            }
        }

        // Generate fresh self-signed cert
        let subject_alt_names = vec!["rootmyvivo-client".to_string(), "localhost".to_string()];
        let cert =
            rcgen::generate_simple_self_signed(subject_alt_names).map_err(|e| RmvError::Adb {
                message: format!("Failed to generate TLS certificate: {}", e),
                code: None,
            })?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(&cert_path, &cert_pem);
        let _ = std::fs::write(&key_path, &key_pem);

        Ok(Self {
            cert_der,
            key_der,
            cert_pem,
            key_pem,
        })
    }
}
