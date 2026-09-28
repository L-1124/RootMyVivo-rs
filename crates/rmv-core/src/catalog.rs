use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedSender;

use crate::device::DeviceInfo;
use crate::error::{Result, RmvError};
use crate::event::EngineEvent;

pub const DEFAULT_CATALOG_URL: &str =
    "https://raw.githubusercontent.com/zenyxx-xd/RootMyVivo-Payloads/main/catalog/devices.json";
pub const JSDELIVR_CATALOG_URL: &str =
    "https://cdn.jsdelivr.net/gh/zenyxx-xd/RootMyVivo-Payloads@main/catalog/devices.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogUrlSource {
    CliOverride,
    EnvVar,
    ConfigFile,
    Default,
}

pub struct CatalogConfig;

impl CatalogConfig {
    pub fn config_path() -> PathBuf {
        let base = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join(".rmv").join("catalog_url")
    }

    pub fn get_saved_url() -> Option<String> {
        let path = Self::config_path();
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn set_saved_url(url: &str) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, url.trim())?;
        Ok(())
    }

    pub fn reset_saved_url() -> Result<bool> {
        let path = Self::config_path();
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn resolve_url(cli_override: Option<&str>) -> (String, CatalogUrlSource) {
        if let Some(url) = cli_override {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return (trimmed.to_string(), CatalogUrlSource::CliOverride);
            }
        }

        if let Ok(env_url) = std::env::var("RMV_CATALOG_URL") {
            let trimmed = env_url.trim();
            if !trimmed.is_empty() {
                return (trimmed.to_string(), CatalogUrlSource::EnvVar);
            }
        }

        if let Some(saved) = Self::get_saved_url() {
            return (saved, CatalogUrlSource::ConfigFile);
        }

        (DEFAULT_CATALOG_URL.to_string(), CatalogUrlSource::Default)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadFile {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelBuild {
    #[serde(rename = "match")]
    pub match_patterns: Vec<String>,
    #[serde(default)]
    pub exploit: Option<String>,
    pub status: String,
    pub file: Option<PayloadFile>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKernelEntry {
    pub build: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    #[serde(rename = "marketName")]
    pub market_name: String,
    pub code: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub kernels: Vec<DeviceKernelEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogV5 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub builds: HashMap<String, KernelBuild>,
    pub devices: Vec<DeviceEntry>,
}

impl CatalogV5 {
    pub async fn fetch_default_with_url(custom_url: Option<&str>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self::fetch_with_url(&client, custom_url).await
    }

    pub async fn fetch(client: &Client) -> Result<Self> {
        Self::fetch_with_url(client, None).await
    }

    pub async fn fetch_with_url(client: &Client, custom_url: Option<&str>) -> Result<Self> {
        let (resolved_url, source) = CatalogConfig::resolve_url(custom_url);
        let urls: Vec<&str> = if source == CatalogUrlSource::Default {
            vec![DEFAULT_CATALOG_URL, JSDELIVR_CATALOG_URL]
        } else {
            vec![&resolved_url, DEFAULT_CATALOG_URL, JSDELIVR_CATALOG_URL]
        };
        let mut last_err = None;

        for url in urls {
            match client.get(url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.json::<CatalogV5>().await {
                            Ok(cat) => return Ok(cat),
                            Err(e) => last_err = Some(RmvError::Http(e)),
                        }
                    }
                }
                Err(e) => last_err = Some(RmvError::Http(e)),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            RmvError::CatalogFetchFailed("载荷目录节点均无法连接或解析失败".to_string())
        }))
    }

    pub fn match_payload<'a>(
        &'a self,
        device: &DeviceInfo,
    ) -> Option<(&'a DeviceEntry, &'a KernelBuild)> {
        let dev_code = device.device.to_lowercase();
        let dev_model = device.model.to_lowercase();

        // 1. 根据设备型号/代号匹配设备条目
        let target_device = self.devices.iter().find(|d| {
            d.code.to_lowercase() == dev_code
                || d.models.iter().any(|m| m.to_lowercase() == dev_code)
                || d.names.iter().any(|n| n.to_lowercase() == dev_model)
        })?;

        // 2. 根据内核信息匹配具体内核构建
        for k in &target_device.kernels {
            if let Some(build) = self.builds.get(&k.build) {
                for pattern in &build.match_patterns {
                    let pat_clean = pattern.trim_end_matches(".*");
                    if device.kernel_full.contains(pat_clean) {
                        return Some((target_device, build));
                    }
                    if let Some(gki) = &device.gki_git_id {
                        if pat_clean.contains(gki) {
                            return Some((target_device, build));
                        }
                    }
                }
            }
        }

        // 3. 回退策略：如果在已知 kernels 里没列出，但在 builds 里有匹配 GKI commit id 的构建
        if let Some(gki) = &device.gki_git_id {
            for build in self.builds.values() {
                for pattern in &build.match_patterns {
                    if pattern.contains(gki) {
                        return Some((target_device, build));
                    }
                }
            }
        }

        None
    }

    pub async fn download_payload(
        client: &Client,
        file_info: &PayloadFile,
        dest_path: &Path,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<()> {
        let mut download_urls = vec![file_info.url.clone()];
        download_urls.extend(file_info.mirrors.clone());

        let mut success = false;
        let mut last_error = None;

        for url in download_urls {
            let resp = match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    last_error = Some(format!("HTTP 状态码: {}", r.status()));
                    continue;
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    continue;
                }
            };

            let total_size = resp.content_length().unwrap_or(file_info.size);
            let mut downloaded: u64 = 0;
            let mut hasher = Sha256::new();

            let mut file = match File::create(dest_path).await {
                Ok(f) => f,
                Err(e) => return Err(RmvError::Io(e)),
            };

            let mut stream = resp.bytes_stream();
            let mut stream_failed = false;

            while let Some(chunk_res) = stream.next().await {
                match chunk_res {
                    Ok(chunk) => {
                        hasher.update(&chunk);
                        downloaded += chunk.len() as u64;

                        if let Err(e) = file.write_all(&chunk).await {
                            last_error = Some(e.to_string());
                            stream_failed = true;
                            break;
                        }

                        if let Some(tx) = event_tx {
                            let _ = tx.send(EngineEvent::Download {
                                filename: file_info.name.clone(),
                                downloaded,
                                total: total_size,
                            });
                        }
                    }
                    Err(e) => {
                        last_error = Some(e.to_string());
                        stream_failed = true;
                        break;
                    }
                }
            }

            if stream_failed {
                let _ = tokio::fs::remove_file(dest_path).await;
                continue;
            }

            let _ = file.flush().await;
            let calculated_hash = format!("{:x}", hasher.finalize());

            if !calculated_hash.eq_ignore_ascii_case(&file_info.sha256) {
                let _ = tokio::fs::remove_file(dest_path).await;
                return Err(RmvError::HashMismatch {
                    expected: file_info.sha256.clone(),
                    actual: calculated_hash,
                });
            }

            success = true;
            break;
        }

        if !success {
            return Err(RmvError::CatalogFetchFailed(format!(
                "下载载荷失败: {}",
                last_error.unwrap_or_else(|| "未知下载错误".to_string())
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_v5_deserialization_and_match() {
        let sample_json = r#"{
            "schemaVersion": 5,
            "builds": {
                "g1f71897ac249": {
                    "match": ["6.6.89-android15-8-g1f71897ac249-abogki467805059-4k.*"],
                    "status": "ready",
                    "file": {
                        "name": "g1f71897ac249.so",
                        "url": "https://example.com/g1f7.so",
                        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                        "size": 147104
                    }
                }
            },
            "devices": [
                {
                    "marketName": "iQOO 13",
                    "code": "pd2408",
                    "models": ["pd2408"],
                    "names": ["V2408A"],
                    "kernels": [
                        { "build": "g1f71897ac249", "note": "origin" }
                    ]
                }
            ]
        }"#;

        let cat: CatalogV5 = serde_json::from_str(sample_json).unwrap();
        assert_eq!(cat.schema_version, 5);

        let dev = DeviceInfo::parse(
            "V2408A",
            "pd2408",
            "vivo",
            "Linux version 6.6.89-android15-8-g1f71897ac249-abogki467805059-4k #1 SMP",
            "boot-1",
        )
        .unwrap();

        let matched = cat.match_payload(&dev);
        assert!(matched.is_some());
        let (d_entry, k_build) = matched.unwrap();
        assert_eq!(d_entry.market_name, "iQOO 13");
        assert_eq!(k_build.file.as_ref().unwrap().name, "g1f71897ac249.so");
    }

    #[test]
    fn test_catalog_config_resolve_url_precedence() {
        let (url, src) = CatalogConfig::resolve_url(Some("https://cli-override.com/devices.json"));
        assert_eq!(url, "https://cli-override.com/devices.json");
        assert_eq!(src, CatalogUrlSource::CliOverride);

        if std::env::var("RMV_CATALOG_URL").is_err() && CatalogConfig::get_saved_url().is_none() {
            let (def_url, def_src) = CatalogConfig::resolve_url(None);
            assert_eq!(def_url, DEFAULT_CATALOG_URL);
            assert_eq!(def_src, CatalogUrlSource::Default);
        }
    }
}
