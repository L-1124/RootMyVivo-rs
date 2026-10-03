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

/// Default official raw GitHub catalog URL.
pub const DEFAULT_CATALOG_URL: &str =
    "https://raw.githubusercontent.com/zenyxx-xd/RootMyVivo-Payloads/main/catalog/devices.json";
/// Fallback jsDelivr CDN catalog mirror URL.
pub const JSDELIVR_CATALOG_URL: &str =
    "https://cdn.jsdelivr.net/gh/zenyxx-xd/RootMyVivo-Payloads@main/catalog/devices.json";

/// Maximum age in seconds before offline catalog cache is considered stale (7 days).
pub const CATALOG_CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 3600;

/// Metadata accompanying a locally cached catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogCacheMeta {
    /// URL the catalog was fetched from.
    pub url: String,
    /// Unix epoch timestamp in seconds when the catalog was saved.
    pub fetched_at: u64,
}

/// Source origin of the resolved catalog URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogUrlSource {
    /// Explicitly overridden via command-line argument.
    CliOverride,
    /// Specified via `RMV_CATALOG_URL` environment variable.
    EnvVar,
    /// Loaded from local persistent config file (`~/.rmv/catalog_url`).
    ConfigFile,
    /// Default official mirror URLs.
    Default,
}

/// Catalog configuration and URL resolution helpers.
pub struct CatalogConfig;

impl CatalogConfig {
    /// Returns persistent catalog config path.
    #[must_use]
    pub fn config_path() -> PathBuf {
        crate::paths::catalog_url_file()
    }

    /// Reads custom saved catalog URL if present.
    #[must_use]
    pub fn get_saved_url() -> Option<String> {
        let path = Self::config_path();
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Saves a custom catalog URL to local configuration.
    ///
    /// # Errors
    /// Returns an error if filesystem directory creation or write fails.
    pub fn set_saved_url(url: &str) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, url.trim())?;
        Ok(())
    }

    /// Resets custom catalog URL back to default.
    ///
    /// # Errors
    /// Returns an error if file removal fails.
    pub fn reset_saved_url() -> Result<bool> {
        let path = Self::config_path();
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Resolves effective catalog URL and source tier.
    #[must_use]
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

/// Exploit payload binary file metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadFile {
    /// Local file name of the payload.
    pub name: String,
    /// Primary download URL.
    pub url: String,
    /// Fallback download mirrors.
    #[serde(default)]
    pub mirrors: Vec<String>,
    /// Cryptographic SHA-256 checksum hex digest.
    pub sha256: String,
    /// Expected payload file size in bytes.
    pub size: u64,
}

/// Kernel build configuration and exploit association.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelBuild {
    /// Fingerprint matching patterns (e.g. `abogki*`).
    #[serde(rename = "match")]
    pub match_patterns: Vec<String>,
    /// Exploit identifier string.
    #[serde(default)]
    pub exploit: Option<String>,
    /// Support status string.
    pub status: String,
    /// Associated payload file entry.
    pub file: Option<PayloadFile>,
    /// Environment variable overrides.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Kernel entry association within a device profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKernelEntry {
    /// Referenced build ID matching a `KernelBuild` entry.
    pub build: String,
    /// Optional explanatory note.
    #[serde(default)]
    pub note: Option<String>,
}

/// Device marketing profile and kernel mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Consumer device market name.
    #[serde(rename = "marketName")]
    pub market_name: String,
    /// Hardware board code.
    pub code: String,
    /// Model number aliases.
    #[serde(default)]
    pub models: Vec<String>,
    /// Alternative marketing names.
    #[serde(default)]
    pub names: Vec<String>,
    /// Associated kernel builds.
    #[serde(default)]
    pub kernels: Vec<DeviceKernelEntry>,
}

/// Root payload catalog definition matching devices to exploit builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogV5 {
    /// Catalog schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Map of kernel build identifiers to build specifications.
    pub builds: HashMap<String, KernelBuild>,
    /// List of registered device profiles.
    pub devices: Vec<DeviceEntry>,
    /// Accompanying cache metadata if loaded from disk.
    #[serde(skip)]
    pub cached_meta: Option<CatalogCacheMeta>,
}

impl CatalogV5 {
    /// Returns persistent catalog cache directory path.
    #[must_use]
    pub fn cache_dir() -> PathBuf {
        crate::paths::cache_dir()
    }

    /// Returns catalog JSON cache file path.
    #[must_use]
    pub fn cache_file() -> PathBuf {
        Self::cache_dir().join("catalog.json")
    }

    /// Returns catalog metadata cache file path.
    #[must_use]
    pub fn cache_meta_file() -> PathBuf {
        Self::cache_dir().join("catalog.json.meta")
    }

    /// Checks whether a cached catalog is within freshness threshold.
    #[must_use]
    pub fn is_fresh(fetched_at: u64, max_age_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        now.saturating_sub(fetched_at) < max_age_secs
    }

    /// Loads locally cached catalog and metadata if present on disk.
    pub async fn load_cached() -> Option<(CatalogV5, CatalogCacheMeta)> {
        let cache_file = Self::cache_file();
        let meta_file = Self::cache_meta_file();

        let json_bytes = tokio::fs::read(&cache_file).await.ok()?;
        let mut cat: CatalogV5 = serde_json::from_slice(&json_bytes).ok()?;

        let meta_bytes = tokio::fs::read(&meta_file).await.ok()?;
        let meta: CatalogCacheMeta = serde_json::from_slice(&meta_bytes).ok()?;

        cat.cached_meta = Some(meta.clone());
        Some((cat, meta))
    }

    /// Saves catalog and metadata to local disk cache.
    pub async fn save_cached(catalog: &CatalogV5, url: &str) {
        let dir = Self::cache_dir();
        if tokio::fs::create_dir_all(&dir).await.is_err() {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let meta = CatalogCacheMeta {
            url: url.to_string(),
            fetched_at: now,
        };

        if let Ok(json) = serde_json::to_vec_pretty(catalog) {
            let _ = tokio::fs::write(Self::cache_file(), json).await;
        }
        if let Ok(meta_json) = serde_json::to_vec_pretty(&meta) {
            let _ = tokio::fs::write(Self::cache_meta_file(), meta_json).await;
        }
    }

    /// Fetches catalog using a default HTTP client and custom URL.
    ///
    /// # Errors
    /// Returns an error if catalog fetch fails across all endpoints.
    pub async fn fetch_default_with_url(custom_url: Option<&str>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self::fetch_with_url(&client, custom_url).await
    }

    /// Fetches catalog using provided HTTP client and default URL.
    ///
    /// # Errors
    /// Returns an error if catalog fetch fails across all endpoints.
    pub async fn fetch(client: &Client) -> Result<Self> {
        Self::fetch_with_url(client, None).await
    }

    /// Fetches catalog trying custom URL first, falling back to official mirrors.
    ///
    /// # Errors
    /// Returns an error if catalog fetch fails across all endpoints.
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
                            Ok(cat) => {
                                if source == CatalogUrlSource::Default {
                                    Self::save_cached(&cat, url).await;
                                }
                                return Ok(cat);
                            }
                            Err(e) => last_err = Some(RmvError::Http(e)),
                        }
                    }
                }
                Err(e) => last_err = Some(RmvError::Http(e)),
            }
        }

        if let Some((cat, _meta)) = Self::load_cached().await {
            return Ok(cat);
        }

        Err(last_err.unwrap_or_else(|| {
            RmvError::CatalogFetchFailed("载荷目录节点均无法连接或解析失败".to_string())
        }))
    }

    /// Matches target device against registered builds and payloads.
    #[must_use]
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

    /// Downloads payload file and verifies SHA-256 integrity.
    ///
    /// # Errors
    /// Returns an error if download fails or SHA-256 digest mismatches.
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

    #[test]
    fn test_catalog_cache_meta_and_freshness() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(CatalogV5::is_fresh(now, 60));
        assert!(CatalogV5::is_fresh(now - 100, 200));
        assert!(!CatalogV5::is_fresh(now - 300, 200));
        assert!(!CatalogV5::is_fresh(
            now - (CATALOG_CACHE_MAX_AGE_SECS + 10),
            CATALOG_CACHE_MAX_AGE_SECS
        ));

        let meta = CatalogCacheMeta {
            url: "https://example.com/devices.json".to_string(),
            fetched_at: now,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: CatalogCacheMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, meta);
    }
}
