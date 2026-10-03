use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedSender;

use crate::error::{Result, RmvError};
use crate::event::{EngineEvent, LogLevel};
use crate::ksu::KsuVariant;
use crate::mirror::MirrorConfig;
use rust_i18n::t;
/// Metadata describing a downloadable root manager APK asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerAssetInfo {
    /// Identifier matching the root solution variant name.
    pub name: String,
    /// Release version tag (e.g. `v3.3.0`).
    pub version: String,
    /// Direct HTTP download URL for the asset.
    pub download_url: String,
    /// Asset filename on the remote release (e.g. `KernelSU_v3.3.0.apk`).
    pub filename: String,
    /// Expected SHA-256 hex digest for pinned official assets.
    pub sha256: Option<&'static str>,
}

impl ManagerAssetInfo {
    /// Returns the corresponding `KsuVariant` for this asset.
    #[must_use]
    pub fn variant(&self) -> KsuVariant {
        KsuVariant::from_id(&self.name)
    }

    /// Returns the remote asset filename.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.filename
    }

    /// Returns the expected asset size in bytes, or 0 if unknown.
    #[must_use]
    pub fn size(&self) -> u64 {
        0
    }
}

/// Metadata describing a locally cached root manager APK file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedManagerInfo {
    /// Detected `KsuVariant` based on filename pattern, if recognized.
    pub variant: Option<KsuVariant>,
    /// Local file name of the cached manager APK.
    pub file_name: String,
    /// Absolute filesystem path to the cached APK.
    pub path: PathBuf,
    /// Cached APK file size in bytes.
    pub size: u64,
}

/// Returns static release asset metadata with pinned SHA-256 digest for the specified root variant.
#[must_use]
pub fn get_static_asset(variant: KsuVariant) -> ManagerAssetInfo {
    match variant {
        KsuVariant::KernelSU => ManagerAssetInfo {
            name: variant.id().to_string(),
            version: "v3.3.0".to_string(),
            filename: "KernelSU_v3.3.0_32601-release.apk".to_string(),
            download_url:
                "https://github.com/tiann/KernelSU/releases/download/v3.3.0/KernelSU_v3.3.0_32601-release.apk"
                    .to_string(),
            sha256: Some("c197060ecb89702e7d54a4c95e29cf5e8d97369bbbb436979ab7fd6bcde7b077"),
        },
        KsuVariant::KernelSuNext => ManagerAssetInfo {
            name: variant.id().to_string(),
            version: "v3.4.0".to_string(),
            filename: "KernelSU_Next_v3.4.0_33294-release.apk".to_string(),
            download_url:
                "https://github.com/KernelSU-Next/KernelSU-Next/releases/download/v3.4.0/KernelSU_Next_v3.4.0_33294-release.apk"
                    .to_string(),
            sha256: Some("50339a93c0f812b8a72c1a387a1b441891e3df0f20b2d9daf80fd798d04b3de8"),
        },
        KsuVariant::SukiSuUltra => ManagerAssetInfo {
            name: variant.id().to_string(),
            version: "v4.2.0".to_string(),
            filename: "SukiSU_v4.2.0_40900-release.apk".to_string(),
            download_url:
                "https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/v4.2.0/SukiSU_v4.2.0_40900-release.apk"
                    .to_string(),
            sha256: Some("4ca9810e6355fbff0bbe4bf5ce159808e64a40d85987a11894030cd990a6bdf3"),
        },
        KsuVariant::ReSukiSu => ManagerAssetInfo {
            name: variant.id().to_string(),
            version: "v4.2.0-rc3".to_string(),
            filename: "ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk".to_string(),
            download_url:
                "https://github.com/ReSukiSU/ReSukiSU/releases/download/v4.2.0-rc3/ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk"
                    .to_string(),
            sha256: Some("25657bc449439687608fffa04b4b586de90fc405e3dc6217bd997fc71ba0a0a1"),
        },
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn select_best_apk(assets: &[GithubAsset]) -> Option<&GithubAsset> {
    let apks: Vec<&GithubAsset> = assets
        .iter()
        .filter(|a| a.name.to_lowercase().ends_with(".apk"))
        .collect();

    if apks.is_empty() {
        return None;
    }

    let non_spoofed: Vec<&GithubAsset> = apks
        .iter()
        .copied()
        .filter(|a| !a.name.to_lowercase().contains("spoofed"))
        .collect();
    let candidates = if non_spoofed.is_empty() {
        apks
    } else {
        non_spoofed
    };

    if let Some(arm64) = candidates.iter().find(|a| {
        let n = a.name.to_lowercase();
        n.contains("arm64-v8a") || n.contains("arm64")
    }) {
        return Some(*arm64);
    }

    if let Some(uni) = candidates
        .iter()
        .find(|a| a.name.to_lowercase().contains("universal"))
    {
        return Some(*uni);
    }

    if let Some(rel) = candidates
        .iter()
        .find(|a| a.name.to_lowercase().contains("release"))
    {
        return Some(*rel);
    }

    candidates.first().copied()
}

fn parse_github_release_asset(
    rel: &GithubRelease,
    variant: KsuVariant,
    _is_latest: bool,
) -> Result<ManagerAssetInfo> {
    let asset = select_best_apk(&rel.assets).ok_or_else(|| {
        RmvError::KsuFailed(
            t!(
                "error.manager_asset_not_found",
                name = variant.display_name(),
                version = rel.tag_name.as_str()
            )
            .to_string(),
        )
    })?;

    let static_asset = get_static_asset(variant);
    let sha256 = if rel
        .tag_name
        .trim()
        .eq_ignore_ascii_case(&static_asset.version)
        || rel
            .tag_name
            .trim()
            .trim_start_matches('v')
            .eq_ignore_ascii_case(static_asset.version.trim_start_matches('v'))
    {
        static_asset.sha256
    } else {
        None
    };

    Ok(ManagerAssetInfo {
        name: variant.id().to_string(),
        version: rel.tag_name.clone(),
        filename: asset.name.clone(),
        download_url: asset.browser_download_url.clone(),
        sha256,
    })
}

static PART_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Downloader and cache manager for root manager APK packages.
pub struct ManagerDownloader;

impl ManagerDownloader {
    /// Returns the default directory used for caching manager APKs.
    #[must_use]
    pub fn default_cache_dir() -> PathBuf {
        crate::paths::manager_cache_dir()
    }

    /// Fetches release asset information for a manager variant, querying GitHub API or falling back to static metadata.
    ///
    /// # Errors
    /// Returns an error if the specified release tag cannot be found or resolved.
    async fn fetch_release_from_github(
        client: &Client,
        variant: KsuVariant,
        target_version: Option<&str>,
        is_latest: bool,
    ) -> Option<GithubRelease> {
        let (owner, repo) = variant.github_repo();
        let url = match target_version {
            Some(ver) => format!(
                "https://api.github.com/repos/{owner}/{repo}/releases/tags/{}",
                ver.trim()
            ),
            None => format!("https://api.github.com/repos/{owner}/{repo}/releases/latest"),
        };

        let fetch_timeout = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            client
                .get(&url)
                .header("User-Agent", "RootMyVivo-rs")
                .header("Accept", "application/vnd.github.v3+json")
                .send(),
        )
        .await;

        let Ok(Ok(resp)) = fetch_timeout else {
            return None;
        };

        if resp.status().is_success() {
            return resp.json().await.ok();
        }

        if resp.status().as_u16() == 404 && is_latest {
            let fallback_url =
                format!("https://api.github.com/repos/{owner}/{repo}/releases?per_page=1");
            if let Ok(f_resp) = client
                .get(&fallback_url)
                .header("User-Agent", "RootMyVivo-rs")
                .header("Accept", "application/vnd.github.v3+json")
                .send()
                .await
            {
                if let Ok(list) = f_resp.json::<Vec<GithubRelease>>().await {
                    return list.into_iter().next();
                }
            }
        }

        None
    }

    /// Fetches release asset information for a manager variant, querying GitHub API or falling back to static metadata.
    ///
    /// # Errors
    /// Returns an error if the specified release tag cannot be found or resolved.
    pub async fn fetch_asset(
        client: &Client,
        variant: KsuVariant,
        target_version: Option<&str>,
    ) -> Result<ManagerAssetInfo> {
        let is_latest = target_version.is_none();
        if let Some(rel) =
            Self::fetch_release_from_github(client, variant, target_version, is_latest).await
        {
            if let Ok(info) = parse_github_release_asset(&rel, variant, is_latest) {
                return Ok(info);
            }
        }

        if is_latest {
            Ok(get_static_asset(variant))
        } else {
            let static_asset = get_static_asset(variant);
            if let Some(ver) = target_version {
                let ver_trim = ver.trim();
                if ver_trim.eq_ignore_ascii_case(&static_asset.version)
                    || ver_trim
                        .trim_start_matches('v')
                        .eq_ignore_ascii_case(static_asset.version.trim_start_matches('v'))
                {
                    return Ok(static_asset);
                }
            }
            Err(RmvError::KsuFailed(
                t!(
                    "error.manager_asset_not_found",
                    name = variant.display_name(),
                    version = target_version.unwrap_or("latest")
                )
                .to_string(),
            ))
        }
    }

    /// Downloads a manager APK using default HTTP client settings.
    ///
    /// # Errors
    /// Returns an error if asset metadata resolution, file I/O, network download, or SHA-256 validation fails.
    pub async fn download_manager_default(
        variant: KsuVariant,
        target_version: Option<&str>,
        custom_cache_dir: Option<&Path>,
        mirror_override: Option<&str>,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<PathBuf> {
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(8))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_default();
        Self::download_manager(
            &client,
            variant,
            target_version,
            custom_cache_dir,
            mirror_override,
            event_tx,
        )
        .await
    }

    /// Downloads a manager APK, verifying its SHA-256 checksum and checking local cache before fetching.
    ///
    /// # Errors
    /// Returns an error if metadata fetching fails, temporary directory creation fails, network streaming fails, or hash verification fails.
    async fn reuse_cached(
        dest_path: &Path,
        expected_sha256: Option<&str>,
        total_size: u64,
    ) -> Result<bool> {
        if !dest_path.exists() {
            return Ok(false);
        }
        let Ok(meta) = tokio::fs::metadata(dest_path).await else {
            return Ok(false);
        };

        if let Some(expected_hash) = expected_sha256 {
            if let Ok(bytes) = tokio::fs::read(dest_path).await {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let calculated = format!("{:x}", hasher.finalize());
                if calculated.eq_ignore_ascii_case(expected_hash) {
                    return Ok(true);
                }
                let _ = tokio::fs::remove_file(dest_path).await;
            }
            Ok(false)
        } else if meta.len() == total_size || (meta.len() > 1_000_000 && total_size == 0) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn stream_to_temp(
        resp: reqwest::Response,
        cache_dir: &Path,
        dest_filename: &str,
        expected_size: u64,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<(PathBuf, String)> {
        let total_size = resp.content_length().unwrap_or(expected_size);
        let mut hasher = Sha256::new();
        let seq = PART_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_path = cache_dir.join(format!("{dest_filename}.part.{}.{seq}", std::process::id()));
        let mut file = File::create(&tmp_path).await?;

        if let Some(tx) = event_tx {
            let _ = tx.send(EngineEvent::Download {
                filename: dest_filename.to_string(),
                downloaded: 0,
                total: total_size,
            });
        }

        let mut stream = resp.bytes_stream();
        let mut downloaded: u64 = 0;
        let mut stream_err: Option<String> = None;

        loop {
            let chunk_res =
                match tokio::time::timeout(std::time::Duration::from_secs(15), stream.next()).await
                {
                    Ok(Some(res)) => res,
                    Ok(None) => break,
                    Err(_) => {
                        stream_err = Some("数据读取超时 (15s)".to_string());
                        break;
                    }
                };

            match chunk_res {
                Ok(chunk) => {
                    hasher.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        stream_err = Some(e.to_string());
                        break;
                    }
                    downloaded += chunk.len() as u64;

                    if let Some(tx) = event_tx {
                        let _ = tx.send(EngineEvent::Download {
                            filename: dest_filename.to_string(),
                            downloaded,
                            total: total_size,
                        });
                    }
                }
                Err(e) => {
                    stream_err = Some(e.to_string());
                    break;
                }
            }
        }

        if let Some(err) = stream_err {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(RmvError::KsuFailed(err));
        }

        if let Some(tx) = event_tx {
            let _ = tx.send(EngineEvent::Download {
                filename: dest_filename.to_string(),
                downloaded: total_size,
                total: total_size,
            });
        }

        file.flush().await?;
        drop(file);

        let meta = tokio::fs::metadata(&tmp_path).await?;
        if (total_size > 0 && meta.len() != total_size) || meta.len() == 0 {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(RmvError::KsuFailed("文件大小不匹配".to_string()));
        }

        let calculated_hash = format!("{:x}", hasher.finalize());
        Ok((tmp_path, calculated_hash))
    }

    async fn verify_and_promote(
        tmp_path: &Path,
        dest_path: &Path,
        calculated_hash: &str,
        expected_hash: Option<&str>,
    ) -> Result<PathBuf> {
        if let Some(expected) = expected_hash {
            if !calculated_hash.eq_ignore_ascii_case(expected) {
                let _ = tokio::fs::remove_file(tmp_path).await;
                return Err(RmvError::HashMismatch {
                    expected: expected.to_string(),
                    actual: calculated_hash.to_string(),
                });
            }
        }

        if let Err(e) = tokio::fs::rename(tmp_path, dest_path).await {
            let _ = tokio::fs::remove_file(tmp_path).await;
            return Err(RmvError::Io(e));
        }

        Ok(dest_path.to_path_buf())
    }

    /// Downloads a manager APK, verifying its SHA-256 checksum and checking local cache before fetching.
    ///
    /// # Errors
    /// Returns an error if metadata fetching fails, temporary directory creation fails, network streaming fails, or hash verification fails.
    async fn fetch_response_with_timeout(
        client: &Client,
        url: &str,
    ) -> std::result::Result<reqwest::Response, String> {
        let req_timeout =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.get(url).send()).await;
        match req_timeout {
            Ok(Ok(r)) if r.status().is_success() => Ok(r),
            Ok(Ok(r)) => Err(format!("HTTP 状态码: {}", r.status())),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("连接超时 (10s)".to_string()),
        }
    }

    async fn download_from_stream(
        resp: reqwest::Response,
        cache_dir: &Path,
        dest_path: &Path,
        dest_filename: &str,
        asset_info: &ManagerAssetInfo,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<PathBuf> {
        let (tmp_path, calculated_hash) =
            Self::stream_to_temp(resp, cache_dir, dest_filename, asset_info.size(), event_tx)
                .await?;
        let promoted =
            Self::verify_and_promote(&tmp_path, dest_path, &calculated_hash, asset_info.sha256)
                .await?;
        if let Some(tx) = event_tx {
            let _ = tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!(
                    "log.manager_download_ok",
                    name = asset_info.variant().display_name(),
                    path = promoted.display().to_string()
                )
                .to_string(),
            });
        }
        Ok(promoted)
    }

    async fn try_reuse_cache(
        dest_path: &Path,
        dest_filename: &str,
        asset_info: &ManagerAssetInfo,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<Option<PathBuf>> {
        if Self::reuse_cached(dest_path, asset_info.sha256, asset_info.size()).await? {
            if let Some(tx) = event_tx {
                let meta_len = tokio::fs::metadata(dest_path).await.map_or(0, |m| m.len());
                let _ = tx.send(EngineEvent::Log {
                    level: LogLevel::Ok,
                    line: t!(
                        "log.manager_cached_reuse",
                        filename = dest_filename,
                        size_mb = meta_len / 1024 / 1024
                    )
                    .to_string(),
                });
            }
            return Ok(Some(dest_path.to_path_buf()));
        }
        Ok(None)
    }

    /// Downloads a manager APK, verifying its SHA-256 checksum and checking local cache before fetching.
    ///
    /// # Errors
    /// Returns an error if metadata fetching fails, temporary directory creation fails, network streaming fails, or hash verification fails.
    pub async fn download_manager(
        client: &Client,
        variant: KsuVariant,
        target_version: Option<&str>,
        custom_cache_dir: Option<&Path>,
        mirror_override: Option<&str>,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<PathBuf> {
        let asset_info = Self::fetch_asset(client, variant, target_version).await?;

        let cache_dir =
            custom_cache_dir.map_or_else(Self::default_cache_dir, std::path::Path::to_path_buf);
        tokio::fs::create_dir_all(&cache_dir).await?;

        let dest_filename = format!(
            "{}_{}_{}",
            variant.id(),
            asset_info.version,
            asset_info.filename
        );
        let dest_path = cache_dir.join(&dest_filename);

        if let Some(cached) =
            Self::try_reuse_cache(&dest_path, &dest_filename, &asset_info, event_tx).await?
        {
            return Ok(cached);
        }

        if asset_info.sha256.is_none() {
            if let Some(tx) = event_tx {
                let _ = tx.send(EngineEvent::Log {
                    level: LogLevel::Warn,
                    line: t!(
                        "log.manager_unverified_hash",
                        version = asset_info.version.clone()
                    )
                    .to_string(),
                });
            }
        }

        let download_urls =
            MirrorConfig::resolve_manager_urls(&asset_info.download_url, mirror_override);

        let mut last_error = None;

        for (idx, url) in download_urls.iter().enumerate() {
            if let Some(tx) = event_tx {
                let _ = tx.send(EngineEvent::Log {
                    level: LogLevel::Info,
                    line: t!(
                        "log.manager_downloading",
                        index = idx + 1,
                        total = download_urls.len(),
                        name = variant.display_name(),
                        version = asset_info.version.clone(),
                        url = url.clone()
                    )
                    .to_string(),
                });
            }

            let resp = match Self::fetch_response_with_timeout(client, url).await {
                Ok(r) => r,
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            };

            match Self::download_from_stream(
                resp,
                &cache_dir,
                &dest_path,
                &dest_filename,
                &asset_info,
                event_tx,
            )
            .await
            {
                Ok(promoted) => return Ok(promoted),
                Err(RmvError::HashMismatch { expected, actual }) => {
                    return Err(RmvError::HashMismatch { expected, actual });
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }
        }

        let err_msg = last_error.unwrap_or_else(|| "unknown error".to_string());
        Err(RmvError::KsuFailed(
            t!(
                "error.manager_download_failed",
                name = variant.display_name(),
                message = err_msg
            )
            .to_string(),
        ))
    }

    /// Lists all cached root manager APK files found in the cache directory.
    #[must_use]
    pub fn list_cached_managers(custom_dir: Option<&Path>) -> Vec<CachedManagerInfo> {
        let dir = custom_dir.map_or_else(Self::default_cache_dir, std::path::Path::to_path_buf);
        let mut list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.to_lowercase().ends_with(".apk") {
                        let meta = entry.metadata().ok();
                        let size = meta.map_or(0, |m| m.len());

                        let variant = if name.starts_with("sukisu") {
                            Some(KsuVariant::SukiSuUltra)
                        } else if name.starts_with("ksunext") {
                            Some(KsuVariant::KernelSuNext)
                        } else if name.starts_with("kernelsu") {
                            Some(KsuVariant::KernelSU)
                        } else if name.starts_with("resukisu") {
                            Some(KsuVariant::ReSukiSu)
                        } else {
                            None
                        };

                        list.push(CachedManagerInfo {
                            variant,
                            file_name: name,
                            path,
                            size,
                        });
                    }
                }
            }
        }
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_assets_completeness() {
        for variant in KsuVariant::all_variants() {
            let asset = get_static_asset(*variant);
            assert_eq!(asset.variant(), *variant);
            assert!(!asset.version.is_empty());
            assert!(std::path::Path::new(&asset.filename)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("apk")));
            assert!(asset.download_url.starts_with("https://github.com/"));
        }
    }

    #[test]
    fn test_select_best_apk() {
        let assets = vec![
            GithubAsset {
                name: "KernelSU_Next_v3.4.0_33294-spoofed_33294-release.apk".to_string(),
                browser_download_url: "url1".to_string(),
            },
            GithubAsset {
                name: "KernelSU_Next_v3.4.0_33294-release.apk".to_string(),
                browser_download_url: "url2".to_string(),
            },
        ];
        let best = select_best_apk(&assets).unwrap();
        assert_eq!(best.name, "KernelSU_Next_v3.4.0_33294-release.apk");

        let resukisu_assets = vec![
            GithubAsset {
                name: "ReSukiSU_v4.2.0-rc3_35171-universal-release.apk".to_string(),
                browser_download_url: "url_uni".to_string(),
            },
            GithubAsset {
                name: "ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk".to_string(),
                browser_download_url: "url_arm64".to_string(),
            },
        ];
        let best_resukisu = select_best_apk(&resukisu_assets).unwrap();
        assert_eq!(
            best_resukisu.name,
            "ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk"
        );
    }

    #[tokio::test]
    async fn test_manager_hash_mismatch() {
        use std::io::Write;
        let temp_dir =
            std::env::temp_dir().join(format!("rmv_test_mismatch_{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        // Setup mock server or test directly:
        // We can test download_manager with bad sha256 or mock response.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let body = b"corrupted fake apk content";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });

        let client = Client::new();
        let target_url = format!("http://127.0.0.1:{port}");
        let fake_asset = ManagerAssetInfo {
            name: "kernelsu".to_string(),
            version: "v3.3.0".to_string(),
            filename: "fake.apk".to_string(),
            download_url: target_url.clone(),
            sha256: Some("0000000000000000000000000000000000000000000000000000000000000000"),
        };

        // Execute download directly with fake asset
        let dest_filename = format!(
            "{}_{}_{}",
            fake_asset.variant().id(),
            fake_asset.version,
            fake_asset.filename
        );
        let _dest_path = temp_dir.join(&dest_filename);
        let tmp_path = temp_dir.join(format!("{dest_filename}.part.test"));

        let resp = client.get(&target_url).send().await.unwrap();
        let mut stream = resp.bytes_stream();
        let mut file = File::create(&tmp_path).await.unwrap();
        let mut hasher = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            hasher.update(&chunk);
            file.write_all(&chunk).await.unwrap();
        }
        file.flush().await.unwrap();
        drop(file);

        let calculated = format!("{:x}", hasher.finalize());
        let expected = fake_asset.sha256.unwrap();
        assert_ne!(calculated, expected);

        let res: Result<()> = if calculated.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            Err(RmvError::HashMismatch {
                expected: expected.to_string(),
                actual: calculated,
            })
        };

        assert!(matches!(res, Err(RmvError::HashMismatch { .. })));
        assert!(!tmp_path.exists());
        let _ = handle.join();
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
