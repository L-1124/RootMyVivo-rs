use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedSender;

use crate::error::{Result, RmvError};
use crate::event::{EngineEvent, LogLevel};
use crate::ksu::KsuVariant;
use crate::mirror::MirrorConfig;
use rust_i18n::t;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerAssetInfo {
    pub variant: KsuVariant,
    pub version: String,
    pub file_name: String,
    pub download_url: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedManagerInfo {
    pub variant: Option<KsuVariant>,
    pub file_name: String,
    pub path: PathBuf,
    pub size: u64,
}

pub fn get_static_asset(variant: KsuVariant) -> ManagerAssetInfo {
    match variant {
        KsuVariant::KernelSU => ManagerAssetInfo {
            variant,
            version: "v3.3.0".to_string(),
            file_name: "KernelSU_v3.3.0_32601-release.apk".to_string(),
            download_url:
                "https://github.com/tiann/KernelSU/releases/download/v3.3.0/KernelSU_v3.3.0_32601-release.apk"
                    .to_string(),
            size: 11306351,
        },
        KsuVariant::KernelSuNext => ManagerAssetInfo {
            variant,
            version: "v3.4.0".to_string(),
            file_name: "KernelSU_Next_v3.4.0_33294-release.apk".to_string(),
            download_url:
                "https://github.com/KernelSU-Next/KernelSU-Next/releases/download/v3.4.0/KernelSU_Next_v3.4.0_33294-release.apk"
                    .to_string(),
            size: 12435552,
        },
        KsuVariant::SukiSuUltra => ManagerAssetInfo {
            variant,
            version: "v4.2.0".to_string(),
            file_name: "SukiSU_v4.2.0_40900-release.apk".to_string(),
            download_url:
                "https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/v4.2.0/SukiSU_v4.2.0_40900-release.apk"
                    .to_string(),
            size: 14766150,
        },
        KsuVariant::ReSukiSu => ManagerAssetInfo {
            variant,
            version: "v4.2.0-rc3".to_string(),
            file_name: "ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk".to_string(),
            download_url:
                "https://github.com/ReSukiSU/ReSukiSU/releases/download/v4.2.0-rc3/ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk"
                    .to_string(),
            size: 9831969,
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
    size: u64,
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
    let candidates = if !non_spoofed.is_empty() {
        non_spoofed
    } else {
        apks
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

pub struct ManagerDownloader;

impl ManagerDownloader {
    pub fn default_cache_dir() -> PathBuf {
        let base = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base)
            .join(".rmv")
            .join("cache")
            .join("managers")
    }

    pub async fn fetch_asset(
        client: &Client,
        variant: KsuVariant,
        target_version: Option<&str>,
    ) -> Result<ManagerAssetInfo> {
        let (owner, repo) = variant.github_repo();

        let (url, is_latest) = match target_version {
            Some(ver) => {
                let tag = ver.trim();
                (
                    format!(
                        "https://api.github.com/repos/{}/{}/releases/tags/{}",
                        owner, repo, tag
                    ),
                    false,
                )
            }
            None => (
                format!(
                    "https://api.github.com/repos/{}/{}/releases/latest",
                    owner, repo
                ),
                true,
            ),
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

        let fetch_res = match fetch_timeout {
            Ok(res) => res,
            Err(_) => {
                if is_latest {
                    return Ok(get_static_asset(variant));
                } else {
                    return Err(RmvError::KsuFailed(
                        t!(
                            "error.manager_asset_not_found",
                            name = variant.display_name(),
                            version = target_version.unwrap_or("latest")
                        )
                        .to_string(),
                    ));
                }
            }
        };

        let release: Option<GithubRelease> = match fetch_res {
            Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
            Ok(resp) if resp.status().as_u16() == 404 && is_latest => {
                let fallback_url = format!(
                    "https://api.github.com/repos/{}/{}/releases?per_page=1",
                    owner, repo
                );
                if let Ok(f_resp) = client
                    .get(&fallback_url)
                    .header("User-Agent", "RootMyVivo-rs")
                    .header("Accept", "application/vnd.github.v3+json")
                    .send()
                    .await
                {
                    if let Ok(list) = f_resp.json::<Vec<GithubRelease>>().await {
                        list.into_iter().next()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(rel) = release {
            if let Some(asset) = select_best_apk(&rel.assets) {
                return Ok(ManagerAssetInfo {
                    variant,
                    version: rel.tag_name,
                    file_name: asset.name.clone(),
                    download_url: asset.browser_download_url.clone(),
                    size: asset.size,
                });
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

    pub async fn download_manager(
        client: &Client,
        variant: KsuVariant,
        target_version: Option<&str>,
        custom_cache_dir: Option<&Path>,
        mirror_override: Option<&str>,
        event_tx: Option<&UnboundedSender<EngineEvent>>,
    ) -> Result<PathBuf> {
        let asset_info = Self::fetch_asset(client, variant, target_version).await?;

        let cache_dir = custom_cache_dir
            .map(|p| p.to_path_buf())
            .unwrap_or_else(Self::default_cache_dir);

        tokio::fs::create_dir_all(&cache_dir).await?;

        let dest_filename = format!(
            "{}_{}_{}",
            variant.id(),
            asset_info.version,
            asset_info.file_name
        );
        let dest_path = cache_dir.join(&dest_filename);

        if dest_path.exists() {
            if let Ok(meta) = tokio::fs::metadata(&dest_path).await {
                if meta.len() == asset_info.size || (meta.len() > 1_000_000 && asset_info.size == 0)
                {
                    if let Some(tx) = event_tx {
                        let _ = tx.send(EngineEvent::Log {
                            level: LogLevel::Ok,
                            line: t!(
                                "log.manager_cached_reuse",
                                filename = dest_filename.clone(),
                                size_mb = meta.len() / 1024 / 1024
                            )
                            .to_string(),
                        });
                    }
                    return Ok(dest_path);
                }
            }
        }

        let download_urls =
            MirrorConfig::resolve_mirror_urls(&asset_info.download_url, mirror_override);

        let mut success = false;
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

            let req_timeout =
                tokio::time::timeout(std::time::Duration::from_secs(10), client.get(url).send())
                    .await;

            let resp = match req_timeout {
                Ok(Ok(r)) if r.status().is_success() => r,
                Ok(Ok(r)) => {
                    last_error = Some(format!("HTTP 状态码: {}", r.status()));
                    continue;
                }
                Ok(Err(e)) => {
                    last_error = Some(e.to_string());
                    continue;
                }
                Err(_) => {
                    last_error = Some("连接超时 (10s)".to_string());
                    continue;
                }
            };

            let total_size = resp.content_length().unwrap_or(asset_info.size);
            let mut file = match File::create(&dest_path).await {
                Ok(f) => f,
                Err(e) => return Err(RmvError::Io(e)),
            };

            if let Some(tx) = event_tx {
                let _ = tx.send(EngineEvent::Download {
                    filename: dest_filename.clone(),
                    downloaded: 0,
                    total: total_size,
                });
            }

            let mut stream = resp.bytes_stream();
            let mut downloaded: u64 = 0;
            let mut stream_failed = false;
            loop {
                let chunk_res =
                    match tokio::time::timeout(std::time::Duration::from_secs(15), stream.next())
                        .await
                    {
                        Ok(Some(res)) => res,
                        Ok(None) => break,
                        Err(_) => {
                            last_error = Some("数据读取超时 (15s)".to_string());
                            stream_failed = true;
                            break;
                        }
                    };

                match chunk_res {
                    Ok(chunk) => {
                        if let Err(e) = file.write_all(&chunk).await {
                            last_error = Some(e.to_string());
                            stream_failed = true;
                            break;
                        }
                        downloaded += chunk.len() as u64;

                        if let Some(tx) = event_tx {
                            let _ = tx.send(EngineEvent::Download {
                                filename: dest_filename.clone(),
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

            if !stream_failed {
                if let Some(tx) = event_tx {
                    let _ = tx.send(EngineEvent::Download {
                        filename: dest_filename.clone(),
                        downloaded: total_size,
                        total: total_size,
                    });
                }
            }

            if stream_failed {
                let _ = tokio::fs::remove_file(&dest_path).await;
                continue;
            }

            let _ = file.flush().await;

            if let Ok(meta) = tokio::fs::metadata(&dest_path).await {
                if total_size > 0
                    && meta.len() != total_size
                    && (meta.len() < total_size.saturating_sub(1024))
                {
                    let _ = tokio::fs::remove_file(&dest_path).await;
                    last_error = Some("文件大小不匹配".to_string());
                    continue;
                }
            }

            success = true;
            break;
        }

        if !success {
            let err_msg = last_error.unwrap_or_else(|| "unknown error".to_string());
            return Err(RmvError::KsuFailed(
                t!(
                    "error.manager_download_failed",
                    name = variant.display_name(),
                    message = err_msg
                )
                .to_string(),
            ));
        }

        if let Some(tx) = event_tx {
            let _ = tx.send(EngineEvent::Log {
                level: LogLevel::Ok,
                line: t!(
                    "log.manager_download_ok",
                    name = variant.display_name(),
                    path = dest_path.display().to_string()
                )
                .to_string(),
            });
        }

        Ok(dest_path)
    }

    pub fn list_cached_managers(custom_dir: Option<&Path>) -> Vec<CachedManagerInfo> {
        let dir = custom_dir
            .map(|p| p.to_path_buf())
            .unwrap_or_else(Self::default_cache_dir);

        let mut list = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.to_lowercase().ends_with(".apk") {
                        let meta = entry.metadata().ok();
                        let size = meta.map(|m| m.len()).unwrap_or(0);

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
            assert_eq!(asset.variant, *variant);
            assert!(!asset.version.is_empty());
            assert!(asset.file_name.ends_with(".apk"));
            assert!(asset.download_url.starts_with("https://github.com/"));
            assert!(asset.size > 0);
        }
    }

    #[test]
    fn test_select_best_apk() {
        let assets = vec![
            GithubAsset {
                name: "KernelSU_Next_v3.4.0_33294-spoofed_33294-release.apk".to_string(),
                browser_download_url: "url1".to_string(),
                size: 100,
            },
            GithubAsset {
                name: "KernelSU_Next_v3.4.0_33294-release.apk".to_string(),
                browser_download_url: "url2".to_string(),
                size: 200,
            },
        ];
        let best = select_best_apk(&assets).unwrap();
        assert_eq!(best.name, "KernelSU_Next_v3.4.0_33294-release.apk");

        let resukisu_assets = vec![
            GithubAsset {
                name: "ReSukiSU_v4.2.0-rc3_35171-universal-release.apk".to_string(),
                browser_download_url: "url_uni".to_string(),
                size: 300,
            },
            GithubAsset {
                name: "ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk".to_string(),
                browser_download_url: "url_arm64".to_string(),
                size: 400,
            },
        ];
        let best_resukisu = select_best_apk(&resukisu_assets).unwrap();
        assert_eq!(
            best_resukisu.name,
            "ReSukiSU_v4.2.0-rc3_35171-arm64-v8a-release.apk"
        );
    }
}
