use std::path::PathBuf;

use crate::error::Result;

pub const DEFAULT_GITHUB_MIRRORS: &[&str] = &[
    "https://ghproxy.net/",
    "https://gh-proxy.com/",
    "https://hub.gitmirror.com/",
];

pub struct MirrorConfig;

impl MirrorConfig {
    pub fn config_path() -> PathBuf {
        crate::paths::mirror_config_file()
    }

    pub fn get_saved_mirror() -> Option<String> {
        let path = Self::config_path();
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn set_saved_mirror(mirror: &str) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, mirror.trim())?;
        Ok(())
    }

    pub fn reset_saved_mirror() -> Result<bool> {
        let path = Self::config_path();
        if path.exists() {
            std::fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn apply_mirror(raw_url: &str, mirror_prefix: &str) -> String {
        let trimmed_prefix = mirror_prefix.trim();
        let trimmed_url = raw_url.trim();

        if trimmed_prefix.eq_ignore_ascii_case("direct")
            || trimmed_prefix.eq_ignore_ascii_case("none")
            || trimmed_prefix.is_empty()
        {
            return trimmed_url.to_string();
        }

        let prefix = if trimmed_prefix.ends_with('/') {
            trimmed_prefix.to_string()
        } else {
            format!("{}/", trimmed_prefix)
        };

        format!("{}{}", prefix, trimmed_url)
    }

    pub fn resolve_mirror_urls(raw_url: &str, cli_override: Option<&str>) -> Vec<String> {
        let raw = raw_url.trim();

        if let Some(cli_prefix) = cli_override {
            let trimmed = cli_prefix.trim();
            if trimmed.eq_ignore_ascii_case("direct")
                || trimmed.eq_ignore_ascii_case("none")
                || trimmed == "false"
            {
                return vec![raw.to_string()];
            }
            if !trimmed.is_empty() {
                let mirrored = Self::apply_mirror(raw, trimmed);
                return vec![mirrored, raw.to_string()];
            }
        }

        if let Ok(env_mirror) = std::env::var("RMV_GITHUB_MIRROR") {
            let trimmed = env_mirror.trim();
            if trimmed.eq_ignore_ascii_case("direct") || trimmed.eq_ignore_ascii_case("none") {
                return vec![raw.to_string()];
            }
            if !trimmed.is_empty() {
                let mirrored = Self::apply_mirror(raw, trimmed);
                return vec![mirrored, raw.to_string()];
            }
        }

        if let Some(saved) = Self::get_saved_mirror() {
            if saved.eq_ignore_ascii_case("direct") || saved.eq_ignore_ascii_case("none") {
                return vec![raw.to_string()];
            }
            let mirrored = Self::apply_mirror(raw, &saved);
            return vec![mirrored, raw.to_string()];
        }

        let mut urls = Vec::with_capacity(DEFAULT_GITHUB_MIRRORS.len() + 1);
        urls.push(raw.to_string());
        for mirror in DEFAULT_GITHUB_MIRRORS {
            urls.push(Self::apply_mirror(raw, mirror));
        }
        urls
    }

    pub fn resolve_manager_urls(raw_url: &str, cli_override: Option<&str>) -> Vec<String> {
        let raw = raw_url.trim();

        if let Some(cli_prefix) = cli_override {
            let trimmed = cli_prefix.trim();
            if trimmed.eq_ignore_ascii_case("direct")
                || trimmed.eq_ignore_ascii_case("none")
                || trimmed == "false"
            {
                return vec![raw.to_string()];
            }
            if !trimmed.is_empty() {
                let mirrored = Self::apply_mirror(raw, trimmed);
                return vec![raw.to_string(), mirrored];
            }
        }

        if let Ok(env_mirror) = std::env::var("RMV_GITHUB_MIRROR") {
            let trimmed = env_mirror.trim();
            if trimmed.eq_ignore_ascii_case("direct") || trimmed.eq_ignore_ascii_case("none") {
                return vec![raw.to_string()];
            }
            if !trimmed.is_empty() {
                let mirrored = Self::apply_mirror(raw, trimmed);
                return vec![raw.to_string(), mirrored];
            }
        }

        if let Some(saved) = Self::get_saved_mirror() {
            if saved.eq_ignore_ascii_case("direct") || saved.eq_ignore_ascii_case("none") {
                return vec![raw.to_string()];
            }
            let mirrored = Self::apply_mirror(raw, &saved);
            return vec![raw.to_string(), mirrored];
        }

        let mut urls = Vec::with_capacity(DEFAULT_GITHUB_MIRRORS.len() + 1);
        urls.push(raw.to_string());
        for mirror in DEFAULT_GITHUB_MIRRORS {
            urls.push(Self::apply_mirror(raw, mirror));
        }
        urls
    }

    pub async fn probe_fastest(
        client: &reqwest::Client,
        urls: &[String],
    ) -> Option<(usize, String)> {
        if urls.is_empty() {
            return None;
        }
        if urls.len() == 1 {
            return Some((0, urls[0].clone()));
        }

        use futures_util::stream::{FuturesUnordered, StreamExt};
        use std::time::Duration;

        let mut tasks = FuturesUnordered::new();
        for (idx, url) in urls.iter().enumerate() {
            let u = url.clone();
            let c = client.clone();
            tasks.push(async move {
                let probe_req = c.head(&u).timeout(Duration::from_millis(2000)).send();

                match probe_req.await {
                    Ok(resp) if resp.status().is_success() => Some((idx, u)),
                    _ => {
                        let range_req = c
                            .get(&u)
                            .header(reqwest::header::RANGE, "bytes=0-0")
                            .timeout(Duration::from_millis(2000))
                            .send();
                        match range_req.await {
                            Ok(resp)
                                if resp.status().is_success()
                                    || resp.status() == reqwest::StatusCode::PARTIAL_CONTENT =>
                            {
                                Some((idx, u))
                            }
                            _ => None,
                        }
                    }
                }
            });
        }

        while let Some(res) = tasks.next().await {
            if let Some(hit) = res {
                return Some(hit);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_mirror() {
        let raw = "https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk";
        assert_eq!(
            MirrorConfig::apply_mirror(raw, "https://ghproxy.net/"),
            "https://ghproxy.net/https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk"
        );
        assert_eq!(
            MirrorConfig::apply_mirror(raw, "https://ghproxy.net"),
            "https://ghproxy.net/https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk"
        );
        assert_eq!(MirrorConfig::apply_mirror(raw, "direct"), raw);
        assert_eq!(MirrorConfig::apply_mirror(raw, "none"), raw);
    }

    #[test]
    fn test_resolve_mirror_urls_cli_override() {
        let raw = "https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk";
        let urls = MirrorConfig::resolve_mirror_urls(raw, Some("https://gh-proxy.com"));
        assert_eq!(urls.len(), 2);
        assert_eq!(
            urls[0],
            "https://gh-proxy.com/https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk"
        );
        assert_eq!(urls[1], raw);

        let direct_urls = MirrorConfig::resolve_mirror_urls(raw, Some("direct"));
        assert_eq!(direct_urls, vec![raw.to_string()]);
    }

    #[test]
    fn test_resolve_manager_urls_prioritizes_direct() {
        let raw = "https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk";
        let urls = MirrorConfig::resolve_manager_urls(raw, Some("https://gh-proxy.com"));
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], raw);
        assert_eq!(
            urls[1],
            "https://gh-proxy.com/https://github.com/tiann/KernelSU/releases/download/v3.3.0/test.apk"
        );
    }

    #[tokio::test]
    async fn test_probe_fastest_empty_or_single() {
        let client = reqwest::Client::new();
        assert_eq!(MirrorConfig::probe_fastest(&client, &[]).await, None);
        let single = vec!["https://example.com/single".to_string()];
        assert_eq!(
            MirrorConfig::probe_fastest(&client, &single).await,
            Some((0, "https://example.com/single".to_string()))
        );
    }
}
