use std::path::PathBuf;

/// Returns the root `~/.rmv` directory.
#[must_use]
pub fn rmv_home_dir() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(".rmv")
}

/// Returns the persistent catalog URL config file path (`~/.rmv/catalog_url`).
#[must_use]
pub fn catalog_url_file() -> PathBuf {
    rmv_home_dir().join("catalog_url")
}

/// Returns the persistent cache directory (`~/.rmv/cache`).
#[must_use]
pub fn cache_dir() -> PathBuf {
    rmv_home_dir().join("cache")
}

/// Returns the persistent execution history directory (`~/.rmv/history`).
#[must_use]
pub fn history_dir() -> PathBuf {
    rmv_home_dir().join("history")
}

/// Returns the downloaded root manager APK cache directory (`~/.rmv/cache/managers`).
#[must_use]
pub fn manager_cache_dir() -> PathBuf {
    cache_dir().join("managers")
}

/// Returns the custom GitHub mirror config file path (`~/.rmv/github_mirror`).
#[must_use]
pub fn mirror_config_file() -> PathBuf {
    rmv_home_dir().join("github_mirror")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rmv_paths_hierarchy() {
        let home = rmv_home_dir();
        assert!(catalog_url_file().starts_with(&home));
        assert!(cache_dir().starts_with(&home));
        assert!(history_dir().starts_with(&home));
        assert!(manager_cache_dir().starts_with(cache_dir()));
        assert!(mirror_config_file().starts_with(&home));
    }
}
