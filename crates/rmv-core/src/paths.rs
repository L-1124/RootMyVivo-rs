use std::path::PathBuf;

pub fn rmv_home_dir() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(".rmv")
}

pub fn catalog_url_file() -> PathBuf {
    rmv_home_dir().join("catalog_url")
}

pub fn cache_dir() -> PathBuf {
    rmv_home_dir().join("cache")
}

pub fn history_dir() -> PathBuf {
    rmv_home_dir().join("history")
}

pub fn manager_cache_dir() -> PathBuf {
    cache_dir().join("managers")
}

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
