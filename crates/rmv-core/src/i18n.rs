use serde::{Deserialize, Serialize};

/// Supported application localization languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Language {
    /// English (fallback default).
    #[default]
    En,
    /// Simplified Chinese (`zh-CN`).
    Zh,
}

impl Language {
    /// Parses a language from an ISO locale or language code.
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        let lower = code.to_lowercase();
        if lower.starts_with("zh") || lower.contains("chinese") {
            Self::Zh
        } else {
            Self::En
        }
    }

    /// Returns the canonical locale code string.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh-CN",
        }
    }

    /// Detects current system locale from environment or OS settings.
    #[must_use]
    pub fn detect_system() -> Self {
        if let Ok(val) = std::env::var("RMV_LANG") {
            return Self::from_code(&val);
        }

        if let Some(locale) = sys_locale::get_locale() {
            let lower = locale.to_lowercase();
            if lower.starts_with("zh") || lower.contains("chinese") {
                return Self::Zh;
            }
        }

        Self::En
    }
}

/// Sets active runtime locale for `rust_i18n::t!` macros.
pub fn set_current_language(lang: Language) {
    rust_i18n::set_locale(lang.code());
}

/// Returns currently active localization language.
#[must_use]
pub fn current_language() -> Language {
    let loc = rust_i18n::locale();
    if loc.starts_with("zh") {
        Language::Zh
    } else {
        Language::En
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn collect_keys(prefix: &str, value: &Value, keys: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    let next_prefix = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    collect_keys(&next_prefix, v, keys);
                }
            }
            _ => {
                keys.insert(prefix.to_string());
            }
        }
    }

    #[test]
    fn test_i18n_keys_bidirectional_completeness() {
        let en_str = include_str!("../locales/en.json");
        let zh_str = include_str!("../locales/zh-CN.json");

        let en_val: Value = serde_json::from_str(en_str).expect("Valid en.json");
        let zh_val: Value = serde_json::from_str(zh_str).expect("Valid zh-CN.json");

        let mut en_keys = BTreeSet::new();
        let mut zh_keys = BTreeSet::new();

        collect_keys("", &en_val, &mut en_keys);
        collect_keys("", &zh_val, &mut zh_keys);

        let missing_in_zh: Vec<_> = en_keys.difference(&zh_keys).cloned().collect();
        let missing_in_en: Vec<_> = zh_keys.difference(&en_keys).cloned().collect();

        assert!(
            missing_in_zh.is_empty(),
            "Keys present in en.json but missing in zh-CN.json: {missing_in_zh:?}"
        );
        assert!(
            missing_in_en.is_empty(),
            "Keys present in zh-CN.json but missing in en.json: {missing_in_en:?}"
        );
    }

    fn scan_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    scan_rs_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
    }

    #[test]
    fn test_all_code_i18n_keys_exist_in_locales() {
        let en_str = include_str!("../locales/en.json");
        let en_val: Value = serde_json::from_str(en_str).expect("Valid en.json");
        let mut locale_keys = BTreeSet::new();
        collect_keys("", &en_val, &mut locale_keys);

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let crates_dir = manifest_dir.parent().expect("crates parent directory");

        let mut rs_files = Vec::new();
        scan_rs_files(&crates_dir.join("rmv-core").join("src"), &mut rs_files);
        scan_rs_files(&crates_dir.join("rmv-cli").join("src"), &mut rs_files);

        let t_re = regex::Regex::new(r#"\bt!\(\s*"([^"]+)""#).expect("valid regex");
        let table_re =
            regex::Regex::new(r#"\(\s*"[^"]+"\s*,\s*"([^"]+)"\s*\)"#).expect("valid regex");

        let mut code_keys = BTreeSet::new();
        for file in rs_files {
            if let Ok(content) = std::fs::read_to_string(&file) {
                for caps in t_re.captures_iter(&content) {
                    if let Some(m) = caps.get(1) {
                        code_keys.insert(m.as_str().to_string());
                    }
                }
                for caps in table_re.captures_iter(&content) {
                    if let Some(m) = caps.get(1) {
                        let key = m.as_str();
                        if key.starts_with("cli.") {
                            code_keys.insert(key.to_string());
                        }
                    }
                }
            }
        }

        assert!(
            !code_keys.is_empty(),
            "Should discover translation keys in code"
        );
        let missing: Vec<_> = code_keys.difference(&locale_keys).cloned().collect();
        assert!(
            missing.is_empty(),
            "Translation keys referenced in code but missing in locales: {missing:#?}"
        );

        let unused: Vec<_> = locale_keys.difference(&code_keys).cloned().collect();
        assert!(
            unused.is_empty(),
            "Locale keys no longer referenced by any code path (delete or wire up): {unused:#?}"
        );
    }
}
