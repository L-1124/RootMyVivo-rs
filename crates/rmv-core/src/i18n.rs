use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Language {
    #[default]
    En,
    Zh,
}

impl Language {
    pub fn from_code(code: &str) -> Self {
        let lower = code.to_lowercase();
        if lower.starts_with("zh") || lower.contains("chinese") {
            Self::Zh
        } else {
            Self::En
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh-CN",
        }
    }

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

pub fn set_current_language(lang: Language) {
    rust_i18n::set_locale(lang.code());
}

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
            "Keys present in en.json but missing in zh-CN.json: {:?}",
            missing_in_zh
        );
        assert!(
            missing_in_en.is_empty(),
            "Keys present in zh-CN.json but missing in en.json: {:?}",
            missing_in_en
        );
    }
}
