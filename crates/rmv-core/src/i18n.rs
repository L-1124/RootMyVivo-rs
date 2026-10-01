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
