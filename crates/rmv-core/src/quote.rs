/// Quotes a string for safe inclusion in POSIX shell commands.
#[must_use]
pub fn sh_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'-'
                | b'_'
                | b'/'
                | b'.'
                | b'='
                | b':'
                | b'@'
        )
    }) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sh_quote_empty() {
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn test_sh_quote_safe_paths() {
        assert_eq!(sh_quote("/data/local/tmp/rmv"), "/data/local/tmp/rmv");
        assert_eq!(sh_quote("preload.so"), "preload.so");
        assert_eq!(sh_quote("key=value:123@pkg"), "key=value:123@pkg");
    }

    #[test]
    fn test_sh_quote_spaces() {
        assert_eq!(sh_quote("/path with spaces/dir"), "'/path with spaces/dir'");
    }

    #[test]
    fn test_sh_quote_single_quotes() {
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_sh_quote_injection_vectors() {
        assert_eq!(sh_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(sh_quote("`id`"), "'`id`'");
        assert_eq!(sh_quote("; rm -rf /;"), "'; rm -rf /;'");
        assert_eq!(sh_quote("foo && reboot"), "'foo && reboot'");
        assert_eq!(sh_quote("foo || true"), "'foo || true'");
        assert_eq!(sh_quote("bar\nexit"), "'bar\nexit'");
    }
}
