//! Finds the URLs written in a file, as plain bytes or as UTF-16 text.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::bytes::Regex;

/// URLs kept per file. Beyond this the fact says the list was cut.
const PER_FILE: usize = 500;

static PLAIN: LazyLock<Regex> = LazyLock::new(|| compile(r"(?-u)https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,2000}"));
/// The same, where every character is followed by a zero byte (UTF-16LE, common in Windows programs).
static WIDE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?-u)h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]\x00){4,2000}"));

fn compile(pattern: &str) -> Regex {
    // The patterns are constants; a failure here is a programming error caught by the tests.
    Regex::new(pattern).unwrap_or_else(|error| panic!("invalid built-in pattern: {error}"))
}

pub struct Found {
    /// Distinct URL representations after credential redaction, sorted.
    pub urls: Vec<String>,
    pub truncated: bool,
}

pub fn find(bytes: &[u8]) -> Found {
    let mut urls = BTreeSet::new();
    let mut truncated = false;
    let plain = PLAIN.find_iter(bytes).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
    let wide = WIDE.find_iter(bytes).map(|m| m.as_bytes().iter().step_by(2).map(|b| *b as char).collect::<String>());
    for url in plain.chain(wide) {
        let url = url.trim_end_matches(['.', ',', ';', ':', '\'', '"', ')', ']', '!', '?']).to_string();
        if host(&url).is_none() {
            continue;
        }
        // URL userinfo and query credentials must not be copied into the structured report.
        // Host validation happens first; a redaction initialization failure suppresses the URL.
        if let Ok(display) = aa_core::text::redact_sensitive_text(&url) {
            if urls.len() >= PER_FILE && !urls.contains(&display) {
                truncated = true;
                break;
            }
            urls.insert(display);
        } else {
            truncated = true;
        }
    }
    Found { urls: urls.into_iter().collect(), truncated }
}

/// The lowercase host of a URL, or `None` when what follows the scheme is not a host name or an
/// IPv4 address (format strings such as `http://%s` are common in programs).
pub fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let well_formed = labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if !well_formed {
        return None;
    }
    let is_ipv4 = labels.len() == 4 && labels.iter().all(|l| l.parse::<u8>().is_ok());
    let last = labels.last()?;
    let is_name = labels.len() >= 2 && last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic());
    (is_ipv4 || is_name || host == "localhost").then_some(host)
}

/// Hosts that appear in files as XML namespaces and document types, not as servers a program calls.
pub fn is_namespace_host(host: &str) -> bool {
    const HOSTS: &[&str] = &[
        "www.w3.org",
        "schemas.android.com",
        "schemas.microsoft.com",
        "schemas.xmlsoap.org",
        "schemas.openxmlformats.org",
        "ns.adobe.com",
        "purl.org",
        "xmlpull.org",
        "www.apple.com",
        "xml.org",
        "www.inkscape.org",
        "sodipodi.sourceforge.net",
        "creativecommons.org",
    ];
    HOSTS.contains(&host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_plain_and_wide_urls() {
        let mut bytes = b"\x00\x01see https://example.com/a?b=1). and http://10.0.0.1:8080/x\x00".to_vec();
        bytes.extend("https://wide.example.org/path".encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend([0, 0]);
        let found = find(&bytes);
        assert_eq!(found.urls, ["http://10.0.0.1:8080/x", "https://example.com/a?b=1", "https://wide.example.org/path"]);
        assert!(!found.truncated);
    }

    #[test]
    fn format_strings_are_not_urls() {
        assert!(find(b"http://%s:%d/ http://{host}/x https://a/ http://-bad-.c").urls.is_empty());
    }

    #[test]
    fn host_is_extracted_and_lowercased() {
        assert_eq!(host("https://User:pw@API.Example.com:443/x").as_deref(), Some("api.example.com"));
        assert_eq!(host("http://localhost/x").as_deref(), Some("localhost"));
        assert_eq!(host("http://1.2.3.4").as_deref(), Some("1.2.3.4"));
        assert_eq!(host("http://1.2.3.999"), None);
        assert_eq!(host("http://nodot/"), None);
    }

    #[test]
    fn long_lists_are_cut_and_say_so() {
        let text: String = (0..PER_FILE + 10).map(|i| format!("https://h{i}.example.com/ ")).collect();
        let found = find(text.as_bytes());
        assert_eq!(found.urls.len(), PER_FILE);
        assert!(found.truncated);
    }

    #[test]
    fn credentials_are_removed_before_deduplication_and_the_output_limit() {
        let mut text: String = (0..PER_FILE - 1).map(|i| format!("https://h{i}.example.com/ ")).collect();
        text.push_str("https://user:fixture-password@example.com/?token=fixture-token ");
        text.push_str("https://other:another-password@example.com/?token=another-token ");
        let found = find(text.as_bytes());
        assert_eq!(found.urls.len(), PER_FILE);
        assert!(!found.truncated);
        assert!(found.urls.iter().any(|url| url == "https://[redacted]@example.com/?token=[redacted]"));
        let wide: Vec<u8> =
            "https://user:fixture-password@example.com/?token=fixture-token".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(find(&wide).urls, ["https://[redacted]@example.com/?token=[redacted]"]);
    }
}
