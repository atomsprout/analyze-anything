//! Which model to ask, and where it lives.
//!
//! Settings come from the `[ai]` table of a configuration file and from command-line flags; a
//! flag wins over the file. The API key itself is never written in either: the settings name the
//! environment variable that holds it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The kind of service that is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Claude through Anthropic's Messages API.
    Anthropic,
    /// Any service that speaks OpenAI's chat-completions protocol: OpenAI itself, a gateway, or a
    /// model server on this machine.
    #[serde(alias = "openai")]
    OpenaiCompatible,
}

impl Provider {
    pub fn id(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenaiCompatible => "openai-compatible",
        }
    }

    pub fn from_id(id: &str) -> Option<Provider> {
        match id {
            "anthropic" | "claude" => Some(Provider::Anthropic),
            "openai-compatible" | "openai" => Some(Provider::OpenaiCompatible),
            _ => None,
        }
    }
}

/// Settings as they are written down: every one optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    pub provider: Option<Provider>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub max_findings: Option<usize>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    ai: Option<Overrides>,
}

/// Settings with nothing left open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub provider: Provider,
    pub model: String,
    /// Without a trailing slash. For Anthropic the host (`/v1/messages` is added); for an
    /// OpenAI-compatible service the address that `/chat/completions` is added to.
    pub base_url: String,
    /// Name of the environment variable that holds the API key.
    pub api_key_env: String,
    /// False when a key is optional: a local server at an address the user gave.
    pub key_required: bool,
    /// Most findings to send.
    pub max_findings: usize,
    pub timeout: Duration,
}

pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5-5";
pub const DEFAULT_MAX_FINDINGS: usize = 300;
const DEFAULT_TIMEOUT_SECONDS: u64 = 600;

/// Where the configuration file is looked for when none is named: `AA_CONFIG`, else
/// `analyze-anything/config.toml` in the user's configuration folder.
pub fn default_path() -> Option<PathBuf> {
    let set = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    if let Some(path) = set("AA_CONFIG") {
        return Some(path);
    }
    let folder =
        if cfg!(windows) { set("APPDATA") } else { set("XDG_CONFIG_HOME").or_else(|| set("HOME").map(|home| home.join(".config"))) };
    folder.map(|folder| folder.join("analyze-anything").join("config.toml"))
}

/// Reads the `[ai]` table of the file at `path`. A file that does not exist, or has no such
/// table, gives empty settings.
pub fn read_file(path: &Path) -> Result<Overrides, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Overrides::default()),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    parse(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// The `[ai]` table of a configuration file's text.
pub fn parse(text: &str) -> Result<Overrides, String> {
    let file: ConfigFile = toml::from_str(text).map_err(|error| error.to_string())?;
    Ok(file.ai.unwrap_or_default())
}

/// Puts flags over the file and fills in what the provider implies.
pub fn resolve(file: Overrides, flags: Overrides) -> Result<Settings, String> {
    let provider = flags.provider.or(file.provider).ok_or_else(|| {
        "AI interpretation is off: no provider is set. Pass --provider anthropic or --provider openai-compatible, \
         or write an [ai] table in the configuration file (see docs/AI.md)"
            .to_string()
    })?;
    let model = flags.model.or(file.model);
    let base_url = flags.base_url.or(file.base_url);
    let api_key_env = flags.api_key_env.or(file.api_key_env);
    let (model, default_url, default_env) = match provider {
        Provider::Anthropic => {
            (model.unwrap_or_else(|| DEFAULT_ANTHROPIC_MODEL.to_string()), "https://api.anthropic.com", "ANTHROPIC_API_KEY")
        }
        Provider::OpenaiCompatible => (
            model.ok_or_else(|| "an OpenAI-compatible service has no default model: set `model` (or pass --model)".to_string())?,
            "https://api.openai.com/v1",
            "OPENAI_API_KEY",
        ),
    };
    // A server the user points at, on this machine for instance, may want no key at all.
    let key_required = provider == Provider::Anthropic || base_url.is_none() || api_key_env.is_some();
    let base_url = base_url.unwrap_or_else(|| default_url.to_string()).trim_end_matches('/').to_string();
    if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
        return Err(format!("base_url must start with https:// or http://, not {base_url:?}"));
    }
    Ok(Settings {
        provider,
        model,
        base_url,
        api_key_env: api_key_env.unwrap_or_else(|| default_env.to_string()),
        key_required,
        max_findings: flags.max_findings.or(file.max_findings).unwrap_or(DEFAULT_MAX_FINDINGS).max(1),
        timeout: Duration::from_secs(flags.timeout_seconds.or(file.timeout_seconds).unwrap_or(DEFAULT_TIMEOUT_SECONDS).max(1)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_set_means_off() {
        let error = resolve(Overrides::default(), Overrides::default()).expect_err("off");
        assert!(error.contains("AI interpretation is off"));
    }

    #[test]
    fn anthropic_fills_in_its_defaults() {
        let file = parse("[ai]\nprovider = \"anthropic\"\n").expect("parses");
        let settings = resolve(file, Overrides::default()).expect("resolves");
        assert_eq!(settings.model, DEFAULT_ANTHROPIC_MODEL);
        assert_eq!(settings.base_url, "https://api.anthropic.com");
        assert_eq!(settings.api_key_env, "ANTHROPIC_API_KEY");
        assert!(settings.key_required);
    }

    #[test]
    fn a_flag_wins_over_the_file() {
        let file = parse("[ai]\nprovider = \"anthropic\"\nmodel = \"claude-haiku-5-5\"\n").expect("parses");
        let flags = Overrides { model: Some("claude-sonnet-5-5".into()), ..Overrides::default() };
        assert_eq!(resolve(file, flags).expect("resolves").model, "claude-sonnet-5-5");
    }

    #[test]
    fn an_openai_compatible_service_needs_a_model_and_may_need_no_key() {
        let file = parse("[ai]\nprovider = \"openai-compatible\"\nbase_url = \"http://localhost:11434/v1/\"\n").expect("parses");
        assert!(resolve(file.clone(), Overrides::default()).expect_err("no model").contains("no default model"));
        let flags = Overrides { model: Some("qwen3".into()), ..Overrides::default() };
        let settings = resolve(file, flags).expect("resolves");
        assert_eq!(settings.base_url, "http://localhost:11434/v1");
        assert!(!settings.key_required);
    }

    #[test]
    fn openai_itself_needs_a_key() {
        let file = parse("[ai]\nprovider = \"openai\"\nmodel = \"gpt-x\"\n").expect("parses");
        let settings = resolve(file, Overrides::default()).expect("resolves");
        assert_eq!(settings.base_url, "https://api.openai.com/v1");
        assert!(settings.key_required);
    }

    #[test]
    fn a_key_written_in_the_file_is_refused() {
        assert!(parse("[ai]\nprovider = \"anthropic\"\napi_key = \"sk-secret\"\n").expect_err("refused").contains("api_key"));
    }

    #[test]
    fn other_tables_and_a_missing_file_are_fine() {
        assert_eq!(parse("[other]\nx = 1\n").expect("parses"), Overrides::default());
        assert_eq!(read_file(Path::new("/nonexistent/analyze-anything/config.toml")).expect("reads"), Overrides::default());
    }
}
