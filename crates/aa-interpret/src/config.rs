//! How the interpretation is done, and by whom.
//!
//! Settings come from the `[ai]` table of `~/.analyze-anything/config.toml` and from
//! command-line flags; a flag wins over the file. An API key may be written in the file
//! (`api_key`) or kept in an environment variable (`api_key_env` names it); the variable wins.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Who runs the conversation with the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    /// This program, talking to a model service with an API key.
    Api,
    /// The Claude Code command line (`claude`), with whatever account it is signed in to.
    Claude,
    /// The Codex command line (`codex`), with whatever account it is signed in to.
    Codex,
    /// Any other program, started by a command the user wrote.
    Command,
}

impl Engine {
    pub fn id(self) -> &'static str {
        match self {
            Engine::Api => "api",
            Engine::Claude => "claude",
            Engine::Codex => "codex",
            Engine::Command => "command",
        }
    }
}

/// The kind of model service the `api` engine talks to.
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
}

/// Settings as they are written down: every one optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<Engine>,
    /// True to interpret after every analysis, without `--ai`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    /// The program and arguments of the `command` engine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Most rounds of questions the model may ask before it must answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_turns: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    ai: Option<Overrides>,
}

/// The `api` engine's settings with nothing left open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Api {
    pub provider: Provider,
    pub model: String,
    /// Without a trailing slash. For Anthropic the host (`/v1/messages` is added); for an
    /// OpenAI-compatible service the address that `/chat/completions` is added to.
    pub base_url: String,
    /// The API key, when there is one.
    pub key: Option<String>,
}

/// What does the work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Api(Api),
    /// `model` is passed on to the program when set.
    Claude {
        model: Option<String>,
    },
    Codex {
        model: Option<String>,
    },
    Command {
        command: Vec<String>,
    },
}

/// Settings with nothing left open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub backend: Backend,
    pub max_turns: u32,
    pub timeout: Duration,
}

impl Settings {
    pub fn engine(&self) -> Engine {
        match self.backend {
            Backend::Api(_) => Engine::Api,
            Backend::Claude { .. } => Engine::Claude,
            Backend::Codex { .. } => Engine::Codex,
            Backend::Command { .. } => Engine::Command,
        }
    }

    /// One line on who will be asked, for the user to read before anything is sent.
    pub fn describe(&self) -> String {
        match &self.backend {
            Backend::Api(api) => format!("{} at {}", api.model, api.base_url),
            Backend::Claude { .. } => "Claude Code (the `claude` command)".into(),
            Backend::Codex { .. } => "Codex (the `codex` command)".into(),
            Backend::Command { command } => format!("the command `{}`", command.first().map(String::as_str).unwrap_or_default()),
        }
    }
}

pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5-5";
pub const DEFAULT_MAX_TURNS: u32 = 12;
const DEFAULT_TIMEOUT_SECONDS: u64 = 600;

/// Where the configuration file is: `AA_CONFIG`, else `.analyze-anything/config.toml` in the
/// user's home folder.
pub fn default_path() -> Option<PathBuf> {
    let set = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    if let Some(path) = set("AA_CONFIG") {
        return Some(path);
    }
    let home = if cfg!(windows) { set("USERPROFILE") } else { set("HOME") };
    home.map(|home| home.join(".analyze-anything").join("config.toml"))
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

/// True when a file that holds a key can be read by other users of the machine.
pub fn readable_by_others(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|data| data.permissions().mode() & 0o077 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Writes `settings` as the `[ai]` table of the file at `path`, readable by the user alone.
/// The file must hold nothing else: this program does not rewrite what it did not write.
pub fn write_file(path: &Path, settings: &Overrides) -> Result<(), String> {
    if let Ok(text) = std::fs::read_to_string(path) {
        let table: toml::Table = toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if table.keys().any(|key| key != "ai") {
            return Err(format!("{} holds more than an [ai] table; edit it by hand", path.display()));
        }
    }
    let text = toml::to_string(&ConfigFile { ai: Some(settings.clone()) }).map_err(|error| error.to_string())?;
    if let Some(folder) = path.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("cannot create {}: {error}", folder.display()))?;
    }
    let cannot = |error: std::io::Error| format!("cannot write {}: {error}", path.display());
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).map_err(cannot)?;
        // An existing file keeps its mode when opened; a key must not stay readable by others.
        file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(cannot)?;
        file.write_all(text.as_bytes()).map_err(cannot)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text).map_err(cannot)
    }
}

/// Puts flags over the file and fills in what the engine implies. `env` looks up an environment
/// variable.
pub fn resolve(file: Overrides, flags: Overrides, env: &dyn Fn(&str) -> Option<String>) -> Result<Settings, String> {
    let provider = flags.provider.or(file.provider);
    // Naming a model service is enough to mean the `api` engine.
    let engine = flags.engine.or(file.engine).or(provider.map(|_| Engine::Api)).ok_or_else(|| {
        "AI interpretation is not set up. Choose who does it, once: `analyze-anything ai claude`, `analyze-anything ai codex`, \
         or `analyze-anything ai api --provider … --model …` (see docs/AI.md)"
            .to_string()
    })?;
    let model = flags.model.or(file.model);
    let backend = match engine {
        Engine::Claude => Backend::Claude { model },
        Engine::Codex => Backend::Codex { model },
        Engine::Command => {
            let command = flags.command.or(file.command).filter(|command| !command.is_empty());
            Backend::Command { command: command.ok_or("the `command` engine needs `command = [\"program\", \"argument\", …]`")? }
        }
        Engine::Api => {
            let provider = provider.ok_or("the `api` engine needs `provider`: \"anthropic\" or \"openai-compatible\"")?;
            let base_url = flags.base_url.or(file.base_url);
            let key_env = flags.api_key_env.or(file.api_key_env);
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
            let present = |value: Option<String>| value.filter(|value| !value.trim().is_empty());
            let variable = key_env.as_deref().unwrap_or(default_env);
            let key = present(env(variable)).or(present(flags.api_key.or(file.api_key)));
            // A server the user points at, on this machine for instance, may want no key at all.
            let key_required = provider == Provider::Anthropic || base_url.is_none() || key_env.is_some();
            if key.is_none() && key_required {
                return Err(format!("no API key: write `api_key` in the configuration file, or set the environment variable {variable}"));
            }
            let base_url = base_url.unwrap_or_else(|| default_url.to_string()).trim_end_matches('/').to_string();
            if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
                return Err(format!("base_url must start with https:// or http://, not {base_url:?}"));
            }
            Backend::Api(Api { provider, model, base_url, key })
        }
    };
    Ok(Settings {
        backend,
        max_turns: flags.max_turns.or(file.max_turns).unwrap_or(DEFAULT_MAX_TURNS).clamp(1, 50),
        timeout: Duration::from_secs(flags.timeout_seconds.or(file.timeout_seconds).unwrap_or(DEFAULT_TIMEOUT_SECONDS).max(1)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn api(settings: &Settings) -> &Api {
        match &settings.backend {
            Backend::Api(api) => api,
            other => panic!("not the api engine: {other:?}"),
        }
    }

    #[test]
    fn nothing_set_means_off() {
        let error = resolve(Overrides::default(), Overrides::default(), &no_env).expect_err("off");
        assert!(error.contains("not set up"));
    }

    #[test]
    fn a_key_may_be_written_in_the_file_and_the_environment_wins() {
        let file = parse("[ai]\nprovider = \"anthropic\"\napi_key = \"from-file\"\n").expect("parses");
        let settings = resolve(file.clone(), Overrides::default(), &no_env).expect("resolves");
        assert_eq!(settings.engine(), Engine::Api);
        assert_eq!(api(&settings).model, DEFAULT_ANTHROPIC_MODEL);
        assert_eq!(api(&settings).base_url, "https://api.anthropic.com");
        assert_eq!(api(&settings).key.as_deref(), Some("from-file"));
        let env = |name: &str| (name == "ANTHROPIC_API_KEY").then(|| "from-env".to_string());
        assert_eq!(api(&resolve(file, Overrides::default(), &env).expect("resolves")).key.as_deref(), Some("from-env"));
    }

    #[test]
    fn a_missing_key_is_said_before_anything_is_sent() {
        let file = parse("[ai]\nprovider = \"openai\"\nmodel = \"m\"\n").expect("parses");
        assert!(resolve(file, Overrides::default(), &no_env).expect_err("no key").contains("OPENAI_API_KEY"));
    }

    #[test]
    fn a_flag_wins_over_the_file() {
        let file = parse("[ai]\nprovider = \"anthropic\"\nmodel = \"claude-haiku-5-5\"\napi_key = \"k\"\n").expect("parses");
        let flags = Overrides { model: Some("claude-sonnet-5-5".into()), ..Overrides::default() };
        assert_eq!(api(&resolve(file, flags, &no_env).expect("resolves")).model, "claude-sonnet-5-5");
    }

    #[test]
    fn a_local_server_needs_a_model_and_no_key() {
        let file =
            parse("[ai]\nengine = \"api\"\nprovider = \"openai-compatible\"\nbase_url = \"http://localhost:11434/v1/\"\n").expect("parses");
        assert!(resolve(file.clone(), Overrides::default(), &no_env).expect_err("no model").contains("no default model"));
        let flags = Overrides { model: Some("qwen3".into()), ..Overrides::default() };
        let settings = resolve(file, flags, &no_env).expect("resolves");
        assert_eq!(api(&settings).base_url, "http://localhost:11434/v1");
        assert_eq!(api(&settings).key, None);
    }

    #[test]
    fn the_other_engines_need_no_key() {
        let claude = resolve(parse("[ai]\nengine = \"claude\"\n").expect("parses"), Overrides::default(), &no_env).expect("resolves");
        assert_eq!(claude.backend, Backend::Claude { model: None });
        let codex =
            resolve(parse("[ai]\nengine = \"codex\"\nmodel = \"x\"\n").expect("parses"), Overrides::default(), &no_env).expect("resolves");
        assert_eq!(codex.backend, Backend::Codex { model: Some("x".into()) });
        assert!(resolve(parse("[ai]\nengine = \"command\"\n").expect("parses"), Overrides::default(), &no_env).is_err());
        let own = resolve(
            parse("[ai]\nengine = \"command\"\ncommand = [\"my-agent\", \"{prompt_file}\"]\n").expect("parses"),
            Overrides::default(),
            &no_env,
        );
        assert_eq!(own.expect("resolves").backend, Backend::Command { command: vec!["my-agent".into(), "{prompt_file}".into()] });
    }

    #[test]
    fn unknown_settings_are_refused_and_other_tables_ignored() {
        assert!(parse("[ai]\nengin = \"claude\"\n").is_err());
        assert_eq!(parse("[other]\nx = 1\n").expect("parses"), Overrides::default());
        assert_eq!(read_file(Path::new("/nonexistent/analyze-anything/config.toml")).expect("reads"), Overrides::default());
    }

    #[test]
    fn a_written_file_reads_back_and_is_private() {
        let folder = tempfile::tempdir().expect("a folder");
        let path = folder.path().join("deep").join("config.toml");
        let settings = Overrides {
            engine: Some(Engine::Api),
            provider: Some(Provider::OpenaiCompatible),
            model: Some("m".into()),
            api_key: Some("k".into()),
            ..Overrides::default()
        };
        write_file(&path, &settings).expect("writes");
        assert_eq!(read_file(&path).expect("reads"), settings);
        assert!(!readable_by_others(&path));
        std::fs::write(&path, "[ai]\nengine = \"claude\"\n[mine]\nx = 1\n").expect("writes");
        assert!(write_file(&path, &settings).expect_err("refuses").contains("by hand"));
    }
}
