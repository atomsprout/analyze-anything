//! `analyze-anything`: the command line for Analyze Anything. A thin shell over `aa-engine` and `aa-report`:
//! it reads arguments, shows progress on stderr and writes files. It holds no analysis of its own.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aa_app::export::{Kind, Lang};
use aa_core::{Location, Report, Severity};
use aa_engine::{Event, Limits, Options, ProgressSink, Registry};
use aa_export::manifest::{self, Status};
use clap::{Parser, Subcommand, ValueEnum};

mod selftest;

#[derive(Parser)]
#[command(
    name = "analyze-anything",
    version,
    about = "Analyze any file or folder and write a report",
    override_usage = "analyze-anything <PATH> [OPTIONS]\n       analyze-anything <COMMAND>",
    after_help = "Give a file or folder and it is analyzed: `analyze-anything App.ipa` writes the report into App.ipa.report.\nTo analyze something named like a command, write its path: `analyze-anything ./diff`."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Leave out the closing line that names this tool and its address in the reports written
    /// for people. Not listed in the help: the line is there unless someone minds it.
    #[arg(long, global = true, hide = true)]
    no_credit: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a file or folder and write the report
    Analyze {
        /// File or folder to analyze. It is only read, never run.
        path: PathBuf,
        #[command(flatten)]
        output: Output,
        #[command(flatten)]
        limits: LimitArgs,
        /// A file of YARA rules to match against every file, in addition to the built-in checks
        #[arg(long)]
        rules: Vec<PathBuf>,
        /// Also have the AI you set up explain the report (see `analyze-anything ai`)
        #[cfg(feature = "ai")]
        #[arg(long)]
        ai: bool,
        /// Do not, even when the configuration says to after every analysis
        #[cfg(feature = "ai")]
        #[arg(long, conflicts_with = "ai")]
        no_ai: bool,
    },
    /// Print the tree of files as JSON: what the input is and what is inside it, without analysis
    Inspect {
        /// File or folder to look into. It is only read, never run.
        path: PathBuf,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Check that this build works: analyze built-in samples and compare with known results
    Selftest,
    /// Write other formats from an existing report.json, without analyzing again
    Render {
        /// A report.json written by `analyze-anything analyze`
        report: PathBuf,
        #[command(flatten)]
        output: Output,
    },
    /// Show one finding of a report in full: its text and every piece of evidence
    Explain {
        /// A report.json written by `analyze-anything analyze`
        report: PathBuf,
        /// The finding's id, or its first characters as the readable reports print them
        id: String,
        /// Language of the text
        #[arg(long, default_value = "en")]
        lang: LangArg,
    },
    /// Check that the files in an output folder are the ones the run wrote, unchanged
    Verify {
        /// A folder written by `analyze-anything analyze` or `analyze-anything render`
        dir: PathBuf,
    },
    /// Compare two reports: findings and files added, removed and changed from the first to the second
    Diff {
        /// The earlier report.json
        before: PathBuf,
        /// The later report.json
        after: PathBuf,
        /// Print the comparison as JSON instead of text
        #[arg(long)]
        json: bool,
        /// Language of the text
        #[arg(long, default_value = "en")]
        lang: LangArg,
        /// Exit with code 3 when the reports differ
        #[arg(long)]
        fail_on_difference: bool,
    },
    /// Have a language model explain a report in plain words (optional; off until set up)
    ///
    /// The model is shown a brief of the report and may look things up in it; the analyzed files
    /// are never sent. Only statements that cite findings of the report are kept.
    #[cfg(feature = "ai")]
    Interpret(InterpretArgs),
    /// Choose who does the AI interpretation, or show what is set up
    #[cfg(feature = "ai")]
    Ai {
        #[command(subcommand)]
        choice: Option<AiChoice>,
    },
    /// Serve a report's read-only tools to an AI agent over standard input and output (MCP)
    #[cfg(feature = "ai")]
    Mcp {
        /// A report.json written by `analyze-anything analyze`
        report: PathBuf,
        /// Language of the text
        #[arg(long, default_value = "en")]
        lang: LangArg,
    },
}

#[cfg(feature = "ai")]
#[derive(clap::Args)]
struct InterpretArgs {
    /// A report.json written by `analyze-anything analyze`, or the folder it is in
    report: PathBuf,
    /// Folder to write ai.json and ai.md into [default: the report's folder]
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Language of the interpretation
    #[arg(long, default_value = "en")]
    lang: LangArg,
    #[command(flatten)]
    how: AiFlags,
    /// Print what the model would be shown first, and send nothing
    #[arg(long)]
    dry_run: bool,
}

/// Settings of the AI interpretation for this run, over those of the configuration file.
#[cfg(feature = "ai")]
#[derive(clap::Args, Default)]
struct AiFlags {
    /// Who runs the conversation with the model
    #[arg(long)]
    engine: Option<EngineArg>,
    /// The kind of model service, for the api engine
    #[arg(long)]
    provider: Option<ProviderArg>,
    /// The model to ask [default for anthropic: claude-opus-5-5]
    #[arg(long)]
    model: Option<String>,
    /// Address of the model service, for a gateway or a model server of your own
    #[arg(long)]
    base_url: Option<String>,
    /// Name of an environment variable that holds the API key
    #[arg(long)]
    api_key_env: Option<String>,
    /// Configuration file to read instead of ~/.analyze-anything/config.toml
    #[arg(long)]
    config: Option<PathBuf>,
}

#[cfg(feature = "ai")]
#[derive(Clone, Copy, ValueEnum)]
enum EngineArg {
    /// This program, with an API key
    Api,
    /// The Claude Code command line, with the account it is signed in to
    Claude,
    /// The Codex command line, with the account it is signed in to
    Codex,
    /// This program, with a model that Ollama runs on this machine
    Ollama,
    /// A command of your own, set in the configuration file
    Command,
}

#[cfg(feature = "ai")]
#[derive(Clone, Copy, ValueEnum)]
enum ProviderArg {
    /// Claude through Anthropic's API
    Anthropic,
    /// Any service that speaks OpenAI's chat-completions protocol
    OpenaiCompatible,
}

#[cfg(feature = "ai")]
#[derive(Subcommand)]
enum AiChoice {
    /// Talk to a model service directly, with an API key
    Api {
        /// The kind of service
        #[arg(long)]
        provider: ProviderArg,
        /// The model to ask [default for anthropic: claude-opus-5-5]
        #[arg(long)]
        model: Option<String>,
        /// Address of the service, for a gateway or a model server of your own
        #[arg(long)]
        base_url: Option<String>,
        /// Name of an environment variable that holds the API key, instead of keeping the key in the file
        #[arg(long)]
        api_key_env: Option<String>,
        /// Read the API key from standard input and keep it in the configuration file
        #[arg(long)]
        api_key_stdin: bool,
        #[command(flatten)]
        common: AiCommon,
    },
    /// Hand it to Claude Code (the `claude` command); no API key needed
    Claude {
        /// A model for Claude Code to use instead of its own choice
        #[arg(long)]
        model: Option<String>,
        #[command(flatten)]
        common: AiCommon,
    },
    /// Hand it to Codex (the `codex` command); no API key needed
    Codex {
        /// A model for Codex to use instead of its own choice
        #[arg(long)]
        model: Option<String>,
        #[command(flatten)]
        common: AiCommon,
    },
    /// Use a model that Ollama runs on this machine; no API key, and nothing leaves the machine
    Ollama {
        /// The model, as `ollama list` shows it
        #[arg(long)]
        model: String,
        /// Where Ollama listens [default: http://localhost:11434/v1]
        #[arg(long)]
        base_url: Option<String>,
        #[command(flatten)]
        common: AiCommon,
    },
    /// Hand it to a program of your own: the command and its arguments follow `--`
    Command {
        /// The program and its arguments; {prompt_file}, {mcp_config} and {report} are filled in
        #[arg(last = true, required = true)]
        command: Vec<String>,
        #[command(flatten)]
        common: AiCommon,
    },
    /// Turn the AI interpretation off again
    Off,
}

#[cfg(feature = "ai")]
#[derive(clap::Args)]
struct AiCommon {
    /// Interpret after every analysis, without `--ai`
    #[arg(long)]
    auto: bool,
}

#[derive(clap::Args)]
struct LimitArgs {
    /// Most files in the tree, unpacked ones included
    #[arg(long)]
    max_files: Option<u64>,
    /// How many containers deep to unpack
    #[arg(long)]
    max_depth: Option<u32>,
    /// Most bytes to unpack from containers in total
    #[arg(long)]
    max_unpacked_bytes: Option<u64>,
    /// Largest single entry to unpack from a container
    #[arg(long)]
    max_entry_bytes: Option<u64>,
    /// Seconds one analyzer may spend on one file before it is given up on
    #[arg(long)]
    analyzer_timeout: Option<u64>,
    /// Seconds unpacking one container may take before the rest is left unopened
    #[arg(long)]
    unpack_timeout: Option<u64>,
}

#[derive(clap::Args)]
struct Output {
    /// Folder to write the report files into [default: <name of the input>.report]
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Formats to write, comma separated
    #[arg(short, long, value_delimiter = ',', default_value = DEFAULT_FORMATS)]
    format: Vec<FormatArg>,
    /// Language of the readable formats
    #[arg(long, default_value = "en")]
    lang: LangArg,
    /// A font file for PDF text the built-in fonts cannot show (other scripts, emoji); repeatable
    #[arg(long)]
    font: Vec<PathBuf>,
    /// Exit with code 3 when a finding of this severity or higher exists
    #[arg(long)]
    fail_on: Option<SeverityArg>,
}

#[cfg(feature = "pdf")]
const DEFAULT_FORMATS: &str = "json,html,pdf,md,txt";
#[cfg(not(feature = "pdf"))]
const DEFAULT_FORMATS: &str = "json,html,md,txt";

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum FormatArg {
    Json,
    Md,
    Txt,
    Html,
    Pdf,
    Sarif,
    /// A CycloneDX software bill of materials
    Sbom,
}

#[derive(Clone, Copy, ValueEnum)]
enum LangArg {
    Zh,
    En,
}

/// Exit codes: 0 complete, 1 could not run (or `verify` found a difference), 2 ran but the
/// analysis is partial, 3 a finding reached the `--fail-on` severity (or `diff` found a
/// difference and was asked to say so).
const EXIT_FAILED: u8 = 1;
const EXIT_PARTIAL: u8 = 2;
const EXIT_FINDINGS: u8 = 3;

struct StderrProgress {
    /// Redraw one line in place only when a person is watching.
    live: bool,
}

impl ProgressSink for StderrProgress {
    fn event(&mut self, event: Event) {
        let mut err = std::io::stderr().lock();
        // Progress is a courtesy; a closed stderr must not stop the analysis.
        let _ = match event {
            Event::Reading { index, total, path } if self.live => write!(err, "\r\x1b[K[{index}/{total}] {path}"),
            Event::Unpacked { path, children } if self.live => write!(err, "\r\x1b[K{path}: {children}"),
            Event::Analyzing { artifacts } if self.live => write!(err, "\r\x1b[K… {artifacts}"),
            Event::Analyzed { index, total, path } if self.live => write!(err, "\r\x1b[K… [{index}/{total}] {path}"),
            Event::Warning { code, path } => {
                let clear = if self.live { "\r\x1b[K" } else { "" };
                writeln!(err, "{clear}warning: {code}{}", path.map(|p| format!(": {p}")).unwrap_or_default())
            }
            Event::Finished if self.live => write!(err, "\r\x1b[K"),
            _ => Ok(()),
        };
    }
}

fn write_outputs(report: &Report, output: &Output) -> Result<(), String> {
    let lang = match output.lang {
        LangArg::Zh => Lang::Zh,
        LangArg::En => Lang::En,
    };
    let kinds: Vec<Kind> = output
        .format
        .iter()
        .map(|format| match format {
            FormatArg::Json => Kind::Json,
            FormatArg::Md => Kind::Markdown,
            FormatArg::Txt => Kind::Text,
            FormatArg::Html => Kind::Html,
            FormatArg::Pdf => Kind::Pdf,
            FormatArg::Sarif => Kind::Sarif,
            FormatArg::Sbom => Kind::Sbom,
        })
        .collect();
    let mut fonts = Vec::new();
    for path in &output.font {
        fonts.push(std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?);
    }
    // The files and the manifest that lets `analyze-anything verify` tell later whether they changed.
    let out = out_dir(report, output);
    for path in aa_app::export::write_folder(report, &out, &kinds, lang, &fonts)? {
        println!("{}", path.display());
    }
    Ok(())
}

/// Where the report files go: the folder that was asked for, else one named after the input.
fn out_dir(report: &Report, output: &Output) -> PathBuf {
    match &output.out {
        Some(out) => out.clone(),
        None => {
            // Only the last part of the name: an input name never chooses a folder elsewhere.
            let name = Path::new(&report.input.name).file_name().map(|name| name.to_string_lossy().into_owned());
            let name = name.filter(|name| !name.is_empty() && name != "." && name != "..").unwrap_or_else(|| "input".to_string());
            PathBuf::from(format!("{name}.report"))
        }
    }
}

/// The arguments as given, with `analyze` put in when the first one is not a command: a bare
/// path means "analyze this".
fn arguments() -> Vec<std::ffi::OsString> {
    use clap::CommandFactory;
    let mut arguments: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let Some(first) = arguments.get(1).map(|first| first.to_string_lossy().into_owned()) else { return arguments };
    let command = Cli::command();
    let known = command.get_subcommands().any(|sub| sub.get_name() == first) || first == "help";
    if !known && !first.starts_with('-') {
        arguments.insert(1, "analyze".into());
    }
    arguments
}

fn limits(args: &LimitArgs) -> Limits {
    let defaults = Limits::default();
    Limits {
        max_files: args.max_files.unwrap_or(defaults.max_files),
        max_depth: args.max_depth.unwrap_or(defaults.max_depth),
        max_unpacked_bytes: args.max_unpacked_bytes.unwrap_or(defaults.max_unpacked_bytes),
        max_entry_bytes: args.max_entry_bytes.unwrap_or(defaults.max_entry_bytes),
        analyzer_seconds: args.analyzer_timeout.unwrap_or(defaults.analyzer_seconds),
        unpack_seconds: args.unpack_timeout.unwrap_or(defaults.unpack_seconds),
        ..defaults
    }
}

/// The tree as plain JSON on standard output, for scripts and agents.
fn inspect(path: &Path, args: &LimitArgs) -> Result<u8, String> {
    let options = Options { limits: limits(args), ..Options::default() };
    let report =
        aa_engine::analyze_with(&Registry::unpack_only(), path, &options, &mut aa_engine::NoProgress).map_err(|e| e.to_string())?;
    let artifacts: Vec<serde_json::Value> = report
        .artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "path": a.path,
                "parent": a.parent,
                "size": a.size,
                "mime": a.detected.as_ref().map(|d| d.mime.as_str()),
                "kind": a.kind,
                "unpacked_by": a.unpacked_by,
                "sha256": a.digests.as_ref().map(|d| d.sha256.as_str()),
            })
        })
        .collect();
    let tree = serde_json::json!({ "input": report.input, "coverage": report.coverage, "artifacts": artifacts, "limitations": report.limitations });
    println!("{}", serde_json::to_string_pretty(&tree).map_err(|e| e.to_string())?);
    Ok(if partial(&report) { EXIT_PARTIAL } else { 0 })
}

fn partial(report: &Report) -> bool {
    let coverage = &report.coverage;
    coverage.truncated || coverage.content_lost > 0 || coverage.artifacts_analyzed < coverage.artifacts_total
}

fn load(path: &Path) -> Result<Report, String> {
    aa_app::export::load(path)
}

fn explain(report: &Report, id: &str, lang: LangArg) -> Result<(), String> {
    let matches: Vec<_> = report.findings.iter().filter(|f| f.id.starts_with(id)).collect();
    let finding = match matches.as_slice() {
        [one] => *one,
        [] => return Err(format!("no finding has an id starting with {id}")),
        many => return Err(format!("{} findings have an id starting with {id}; give more characters", many.len())),
    };
    let rule = report.rules.get(&finding.rule);
    let (title, text) = match (rule, lang) {
        (Some(rule), LangArg::Zh) => (rule.title_zh.as_str(), aa_core::fill(&rule.text_zh, &finding.params)),
        (Some(rule), LangArg::En) => (rule.title_en.as_str(), aa_core::fill(&rule.text_en, &finding.params)),
        (None, _) => (finding.rule.as_str(), String::new()),
    };
    println!("{title}\n{text}\n");
    println!("id:         {}", finding.id);
    println!("rule:       {}", finding.rule);
    println!("section:    {}", serde_json::to_string(&finding.section).unwrap_or_default().trim_matches('"'));
    println!("severity:   {}", serde_json::to_string(&finding.severity).unwrap_or_default().trim_matches('"'));
    println!("confidence: {}", serde_json::to_string(&finding.confidence).unwrap_or_default().trim_matches('"'));
    if !finding.references.is_empty() {
        println!("references: {}", finding.references.join(", "));
    }
    for (name, value) in &finding.params {
        println!("param {name} = {value}");
    }
    for evidence in &finding.evidence {
        let place = match &evidence.location {
            Location::Bytes { offset, length } => format!("bytes {offset}..{}", offset.saturating_add(*length)),
            Location::Field(field) => format!("field {field}"),
            Location::Whole => "whole file".to_string(),
        };
        println!("\nevidence: {}", evidence.artifact);
        println!("  sha256: {}", evidence.sha256.as_deref().unwrap_or("unknown"));
        println!("  where:  {place}");
        println!("  value:  {}", evidence.value);
    }
    Ok(())
}

fn verify(dir: &Path) -> Result<u8, String> {
    let check = manifest::verify(dir).map_err(|e| e.to_string())?;
    for (name, status) in &check.files {
        let word = match status {
            Status::Unchanged => "ok       ",
            Status::Changed => "CHANGED  ",
            Status::Missing => "MISSING  ",
            Status::Unlisted => "UNLISTED ",
        };
        println!("{word}{name}");
    }
    Ok(if check.intact() { 0 } else { EXIT_FAILED })
}

#[cfg(feature = "ai")]
mod ai {
    //! The commands of the optional AI interpretation.

    use super::*;
    use aa_interpret::config::{self, Engine, Overrides};

    fn config_path(named: &Option<PathBuf>) -> Result<PathBuf, String> {
        match named {
            // A file that was named must be there; the usual one may be absent.
            Some(path) if !path.is_file() => Err(format!("cannot read {}: no such file", path.display())),
            Some(path) => Ok(path.clone()),
            None => config::default_path().ok_or_else(|| "cannot tell where the home folder is; pass --config".to_string()),
        }
    }

    fn language(lang: LangArg) -> aa_interpret::Language {
        match lang {
            LangArg::Zh => aa_interpret::Language::Zh,
            LangArg::En => aa_interpret::Language::En,
        }
    }

    fn provider(provider: ProviderArg) -> aa_interpret::Provider {
        match provider {
            ProviderArg::Anthropic => aa_interpret::Provider::Anthropic,
            ProviderArg::OpenaiCompatible => aa_interpret::Provider::OpenaiCompatible,
        }
    }

    /// True when the configuration says to interpret after every analysis.
    pub fn automatic() -> bool {
        config::default_path().and_then(|path| config::read_file(&path).ok()).and_then(|file| file.auto).unwrap_or(false)
    }

    fn settings(flags: &AiFlags) -> Result<aa_interpret::Settings, String> {
        let path = config_path(&flags.config)?;
        let file = config::read_file(&path)?;
        if file.api_key.is_some() && config::readable_by_others(&path) {
            eprintln!("warning: {} holds an API key and other users of this machine can read it; `chmod 600` it", path.display());
        }
        let overrides = Overrides {
            engine: flags.engine.map(|engine| match engine {
                EngineArg::Api => Engine::Api,
                EngineArg::Claude => Engine::Claude,
                EngineArg::Codex => Engine::Codex,
                EngineArg::Ollama => Engine::Ollama,
                EngineArg::Command => Engine::Command,
            }),
            provider: flags.provider.map(provider),
            model: flags.model.clone(),
            base_url: flags.base_url.clone(),
            api_key_env: flags.api_key_env.clone(),
            ..Overrides::default()
        };
        config::resolve(file, overrides, &|name| std::env::var(name).ok())
    }

    /// Interprets `report`, which is the file at `path`, and writes ai.json and ai.md into `dir`.
    pub fn write(report: &Report, path: &Path, dir: &Path, lang: LangArg, flags: &AiFlags) -> Result<(), String> {
        let settings = settings(flags)?;
        let live = std::io::stderr().is_terminal();
        eprintln!("asking {} …", settings.describe());
        let mut on_step = |step: &str| {
            let shown: String = step.chars().take(100).collect();
            if live {
                eprint!("\r\x1b[K  {shown}");
            }
        };
        let program = std::env::current_exe().map_err(|e| format!("cannot tell where this program is: {e}"))?;
        // A program that is handed the work starts elsewhere; it needs the whole path.
        let report_path = std::fs::canonicalize(path).map_err(|e| format!("cannot find {}: {e}", path.display()))?;
        let context = aa_interpret::Context {
            report_path: &report_path,
            program: &program,
            transport: &aa_interpret::Net,
            runner: &aa_interpret::Processes,
            on_step: &mut on_step,
        };
        let result = aa_interpret::interpret(report, &settings, language(lang), context);
        if live {
            eprint!("\r\x1b[K");
        }
        let result = result?;
        let text = aa_interpret::markdown(&result);
        // In a folder an analysis wrote, the new files are listed so that `verify` still accepts it.
        let files = [(aa_interpret::JSON_NAME, aa_interpret::json(&result)), (aa_interpret::MARKDOWN_NAME, text.into_bytes())];
        for path in aa_app::export::add_files(dir, &files)? {
            println!("{}", path.display());
        }
        Ok(())
    }

    pub fn interpret(args: InterpretArgs) -> Result<u8, String> {
        let path = if args.report.is_dir() { args.report.join("report.json") } else { args.report.clone() };
        let report = load(&path)?;
        if args.dry_run {
            let (instructions, brief) = aa_interpret::preview(&report, language(args.lang));
            println!("{instructions}\n\n{brief}");
            return Ok(0);
        }
        let dir = match &args.out {
            Some(dir) => dir.clone(),
            None => path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf(),
        };
        write(&report, &path, &dir, args.lang, &args.how)?;
        // The interpretation is what was asked for: show it.
        let text = std::fs::read_to_string(dir.join(aa_interpret::MARKDOWN_NAME)).unwrap_or_default();
        print!("\n{text}");
        Ok(0)
    }

    pub fn serve(report: &Path, lang: LangArg) -> Result<u8, String> {
        let report = load(report)?;
        aa_interpret::mcp::serve(&report, language(lang), std::io::stdin().lock(), std::io::stdout().lock()).map_err(|e| e.to_string())?;
        Ok(0)
    }

    /// Shows or changes who does the interpretation.
    pub fn choose(choice: Option<AiChoice>) -> Result<u8, String> {
        let path = config_path(&None)?;
        let Some(choice) = choice else {
            let file = config::read_file(&path)?;
            match config::resolve(file.clone(), Overrides::default(), &|name| std::env::var(name).ok()) {
                Ok(settings) => {
                    println!("AI interpretation: {} (engine: {})", settings.describe(), settings.engine().id());
                    println!("after every analysis: {}", if file.auto == Some(true) { "yes" } else { "no, only with --ai" });
                }
                Err(problem) if file == Overrides::default() => println!("AI interpretation: off.\n{problem}"),
                Err(problem) => println!("AI interpretation: set up, but it cannot run: {problem}"),
            }
            println!("configuration file: {}", path.display());
            return Ok(0);
        };
        let auto = |common: &AiCommon| common.auto.then_some(true);
        let settings = match choice {
            AiChoice::Off => {
                if path.is_file() {
                    config::write_file(&path, &Overrides::default())?;
                }
                println!("AI interpretation is off.");
                return Ok(0);
            }
            AiChoice::Claude { model, common } => {
                Overrides { engine: Some(Engine::Claude), model, auto: auto(&common), ..Overrides::default() }
            }
            AiChoice::Codex { model, common } => {
                Overrides { engine: Some(Engine::Codex), model, auto: auto(&common), ..Overrides::default() }
            }
            AiChoice::Ollama { model, base_url, common } => {
                Overrides { engine: Some(Engine::Ollama), model: Some(model), base_url, auto: auto(&common), ..Overrides::default() }
            }
            AiChoice::Command { command, common } => {
                Overrides { engine: Some(Engine::Command), command: Some(command), auto: auto(&common), ..Overrides::default() }
            }
            AiChoice::Api { provider: kind, model, base_url, api_key_env, api_key_stdin, common } => {
                let api_key = if api_key_stdin {
                    if std::io::stdin().is_terminal() {
                        eprint!("API key (it is kept in {}): ", path.display());
                    }
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).map_err(|e| format!("cannot read the key: {e}"))?;
                    let key = line.trim().to_string();
                    if key.is_empty() {
                        return Err("no key was given".into());
                    }
                    Some(key)
                } else {
                    None
                };
                Overrides {
                    engine: Some(Engine::Api),
                    provider: Some(provider(kind)),
                    model,
                    base_url,
                    api_key,
                    api_key_env,
                    auto: auto(&common),
                    ..Overrides::default()
                }
            }
        };
        // Say now what would stop it later, a missing key or model for instance; a key may still
        // be on its way into the environment, so this is a warning and the choice is kept.
        let check = config::resolve(settings.clone(), Overrides::default(), &|name| std::env::var(name).ok());
        config::write_file(&path, &settings)?;
        println!("{}", path.display());
        match check {
            Ok(resolved) => println!("AI interpretation: {}. Use it with `analyze-anything <file> --ai`.", resolved.describe()),
            Err(problem) => println!("saved, but it cannot run yet: {problem}"),
        }
        Ok(0)
    }
}

fn run(cli: Cli) -> Result<u8, String> {
    if cli.no_credit {
        aa_app::export::set_credit(false);
    }
    let (report, mut output, wants_ai) = match cli.command {
        Command::Analyze {
            path,
            output,
            limits: limit_args,
            rules,
            #[cfg(feature = "ai")]
            ai,
            #[cfg(feature = "ai")]
            no_ai,
        } => {
            let mut progress = StderrProgress { live: std::io::stderr().is_terminal() };
            let options = Options { limits: limits(&limit_args), ..Options::default() };
            // A run that was killed could not remove what it had unpacked; do it now.
            aa_engine::sweep_stale(None);
            let mut registry = Registry::standard();
            for file in &rules {
                let source = std::fs::read_to_string(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
                let analyzer = aa_content::yara::analyzer(&source).map_err(|e| format!("{}: {e}", file.display()))?;
                // After the built-in content checks, before the analyzers that summarise.
                registry.analyzers.insert(1, analyzer.into());
            }
            let report = aa_engine::analyze_with(&registry, &path, &options, &mut progress).map_err(|e| e.to_string())?;
            #[cfg(feature = "ai")]
            let wants_ai = if ai {
                Some(true)
            } else if !no_ai && ai::automatic() {
                Some(false)
            } else {
                None
            };
            #[cfg(not(feature = "ai"))]
            let wants_ai: Option<bool> = None;
            (report, output, wants_ai)
        }
        Command::Inspect { path, limits } => return inspect(&path, &limits),
        Command::Selftest => return selftest::run(),
        Command::Render { report, output } => (load(&report)?, output, None),
        Command::Explain { report, id, lang } => return explain(&load(&report)?, &id, lang).map(|()| 0),
        Command::Verify { dir } => return verify(&dir),
        #[cfg(feature = "ai")]
        Command::Interpret(args) => return ai::interpret(args),
        #[cfg(feature = "ai")]
        Command::Ai { choice } => return ai::choose(choice),
        #[cfg(feature = "ai")]
        Command::Mcp { report, lang } => return ai::serve(&report, lang),
        Command::Diff { before, after, json, lang, fail_on_difference } => {
            let difference = aa_export::diff::diff(&load(&before)?, &load(&after)?);
            if json {
                println!("{}", serde_json::to_string_pretty(&difference).map_err(|e| e.to_string())?);
            } else {
                let language = match lang {
                    LangArg::Zh => aa_export::diff::Language::Zh,
                    LangArg::En => aa_export::diff::Language::En,
                };
                print!("{}", aa_export::diff::text(&difference, language));
            }
            return Ok(if fail_on_difference && !difference.is_empty() { EXIT_FINDINGS } else { 0 });
        }
    };
    // The interpretation is made from report.json, so that file is written whatever was asked.
    if wants_ai.is_some() && !output.format.contains(&FormatArg::Json) {
        output.format.push(FormatArg::Json);
    }
    write_outputs(&report, &output)?;
    #[cfg(feature = "ai")]
    if let Some(asked) = wants_ai {
        let dir = out_dir(&report, &output);
        if let Err(problem) = ai::write(&report, &dir.join("report.json"), &dir, output.lang, &AiFlags::default()) {
            // The report is written and stands on its own. Asked for with --ai, a failure is
            // the command's failure; done by the configuration's standing order, it is a warning.
            if asked {
                return Err(format!("the report is written, but the AI interpretation failed: {problem}"));
            }
            eprintln!("warning: the AI interpretation failed: {problem}");
        }
    }
    #[cfg(not(feature = "ai"))]
    let _ = wants_ai;
    let threshold = output.fail_on.map(|severity| match severity {
        SeverityArg::Low => Severity::Low,
        SeverityArg::Medium => Severity::Medium,
        SeverityArg::High => Severity::High,
    });
    if let Some(threshold) = threshold
        && report.findings.iter().any(|f| f.severity >= threshold)
    {
        return Ok(EXIT_FINDINGS);
    }
    Ok(if partial(&report) { EXIT_PARTIAL } else { 0 })
}

/// Ends quietly when whoever reads the output has stopped reading (`analyze-anything … | head`):
/// printing to a closed pipe is the end of the job, not a crash to report.
fn end_quietly_on_a_closed_pipe() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let payload = panic.payload();
        let text = payload.downcast_ref::<String>().map(String::as_str).or_else(|| payload.downcast_ref::<&str>().copied());
        let closed = text.is_some_and(|text| text.starts_with("failed printing to std") && text.contains("Broken pipe"));
        if closed {
            std::process::exit(0);
        }
        report(panic);
    }));
}

fn main() -> ExitCode {
    end_quietly_on_a_closed_pipe();
    match run(Cli::parse_from(arguments())) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}
