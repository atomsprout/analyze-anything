//! `aa`: the command line for Analyze Anything. A thin shell over `aa-engine` and `aa-report`:
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
#[command(name = "aa", version, about = "Analyze any file or folder and write a report")]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
        /// A report.json written by `aa analyze`
        report: PathBuf,
        #[command(flatten)]
        output: Output,
    },
    /// Show one finding of a report in full: its text and every piece of evidence
    Explain {
        /// A report.json written by `aa analyze`
        report: PathBuf,
        /// The finding's id, or its first characters as the readable reports print them
        id: String,
        /// Language of the text
        #[arg(long, default_value = "en")]
        lang: LangArg,
    },
    /// Check that the files in an output folder are the ones the run wrote, unchanged
    Verify {
        /// A folder written by `aa analyze` or `aa render`
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
    /// Folder to write the report files into
    #[arg(short, long, default_value = "out")]
    out: PathBuf,
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
    // The files and the manifest that lets `aa verify` tell later whether they changed.
    for path in aa_app::export::write_folder(report, &output.out, &kinds, lang, &fonts)? {
        println!("{}", path.display());
    }
    Ok(())
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

fn run(cli: Cli) -> Result<u8, String> {
    let (report, output) = match cli.command {
        Command::Analyze { path, output, limits: limit_args, rules } => {
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
            (report, output)
        }
        Command::Inspect { path, limits } => return inspect(&path, &limits),
        Command::Selftest => return selftest::run(),
        Command::Render { report, output } => (load(&report)?, output),
        Command::Explain { report, id, lang } => return explain(&load(&report)?, &id, lang).map(|()| 0),
        Command::Verify { dir } => return verify(&dir),
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
    write_outputs(&report, &output)?;
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

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}
