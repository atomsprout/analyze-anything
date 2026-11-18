//! `aa`: the command line for Analyze Anything. A thin shell over `aa-engine` and `aa-report`:
//! it reads arguments, shows progress on stderr and writes files. It holds no analysis of its own.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aa_core::Report;
use aa_engine::{Event, Options, ProgressSink};
use aa_report::{Format, Lang};
use clap::{Parser, Subcommand, ValueEnum};

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
    },
    /// Write other formats from an existing report.json, without analyzing again
    Render {
        /// A report.json written by `aa analyze`
        report: PathBuf,
        #[command(flatten)]
        output: Output,
    },
}

#[derive(clap::Args)]
struct Output {
    /// Folder to write the report files into
    #[arg(short, long, default_value = "out")]
    out: PathBuf,
    /// Formats to write, comma separated
    #[arg(short, long, value_delimiter = ',', default_value = "json,md")]
    format: Vec<FormatArg>,
    /// Language of the readable formats
    #[arg(long, default_value = "zh")]
    lang: LangArg,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum FormatArg {
    Json,
    Md,
    Txt,
}

#[derive(Clone, Copy, ValueEnum)]
enum LangArg {
    Zh,
    En,
}

/// Exit codes: 0 complete, 1 could not run, 2 ran but the analysis is partial.
const EXIT_FAILED: u8 = 1;
const EXIT_PARTIAL: u8 = 2;

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
    std::fs::create_dir_all(&output.out).map_err(|e| format!("cannot create {}: {e}", output.out.display()))?;
    let lang = match output.lang {
        LangArg::Zh => Lang::Zh,
        LangArg::En => Lang::En,
    };
    let mut done: Vec<FormatArg> = Vec::new();
    for format in &output.format {
        if done.contains(format) {
            continue;
        }
        done.push(*format);
        let format = match format {
            FormatArg::Json => Format::Json,
            FormatArg::Md => Format::Markdown,
            FormatArg::Txt => Format::Text,
        };
        let bytes = aa_report::render(report, format, lang).map_err(|e| e.to_string())?;
        let path = output.out.join(format!("report.{}", format.extension()));
        std::fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        println!("{}", path.display());
    }
    Ok(())
}

fn load(path: &Path) -> Result<Report, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let report: Report = serde_json::from_slice(&bytes).map_err(|e| format!("{} is not a report: {e}", path.display()))?;
    if report.schema_version != aa_core::SCHEMA_VERSION {
        return Err(format!(
            "{} uses report layout {}, this aa reads layout {}",
            path.display(),
            report.schema_version,
            aa_core::SCHEMA_VERSION
        ));
    }
    Ok(report)
}

fn run(cli: Cli) -> Result<u8, String> {
    let (report, output) = match cli.command {
        Command::Analyze { path, output } => {
            let mut progress = StderrProgress { live: std::io::stderr().is_terminal() };
            let report = aa_engine::analyze(&path, &Options::default(), &mut progress).map_err(|e| e.to_string())?;
            (report, output)
        }
        Command::Render { report, output } => (load(&report)?, output),
    };
    write_outputs(&report, &output)?;
    let partial = report.coverage.truncated || report.coverage.artifacts_analyzed < report.coverage.artifacts_total;
    Ok(if partial { EXIT_PARTIAL } else { 0 })
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
