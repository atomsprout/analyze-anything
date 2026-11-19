//! The engines that hand the work to another program: Claude Code, Codex, or a command of the
//! user's own.
//!
//! The other program gets the instructions and the brief, and reaches the report through this
//! program's tool server (`analyze-anything mcp <report.json>`), which only answers read-only
//! questions. What it prints comes back here and is checked like any model's answer.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::Language;
use crate::config::Backend;
use crate::tools::specs;

/// Name of the tool server as the other program knows it.
const SERVER: &str = "report";

/// What a finished program left behind.
pub struct Finished {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Something that can run a program to its end.
pub trait Runner {
    fn run(&self, program: &str, arguments: &[String], input: &str, folder: &Path, timeout: Duration) -> Result<Finished, String>;
}

/// What the delegate needs to know about the report it is asked about.
pub struct Job<'a> {
    /// This program, to start as the tool server.
    pub program: &'a Path,
    /// The report on disk.
    pub report: &'a Path,
    pub language: Language,
    pub instructions: &'a str,
    pub brief: &'a str,
    pub timeout: Duration,
}

pub struct Outcome {
    pub text: String,
    /// The model that answered, when the program says.
    pub model: Option<String>,
}

fn server_arguments(job: &Job) -> Vec<String> {
    let language = match job.language {
        Language::En => "en",
        Language::Zh => "zh",
    };
    vec!["mcp".to_string(), job.report.display().to_string(), "--lang".to_string(), language.to_string()]
}

/// Hands the job to `backend`'s program. `scratch` is an empty folder for the files the program
/// is given; the program is started in it, away from any project's own instructions.
pub fn run(backend: &Backend, job: &Job, runner: &dyn Runner, scratch: &Path) -> Result<Outcome, String> {
    let write = |name: &str, text: &str| -> Result<PathBuf, String> {
        let path = scratch.join(name);
        std::fs::write(&path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        Ok(path)
    };
    let how = format!(
        "Use the tools of the `{SERVER}` server (list_findings, get_finding, list_files) to look things up in the report. \
Use no other tool, read no file and run no command: everything you may use is in that report."
    );
    let server = json!({ "mcpServers": { SERVER: { "command": job.program.display().to_string(), "args": server_arguments(job) } } });
    let servers = write("mcp.json", &server.to_string())?;
    match backend {
        Backend::Api(_) => Err("the api engine is not a delegate".into()),
        Backend::Claude { model } => {
            let allowed: Vec<String> = specs().iter().map(|spec| format!("mcp__{SERVER}__{}", spec.name)).collect();
            let mut arguments: Vec<String> = [
                "--print",
                "--output-format",
                "json",
                // No built-in tool at all, only the report's; and nothing from the user's other servers.
                "--tools",
                "",
                "--strict-mcp-config",
                "--permission-mode",
                "dontAsk",
                "--no-session-persistence",
            ]
            .map(str::to_string)
            .to_vec();
            arguments.extend(["--mcp-config".to_string(), servers.display().to_string()]);
            arguments.extend(["--allowedTools".to_string(), allowed.join(",")]);
            arguments.extend(["--system-prompt".to_string(), format!("{}\n\n{how}", job.instructions)]);
            if let Some(model) = model {
                arguments.extend(["--model".to_string(), model.clone()]);
            }
            let finished = started(runner, "claude", &arguments, job.brief, scratch, job.timeout, "Claude Code")?;
            let reply: Value = serde_json::from_str(finished.stdout.trim()).map_err(|_| said("claude", &finished))?;
            let text = reply.get("result").and_then(Value::as_str).unwrap_or_default().to_string();
            if reply.get("is_error").and_then(Value::as_bool) == Some(true) || !finished.success {
                return Err(format!("claude did not finish: {}", if text.is_empty() { said("claude", &finished) } else { text }));
            }
            let model = reply.get("modelUsage").and_then(Value::as_object).and_then(|models| models.keys().next().cloned());
            Ok(Outcome { text, model })
        }
        Backend::Codex { model } => {
            let last = scratch.join("answer.txt");
            let setting = |key: &str, value: Value| ["-c".to_string(), format!("mcp_servers.{SERVER}.{key}={value}")];
            let mut arguments: Vec<String> =
                ["exec", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only"].map(str::to_string).to_vec();
            arguments.extend(["--output-last-message".to_string(), last.display().to_string()]);
            arguments.extend(setting("command", json!(job.program.display().to_string())));
            arguments.extend(setting("args", json!(server_arguments(job))));
            // The server's tools only read; without this a run with nobody to ask would stall.
            arguments.extend(setting("default_tools_approval_mode", json!("approve")));
            if let Some(model) = model {
                arguments.extend(["--model".to_string(), model.clone()]);
            }
            arguments.push("-".to_string());
            let prompt = format!("{}\n\n{how}\n\n{}", job.instructions, job.brief);
            let finished = started(runner, "codex", &arguments, &prompt, scratch, job.timeout, "Codex")?;
            let text = std::fs::read_to_string(&last).unwrap_or_default();
            if !finished.success || text.trim().is_empty() {
                return Err(format!("codex did not finish: {}", said("codex", &finished)));
            }
            Ok(Outcome { text, model: model.clone() })
        }
        Backend::Command { command } => {
            let prompt = format!("{}\n\n{how}\n\n{}", job.instructions, job.brief);
            let prompt_file = write("prompt.txt", &prompt)?;
            let fill = |word: &String| {
                word.replace("{prompt_file}", &prompt_file.display().to_string())
                    .replace("{mcp_config}", &servers.display().to_string())
                    .replace("{report}", &job.report.display().to_string())
            };
            let program = command.first().ok_or("the command is empty")?;
            let arguments: Vec<String> = command.iter().skip(1).map(fill).collect();
            let finished = started(runner, program, &arguments, &prompt, scratch, job.timeout, program)?;
            if !finished.success || finished.stdout.trim().is_empty() {
                return Err(format!("{program} did not finish: {}", said(program, &finished)));
            }
            Ok(Outcome { text: finished.stdout, model: None })
        }
    }
}

fn started(
    runner: &dyn Runner,
    program: &str,
    arguments: &[String],
    input: &str,
    folder: &Path,
    timeout: Duration,
    name: &str,
) -> Result<Finished, String> {
    runner.run(program, arguments, input, folder, timeout).map_err(|error| format!("cannot run {name} (the `{program}` command): {error}"))
}

/// The end of what a program printed, for an error message.
fn said(program: &str, finished: &Finished) -> String {
    let text = if finished.stderr.trim().is_empty() { &finished.stdout } else { &finished.stderr };
    let tail: Vec<&str> = text.trim().lines().rev().take(6).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    if tail.is_empty() { format!("{program} printed nothing") } else { tail.join("\n") }
}

/// Runs programs for real.
pub struct Processes;

impl Runner for Processes {
    fn run(&self, program: &str, arguments: &[String], input: &str, folder: &Path, timeout: Duration) -> Result<Finished, String> {
        let mut child = Command::new(program)
            .args(arguments)
            .current_dir(folder)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    "it is not installed, or not on PATH".to_string()
                } else {
                    error.to_string()
                }
            })?;
        // Feed and drain on threads of their own: a program that fills one pipe while we wait
        // on another would otherwise stop for good.
        let mut stdin = child.stdin.take();
        let input = input.to_string();
        let feeder = std::thread::spawn(move || {
            if let Some(stdin) = stdin.as_mut() {
                let _ = stdin.write_all(input.as_bytes());
            }
        });
        let drain = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut text = Vec::new();
                if let Some(mut pipe) = pipe {
                    let _ = pipe.read_to_end(&mut text);
                }
                String::from_utf8_lossy(&text).into_owned()
            })
        };
        let stdout = drain(child.stdout.take().map(|pipe| Box::new(pipe) as Box<dyn Read + Send>));
        let stderr = drain(child.stderr.take().map(|pipe| Box::new(pipe) as Box<dyn Read + Send>));
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("it did not finish in {} seconds and was stopped", timeout.as_secs()));
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let _ = feeder.join();
        Ok(Finished { success: status.success(), stdout: stdout.join().unwrap_or_default(), stderr: stderr.join().unwrap_or_default() })
    }
}
