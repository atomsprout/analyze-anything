//! The disassemblers the deep level can ask, and how each is run.
//!
//! Each is given one program file and a request, runs its own analysis without a person at it,
//! then runs a script of ours (in `scripts/`) that writes the answer as JSON. The two scripts
//! answer in the same shape, so everything after this file is the same for both tools.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const GHIDRA_SCRIPT: &str = include_str!("../scripts/AaFacts.java");
const HOPPER_SCRIPT: &str = include_str!("../scripts/aa_facts_hopper.py");

/// A disassembler found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tool {
    /// Ghidra, through `support/analyzeHeadless` of its folder.
    Ghidra { headless: PathBuf },
    /// Hopper, through the `hopper` launcher inside the app.
    Hopper { launcher: PathBuf },
}

impl Tool {
    pub fn id(&self) -> &'static str {
        match self {
            Tool::Ghidra { .. } => "ghidra",
            Tool::Hopper { .. } => "hopper",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Tool::Ghidra { .. } => "Ghidra",
            Tool::Hopper { .. } => "Hopper",
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            Tool::Ghidra { headless } => headless,
            Tool::Hopper { launcher } => launcher,
        }
    }
}

/// What kind of program file is handed over; Hopper has to be told, Ghidra finds out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    MachO,
    Elf,
    Pe,
}

/// What the tool is asked about one program file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Request {
    /// Names of functions, as their headers write them (`dlopen`, `CreateProcessW`).
    pub apis: Vec<String>,
    /// Texts to look for among the program's strings.
    pub strings: Vec<String>,
}

/// One function of the program that uses something.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct User {
    /// The function's name; one the tool made up when the program carries none.
    pub function: String,
    /// Where the function starts, as an address in the loaded program.
    pub address: u64,
    /// The address of the instruction that does the using.
    pub at: u64,
    /// Where that instruction is in the file that was handed over, when the tool can tell.
    pub offset: Option<u64>,
}

/// The functions that use one thing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Use {
    /// The function's name for an API; absent for a string.
    #[serde(default)]
    pub name: String,
    /// The text for a string; absent for an API.
    #[serde(default)]
    pub value: String,
    /// How many functions use it; `users` may list fewer.
    pub total: u64,
    pub users: Vec<User>,
}

/// What the tool read out of one program file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Facts {
    pub tool: String,
    pub version: String,
    /// The processor the tool took the code to be for, in its own words.
    pub language: String,
    /// Functions with a body in the file, not counting the stubs that only jump to an import.
    pub functions: u64,
    pub apis: Vec<Use>,
    pub strings: Vec<Use>,
}

/// Something that can ask a tool about a program file.
pub trait Asker: Send + Sync {
    /// Has `tool` analyze the program at `program` and answer `request`. `work` is an empty
    /// folder for whatever the tool and the script need to write.
    fn ask(&self, tool: &Tool, program: &Path, format: Format, request: &Request, work: &Path, timeout: Duration) -> Result<Facts, String>;
}

/// Runs the tools for real.
pub struct Programs;

impl Asker for Programs {
    fn ask(&self, tool: &Tool, program: &Path, format: Format, request: &Request, work: &Path, timeout: Duration) -> Result<Facts, String> {
        let write = |name: &str, text: &str| -> Result<PathBuf, String> {
            let path = work.join(name);
            std::fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            Ok(path)
        };
        let request_file = write("request.json", &serde_json::to_string(request).map_err(|e| e.to_string())?)?;
        let answer = work.join("facts.json");
        let said = match tool {
            Tool::Ghidra { headless } => {
                write("AaFacts.java", GHIDRA_SCRIPT)?;
                let project = work.join("project");
                std::fs::create_dir_all(&project).map_err(|e| format!("cannot create {}: {e}", project.display()))?;
                let mut command = Command::new(headless);
                command
                    .arg(&project)
                    .arg("aa")
                    .arg("-import")
                    .arg(program)
                    .arg("-scriptPath")
                    .arg(work)
                    .arg("-postScript")
                    .arg("AaFacts.java")
                    .arg(&request_file)
                    .arg(&answer)
                    .arg("-deleteProject")
                    .arg("-analysisTimeoutPerFile")
                    .arg(timeout.as_secs().max(1).to_string());
                // Ghidra's own limit ends the analysis; a little more is allowed for starting
                // up, importing and the script.
                run(command, work, timeout + Duration::from_secs(120), &answer, true)?
            }
            Tool::Hopper { launcher } => {
                // The launcher passes a script no arguments, so the paths go in front of it.
                let script = format!(
                    "REQUEST = {}\nANSWER = {}\n{HOPPER_SCRIPT}",
                    serde_json::to_string(&request_file.to_string_lossy()).map_err(|e| e.to_string())?,
                    serde_json::to_string(&answer.to_string_lossy()).map_err(|e| e.to_string())?,
                );
                let script = write("aa_facts_hopper.py", &script)?;
                let loader = match format {
                    Format::MachO => "Mach-O",
                    Format::Elf => "ELF",
                    Format::Pe => "WinPE",
                };
                let mut command = Command::new(launcher);
                command.arg("-l").arg(loader).arg("-e").arg(program).arg("-Y").arg(&script);
                // The launcher hands the file to the Hopper app and may end at once; the answer
                // file is what says the work is done.
                run(command, work, timeout, &answer, false)?
            }
        };
        let bytes = std::fs::read(&answer).map_err(|_| match said.trim() {
            "" => format!("{} wrote no answer", tool.name()),
            said => format!("{} wrote no answer; it said: {said}", tool.name()),
        })?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}'s answer cannot be read: {e}", tool.name()))?;
        if let Some(problem) = value.get("error").and_then(serde_json::Value::as_str) {
            return Err(format!("the script failed inside {}: {problem}", tool.name()));
        }
        serde_json::from_value(value).map_err(|e| format!("{}'s answer is not what was asked for: {e}", tool.name()))
    }
}

/// Starts `command` and waits for `answer` to appear, or for the program to end when
/// `ends_with_answer` says its ending is the sign. Returns the end of what it printed.
fn run(mut command: Command, folder: &Path, timeout: Duration, answer: &Path, ends_with_answer: bool) -> Result<String, String> {
    let log = folder.join("tool.log");
    let out = std::fs::File::create(&log).map_err(|e| format!("cannot write {}: {e}", log.display()))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let name = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .current_dir(folder)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .map_err(|e| format!("cannot start {name}: {e}"))?;
    let started = Instant::now();
    let mut ended = false;
    loop {
        if !ended && child.try_wait().map_err(|e| e.to_string())?.is_some() {
            ended = true;
            if ends_with_answer {
                break;
            }
        }
        if answer.exists() {
            break;
        }
        if started.elapsed() > timeout {
            if !ended {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(format!("no answer within {} seconds", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if !ended {
        // The launcher of an app that stays open: it has done its part.
        let _ = child.try_wait();
    }
    let said = std::fs::read_to_string(&log).unwrap_or_default();
    Ok(worth_saying(&said))
}

/// What of a tool's output goes into a message when it gave no answer: its complaints when it
/// made any, else its last lines.
fn worth_saying(said: &str) -> String {
    let lines: Vec<&str> = said.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    let errors: Vec<&str> =
        lines.iter().copied().filter(|line| line.starts_with("ERROR") && line.len() > "ERROR  (HeadlessAnalyzer)".len()).take(2).collect();
    let chosen = if errors.is_empty() { lines.iter().rev().take(3).rev().copied().collect() } else { errors };
    chosen.iter().map(|line| line.chars().take(300).collect::<String>()).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tools_complaints_are_what_is_said_of_a_run_without_an_answer() {
        let log = "INFO  starting\nERROR Failed to find script in any script directory: /x/AaFacts.java (GhidraScriptUtil)\nERROR  (HeadlessAnalyzer)\nINFO  REPORT: Import succeeded (HeadlessAnalyzer)\n";
        assert_eq!(worth_saying(log), "ERROR Failed to find script in any script directory: /x/AaFacts.java (GhidraScriptUtil)");
        assert_eq!(worth_saying("one\n\ntwo\nthree\nfour\n"), "two | three | four");
        assert_eq!(worth_saying(""), "");
    }
}
