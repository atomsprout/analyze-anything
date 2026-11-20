//! Which disassembler to ask, and where it is.
//!
//! The choice is kept in `~/.analyze-anything/deep.toml`, a file of its own beside the AI
//! settings. Nothing in it is needed when a tool is in a usual place: Ghidra is looked for
//! through `GHIDRA_INSTALL_DIR` and the search path, Hopper in the Applications folder.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::tool::Tool;

/// The file's contents. Everything is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chosen {
    /// `ghidra` or `hopper`: which to use when both are there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Ghidra's folder, the one that holds `support/analyzeHeadless`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ghidra: Option<PathBuf>,
    /// The Hopper app, or the `hopper` launcher inside it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hopper: Option<PathBuf>,
    /// Most program files of one input handed to the tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_files: Option<usize>,
    /// Longest the tool may spend on one program file, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u64>,
}

/// Where the settings are kept: `AA_DEEP_CONFIG`, or `deep.toml` in `~/.analyze-anything`.
pub fn default_path() -> Option<PathBuf> {
    let set = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    if let Some(path) = set("AA_DEEP_CONFIG") {
        return Some(path);
    }
    let home = if cfg!(windows) { set("USERPROFILE") } else { set("HOME") };
    home.map(|home| home.join(".analyze-anything").join("deep.toml"))
}

/// Reads the file at `path`. A file that does not exist gives empty settings.
pub fn read_file(path: &Path) -> Result<Chosen, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Chosen::default()),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

pub fn write_file(path: &Path, chosen: &Chosen) -> Result<(), String> {
    let text = toml::to_string(chosen).map_err(|error| error.to_string())?;
    if let Some(folder) = path.parent() {
        std::fs::create_dir_all(folder).map_err(|error| format!("cannot create {}: {error}", folder.display()))?;
    }
    std::fs::write(path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The usual place of the Hopper app's launcher on a Mac.
const HOPPER_APP: &str = "/Applications/Hopper Disassembler.app";

/// `analyzeHeadless` for the Ghidra folder `given`; `given` itself when it already is that file.
fn headless(given: &Path) -> PathBuf {
    let name = if cfg!(windows) { "analyzeHeadless.bat" } else { "analyzeHeadless" };
    if given.file_name().is_some_and(|file| file == name) { given.to_path_buf() } else { given.join("support").join(name) }
}

/// The launcher for the Hopper app `given`; `given` itself when it already is the launcher.
fn launcher(given: &Path) -> PathBuf {
    if given.extension().is_some_and(|extension| extension == "app") { given.join("Contents/MacOS/hopper") } else { given.to_path_buf() }
}

fn ghidra(chosen: &Chosen, env: &dyn Fn(&str) -> Option<String>, is_file: &dyn Fn(&Path) -> bool) -> Result<Tool, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    candidates.extend(chosen.ghidra.as_deref().map(headless));
    candidates.extend(env("GHIDRA_INSTALL_DIR").filter(|dir| !dir.is_empty()).map(|dir| headless(Path::new(&dir))));
    let name = if cfg!(windows) { "analyzeHeadless.bat" } else { "analyzeHeadless" };
    candidates.extend(
        env("PATH").map(|path| std::env::split_paths(&path).map(|folder| folder.join(name)).collect::<Vec<_>>()).unwrap_or_default(),
    );
    for candidate in candidates {
        if is_file(&candidate) {
            return Ok(Tool::Ghidra { headless: candidate });
        }
    }
    Err("Ghidra was not found: say where it is with `analyze-anything deep ghidra --path <Ghidra's folder>`, or set GHIDRA_INSTALL_DIR"
        .into())
}

fn hopper(chosen: &Chosen, is_file: &dyn Fn(&Path) -> bool) -> Result<Tool, String> {
    let candidates = [chosen.hopper.as_deref().map(launcher), Some(launcher(Path::new(HOPPER_APP)))];
    match candidates.into_iter().flatten().find(|candidate| is_file(candidate)) {
        Some(found) => Ok(Tool::Hopper { launcher: found }),
        None => Err("Hopper was not found: say where it is with `analyze-anything deep hopper --path <the Hopper app>`".into()),
    }
}

/// The tool to ask: `wanted` (a flag), else the file's choice, else Ghidra when it is found,
/// else Hopper. `env` looks up an environment variable and `is_file` says whether a file exists.
pub fn find(
    chosen: &Chosen,
    wanted: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
    is_file: &dyn Fn(&Path) -> bool,
) -> Result<Tool, String> {
    match wanted.or(chosen.tool.as_deref()) {
        Some("ghidra") => ghidra(chosen, env, is_file),
        Some("hopper") => hopper(chosen, is_file),
        Some(other) => Err(format!("{other:?} is not a tool the deep level knows: it is `ghidra` or `hopper`")),
        None => ghidra(chosen, env, is_file).or_else(|_| hopper(chosen, is_file)).map_err(|_| {
            "the deep level needs Ghidra or Hopper, and neither was found: say where one is with \
             `analyze-anything deep ghidra --path <Ghidra's folder>` or `analyze-anything deep hopper --path <the Hopper app>`"
                .to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn the_tool_is_the_flags_then_the_files_then_ghidra_before_hopper() {
        let everything = |_: &Path| true;
        let chosen = Chosen { tool: Some("hopper".into()), ghidra: Some("/opt/ghidra".into()), ..Chosen::default() };
        assert_eq!(find(&chosen, None, &none, &everything).expect("found").id(), "hopper");
        assert_eq!(find(&chosen, Some("ghidra"), &none, &everything).expect("found").id(), "ghidra");
        let unsaid = Chosen { ghidra: Some("/opt/ghidra".into()), ..Chosen::default() };
        assert_eq!(find(&unsaid, None, &none, &everything).expect("found").id(), "ghidra");
        assert!(find(&unsaid, Some("ida"), &none, &everything).expect_err("unknown").contains("ghidra"));
    }

    #[test]
    fn ghidra_is_found_in_its_folder_through_the_variable_or_on_the_search_path() {
        let name = if cfg!(windows) { "analyzeHeadless.bat" } else { "analyzeHeadless" };
        let wanted = Path::new("/opt/ghidra").join("support").join(name);
        let there = |path: &Path| path == wanted;
        let from_file = Chosen { ghidra: Some("/opt/ghidra".into()), ..Chosen::default() };
        assert_eq!(find(&from_file, None, &none, &there).expect("found").path(), wanted);
        let env = |name: &str| (name == "GHIDRA_INSTALL_DIR").then(|| "/opt/ghidra".to_string());
        assert_eq!(find(&Chosen::default(), None, &env, &there).expect("found").path(), wanted);
        let on_path = Path::new("/usr/local/bin").join(name);
        let env = |name: &str| (name == "PATH").then(|| "/usr/local/bin".to_string());
        assert_eq!(find(&Chosen::default(), None, &env, &|path: &Path| path == on_path).expect("found").path(), on_path);
    }

    #[test]
    fn with_no_tool_anywhere_the_error_says_how_to_name_one() {
        let nothing = |_: &Path| false;
        let error = find(&Chosen::default(), None, &none, &nothing).expect_err("nothing");
        assert!(error.contains("deep ghidra --path") && error.contains("deep hopper --path"), "{error}");
        assert!(find(&Chosen::default(), Some("hopper"), &none, &nothing).expect_err("no hopper").contains("Hopper was not found"));
    }

    #[test]
    fn the_file_is_read_back_as_written_and_refuses_what_it_does_not_know() {
        let folder = tempfile::tempdir().expect("folder");
        let path = folder.path().join("deep.toml");
        assert_eq!(read_file(&path).expect("absent is empty"), Chosen::default());
        let chosen = Chosen { tool: Some("ghidra".into()), ghidra: Some("/opt/ghidra".into()), seconds: Some(900), ..Chosen::default() };
        write_file(&path, &chosen).expect("written");
        assert_eq!(read_file(&path).expect("read"), chosen);
        std::fs::write(&path, "tools = \"ghidra\"\n").expect("written");
        assert!(read_file(&path).is_err());
    }
}
