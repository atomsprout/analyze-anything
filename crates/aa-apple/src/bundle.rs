//! Finding bundles in the artifact tree and reading their property lists.

use aa_core::Artifact;
use aa_core::plugin::Tree;
use plist::{Dictionary, Value};

/// Largest property list parsed.
const MAX_PLIST: u64 = 32 * 1024 * 1024;

/// Extensions that make a folder with an `Info.plist` directly inside a bundle (the iOS layout).
/// A folder with `Contents/Info.plist` is a bundle whatever it is called.
const FLAT_BUNDLES: &[&str] = &["app", "appex", "framework", "xpc", "bundle", "kext", "plugin", "systemextension", "dext"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `X.app/Info.plist`: iOS and its relatives.
    Flat,
    /// `X.app/Contents/Info.plist`: macOS.
    Contents,
    /// `X.framework/Versions/A/Resources/Info.plist`: macOS frameworks.
    Versioned,
}

#[derive(Debug, Clone)]
pub struct Bundle<'t> {
    /// The bundle folder's path; empty when the input folder itself is the bundle.
    pub dir: String,
    /// The folder's extension, lowercase: `app`, `framework`, `appex`, …; empty when unknown.
    pub extension: String,
    pub layout: Layout,
    /// The folder signatures are relative to: where the executable's `_CodeSignature` lives.
    pub root: String,
    pub info: &'t Artifact,
    /// The parsed `Info.plist`; `Err` says why it could not be read.
    pub plist: Result<Dictionary, String>,
    /// Index of the bundle this one is nested in.
    pub parent: Option<usize>,
    /// What to call the bundle when it has no folder of its own: the name of the input.
    pub input: String,
}

fn join(dir: &str, rest: &str) -> String {
    if dir.is_empty() { rest.to_string() } else { format!("{dir}/{rest}") }
}

impl Bundle<'_> {
    pub fn path(&self, rest: &str) -> String {
        join(&self.dir, rest)
    }

    /// The path of a file given relative to the signing root.
    pub fn rooted(&self, rest: &str) -> String {
        join(&self.root, rest)
    }

    /// The folder name. When the input itself is the bundle that is the input's name, or `.`
    /// (the folder that was given) when the tree does not know it.
    pub fn name(&self) -> &str {
        match self.dir.rsplit('/').next() {
            Some(name) if !self.dir.is_empty() => name,
            _ if !self.input.is_empty() => &self.input,
            _ => ".",
        }
    }

    pub fn string(&self, key: &str) -> Option<&str> {
        self.plist.as_ref().ok()?.get(key)?.as_string()
    }

    /// What the bundle is: `app`, `framework`, `app-extension`, …
    pub fn kind(&self) -> &'static str {
        let package = self.string("CFBundlePackageType").unwrap_or("");
        match (self.extension.as_str(), package) {
            ("app", _) | (_, "APPL") => "app",
            ("framework", _) | (_, "FMWK") => "framework",
            ("appex", _) => "app-extension",
            ("xpc", _) | (_, "XPC!") => "xpc-service",
            ("kext", _) | (_, "KEXT") => "kernel-extension",
            ("systemextension", _) | ("dext", _) => "system-extension",
            _ => "bundle",
        }
    }

    /// The path of the main executable, as `Info.plist` names it.
    pub fn executable_path(&self) -> Option<String> {
        let name = self.string("CFBundleExecutable")?;
        Some(match self.layout {
            Layout::Flat | Layout::Versioned => self.rooted(name),
            Layout::Contents => self.rooted(&format!("MacOS/{name}")),
        })
    }

    /// True when `path` is inside this bundle.
    pub fn contains(&self, path: &str) -> bool {
        self.dir.is_empty() || path.strip_prefix(self.dir.as_str()).is_some_and(|rest| rest.starts_with('/'))
    }
}

/// Reads a property list, XML or binary.
pub fn read_plist(tree: &dyn Tree, artifact: &Artifact) -> Result<Value, String> {
    if artifact.size > MAX_PLIST {
        return Err(format!("{} bytes is too large for a property list", artifact.size));
    }
    let bytes = tree.read(&artifact.path).map_err(|e| e.to_string())?;
    parse_plist(&bytes)
}

pub fn parse_plist(bytes: &[u8]) -> Result<Value, String> {
    Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())
}

fn read_dictionary(tree: &dyn Tree, artifact: &Artifact) -> Result<Dictionary, String> {
    read_plist(tree, artifact)?.into_dictionary().ok_or_else(|| "the property list is not a dictionary".to_string())
}

fn extension_of(dir: &str) -> String {
    dir.rsplit('/').next().and_then(|name| name.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Where the bundle an `Info.plist` at `path` describes is, if the path fits a bundle layout.
fn locate(path: &str) -> Option<(String, Layout, String)> {
    let folder = path.strip_suffix("Info.plist")?;
    let folder = folder.strip_suffix('/').unwrap_or(folder);
    if !folder.is_empty() && path.len() == folder.len() + "Info.plist".len() {
        // "XInfo.plist" is not an Info.plist.
        return None;
    }
    let parts: Vec<&str> = if folder.is_empty() { Vec::new() } else { folder.split('/').collect() };
    let count = parts.len();
    if count >= 3
        && parts[count - 1] == "Resources"
        && parts[count - 3] == "Versions"
        && extension_of(parts[..count - 3].last().copied().unwrap_or("")) == "framework"
    {
        return Some((parts[..count - 3].join("/"), Layout::Versioned, parts[..count - 1].join("/")));
    }
    if parts.last() == Some(&"Contents") {
        return Some((parts[..count - 1].join("/"), Layout::Contents, folder.to_string()));
    }
    if folder.is_empty() || FLAT_BUNDLES.contains(&extension_of(folder).as_str()) {
        return Some((folder.to_string(), Layout::Flat, folder.to_string()));
    }
    None
}

/// Every bundle in the tree, sorted by folder so that a bundle comes before what it contains.
pub fn discover(tree: &dyn Tree) -> Vec<Bundle<'_>> {
    let mut bundles: Vec<Bundle<'_>> = Vec::new();
    for artifact in tree.artifacts().iter().filter(|a| a.name() == "Info.plist") {
        let Some((dir, layout, root)) = locate(&artifact.path) else { continue };
        if dir.is_empty() && layout == Layout::Flat && tree.get("Contents/Info.plist").is_some() {
            continue;
        }
        if bundles.iter().any(|known| known.dir == dir) {
            continue;
        }
        let plist = read_dictionary(tree, artifact);
        // A flat Info.plist at the top of the input is a bundle only if it reads like one.
        if dir.is_empty() && layout == Layout::Flat && !plist.as_ref().is_ok_and(|p| p.contains_key("CFBundleIdentifier")) {
            continue;
        }
        let input = if dir.is_empty() { tree.input_name().to_string() } else { String::new() };
        // A folder given as the input keeps its extension in the input's name, not in a path.
        let extension = if dir.is_empty() { extension_of(&input) } else { extension_of(&dir) };
        bundles.push(Bundle { extension, dir, layout, root, info: artifact, plist, parent: None, input });
    }
    bundles.sort_by(|a, b| a.dir.cmp(&b.dir));
    for index in 0..bundles.len() {
        // The closest enclosing bundle: the last one before it whose folder is a prefix.
        let parent = (0..index)
            .rev()
            .find(|candidate| bundles[*candidate].contains(&bundles[index].dir) && bundles[*candidate].dir != bundles[index].dir);
        bundles[index].parent = parent;
    }
    bundles
}

/// The strings of an array value.
pub fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_string().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// A boolean, also accepting the strings and numbers some tools write instead.
pub fn truthy(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Boolean(flag) => Some(*flag),
        Value::String(text) => match text.to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => Some(true),
            "no" | "false" | "0" => Some(false),
            _ => None,
        },
        Value::Integer(number) => number.as_signed().map(|n| n != 0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        let flat = locate("a.ipa/Payload/X.app/Info.plist").expect("flat");
        assert_eq!(flat, ("a.ipa/Payload/X.app".to_string(), Layout::Flat, "a.ipa/Payload/X.app".to_string()));
        let mac = locate("X.app/Contents/Info.plist").expect("contents");
        assert_eq!(mac, ("X.app".to_string(), Layout::Contents, "X.app/Contents".to_string()));
        let framework = locate("X.app/Contents/Frameworks/S.framework/Versions/B/Resources/Info.plist").expect("versioned");
        assert_eq!(framework.0, "X.app/Contents/Frameworks/S.framework");
        assert_eq!(framework.1, Layout::Versioned);
        assert_eq!(framework.2, "X.app/Contents/Frameworks/S.framework/Versions/B");
        assert_eq!(locate("Contents/Info.plist").map(|l| (l.0, l.1)), Some((String::new(), Layout::Contents)));
        assert_eq!(locate("Info.plist").map(|l| l.1), Some(Layout::Flat));
        assert_eq!(locate("X.app/Resources/Info.plist"), None);
        assert_eq!(locate("docs/Info.plist"), None);
        assert_eq!(locate("X.app/MyInfo.plist"), None);
        assert_eq!(locate("X.app/Info.plist.bak"), None);
    }

    #[test]
    fn plist_helpers() {
        let value = parse_plist(b"<plist><dict><key>a</key><array><string>x</string><integer>1</integer></array><key>b</key><string>YES</string></dict></plist>")
            .expect("valid");
        let dictionary = value.as_dictionary().expect("dictionary");
        assert_eq!(strings(dictionary.get("a")), ["x"]);
        assert_eq!(truthy(dictionary.get("b")), Some(true));
        assert_eq!(truthy(dictionary.get("a")), None);
        assert_eq!(truthy(None), None);
        assert!(parse_plist(b"").is_err());
        assert!(parse_plist(b"bplist00\xff\xff\xff\xff").is_err());
        assert!(parse_plist(b"<plist><dict><key>a</key>").is_err());
    }
}
