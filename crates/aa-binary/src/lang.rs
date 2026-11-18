//! Which languages and toolchains a binary was built with, from markers the toolchains leave:
//! section names, runtime libraries, runtime symbols, and (least reliable) strings.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use memchr::memmem;
use serde_json::{Value, json};

use crate::common::{Marks, Rd, finding, text};

/// Go module dependencies kept in the fact.
const MAX_GO_DEPS: usize = 1000;

/// A section's name and where its bytes are in the binary.
pub struct Region {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

pub struct Language {
    pub name: &'static str,
    pub confidence: Confidence,
    /// What the claim rests on, e.g. `section .go.buildinfo`.
    pub basis: String,
    /// Offset and length of the marker inside the binary, when it is a byte range.
    pub at: Option<(u64, u64)>,
}

#[derive(Default)]
pub struct Toolchain {
    pub languages: Vec<Language>,
    /// The Go build information block, as a fact value, and where it was read.
    pub go: Option<(Value, u64)>,
    /// Commit hash of the Rust compiler, from a `/rustc/<hash>/` source path, and its offset.
    pub rustc_commit: Option<(String, u64)>,
}

impl Toolchain {
    pub fn has(&self, name: &str) -> bool {
        self.languages.iter().any(|l| l.name == name)
    }

    fn add(&mut self, name: &'static str, confidence: Confidence, basis: String, at: Option<(u64, u64)>) {
        // The first marker found for a language is the strongest; later ones add nothing.
        if !self.has(name) {
            self.languages.push(Language { name, confidence, basis, at });
        }
    }

    /// The fact value: `{ languages: [{name, confidence, basis}], go?, rustc_commit? }`.
    pub fn to_json(&self) -> Value {
        let languages: Vec<Value> = self
            .languages
            .iter()
            .map(|l| {
                json!({
                    "name": l.name,
                    "confidence": if l.confidence == Confidence::Heuristic { "heuristic" } else { "derived" },
                    "basis": l.basis,
                })
            })
            .collect();
        json!({
            "languages": languages,
            "go": self.go.as_ref().map(|(value, _)| value.clone()),
            "rustc_commit": self.rustc_commit.as_ref().map(|(hash, _)| hash.clone()),
        })
    }

    /// One finding per language, plus the Go build details. `label` prefixes the basis for a
    /// slice of a universal binary; `base` is the slice's offset in the file.
    pub fn emit(&self, file: &Artifact, base: u64, label: &str, out: &mut Output) {
        for language in &self.languages {
            let rule = if language.confidence == Confidence::Heuristic { "binary.language-heuristic" } else { "binary.language" };
            let basis = language.basis.as_str();
            let evidence = match language.at {
                Some((offset, length)) if length > 0 => Evidence::bytes(file, base + offset, length, basis),
                _ => Evidence::field(file, format!("{label}toolchain marker"), basis),
            };
            out.finding(
                finding(Section::Composition, rule, language.confidence, Severity::Info)
                    .param("label", label)
                    .param("language", language.name)
                    .param("basis", basis)
                    .evidence(evidence),
            );
        }
        if let Some((go, offset)) = &self.go
            && let Some(version) = go.get("version").and_then(Value::as_str)
        {
            let module = go.get("module").and_then(Value::as_str).unwrap_or("—");
            let deps = go.get("deps_total").and_then(Value::as_u64).unwrap_or(0);
            out.finding(
                // The block is a structure the Go linker defines; the strings are read as stored.
                finding(Section::Composition, "binary.go-build", Confidence::Verified, Severity::Info)
                    .param("version", version)
                    .param("module", module)
                    .param("deps", deps)
                    .param("label", label)
                    .evidence(Evidence::bytes(file, base + offset, 32, version)),
            );
        }
        if let Some((commit, offset)) = &self.rustc_commit {
            out.finding(
                finding(Section::Composition, "binary.rustc-commit", Confidence::Heuristic, Severity::Info)
                    .param("commit", commit.as_str())
                    .param("label", label)
                    .evidence(Evidence::bytes(file, base + offset, 48, format!("/rustc/{commit}/"))),
            );
        }
    }
}

/// Reads every marker. `libraries` are the names of linked libraries, `regions` the sections,
/// `idents` the compiler identification strings of an ELF `.comment` section.
pub fn detect(rd: &Rd, marks: &Marks, libraries: &[String], regions: &[Region], idents: &[String]) -> Toolchain {
    let mut found = Toolchain::default();
    let section = |wanted: &[&str]| regions.iter().find(|r| wanted.iter().any(|w| r.name == *w));
    let section_prefix = |prefix: &[&str]| regions.iter().find(|r| prefix.iter().any(|p| r.name.starts_with(p)));
    let library = |needles: &[&str]| {
        libraries.iter().find(|l| {
            let lower = l.to_ascii_lowercase();
            let leaf = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
            needles.iter().any(|n| leaf.starts_with(n))
        })
    };

    // Go.
    if let Some(region) = section(&[".go.buildinfo", "__go_buildinfo", ".gopclntab", "__gopclntab", ".note.go.buildid"]) {
        found.add("Go", Confidence::Derived, format!("section {}", region.name), Some((region.offset, region.size.min(32))));
    }
    if let Some((symbol, offset)) = &marks.go {
        found.add("Go", Confidence::Derived, format!("symbol {symbol}"), Some((*offset, 0)));
    }
    found.go = go_buildinfo(rd, section(&[".go.buildinfo", "__go_buildinfo"]));
    if let Some((_, offset)) = &found.go {
        found.add("Go", Confidence::Derived, "Go build information block".into(), Some((*offset, 16)));
    }

    // Rust.
    if let Some((symbol, offset)) = &marks.rust {
        found.add("Rust", Confidence::Derived, format!("symbol {symbol}"), Some((*offset, 0)));
    }
    if let Some(region) = section(&[".rustc", "__rustc"]) {
        found.add("Rust", Confidence::Derived, format!("section {}", region.name), Some((region.offset, region.size.min(32))));
    }
    if let Some(ident) = idents.iter().find(|i| i.starts_with("rustc version ")) {
        found.add("Rust", Confidence::Derived, format!("compiler identification \"{ident}\""), None);
    }
    found.rustc_commit = rustc_commit(rd.data);
    if let Some((commit, offset)) = &found.rustc_commit {
        found.add("Rust", Confidence::Heuristic, format!("source path /rustc/{commit}/"), Some((*offset, 48)));
    } else if let Some(offset) = memmem::find(rd.data, b"library/core/src/").or_else(|| memmem::find(rd.data, b"library\\core\\src\\")) {
        found.add("Rust", Confidence::Heuristic, "string library/core/src/".into(), Some((offset as u64, 17)));
    }

    // Swift.
    if let Some(region) = section_prefix(&["__swift5_", "swift5_", ".swift5_"]) {
        found.add("Swift", Confidence::Derived, format!("section {}", region.name), Some((region.offset, region.size.min(32))));
    }
    if let Some(lib) = library(&["libswiftcore"]) {
        found.add("Swift", Confidence::Derived, format!("links {lib}"), None);
    }
    if let Some((symbol, offset)) = &marks.swift {
        found.add("Swift", Confidence::Derived, format!("symbol {symbol}"), Some((*offset, 0)));
    }

    // Objective-C.
    if let Some(region) = section(&["__objc_classlist", "__objc_selrefs", "__objc_methname", "__objc_catlist", "__objc_protolist"]) {
        found.add("Objective-C", Confidence::Derived, format!("section {}", region.name), Some((region.offset, region.size.min(32))));
    } else if marks.objc_msgsend {
        found.add("Objective-C", Confidence::Derived, "imports objc_msgSend".into(), None);
    }

    // C++.
    if let Some(lib) = library(&["libstdc++", "libc++", "msvcp", "libc++abi", "vcruntime140_1", "libgnustl", "libstlport"]) {
        found.add("C++", Confidence::Derived, format!("links {lib}"), None);
    }
    if let Some((symbol, offset)) = &marks.cxx {
        found.add("C++", Confidence::Derived, format!("symbol {symbol}"), Some((*offset, 0)));
    }
    found
}

/// The first `/rustc/<40 hex digits>/` path in `data`: the standard library's source location as
/// compiled into panic messages. Looks at a bounded number of candidates.
fn rustc_commit(data: &[u8]) -> Option<(String, u64)> {
    for at in memmem::find_iter(data, b"/rustc/").take(4096) {
        let Some(hash) = data.get(at + 7..at + 47) else { continue };
        let sep = data.get(at + 47).copied();
        if hash.iter().all(u8::is_ascii_hexdigit) && matches!(sep, Some(b'/' | b'\\')) {
            return Some((String::from_utf8_lossy(hash).into_owned(), at as u64));
        }
    }
    None
}

const GO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Parses the Go build information block (`debug/buildinfo`): Go version, main module, and
/// dependencies. Go 1.18+ stores the strings inline; older releases store pointers, which are not
/// followed here (then `version` is null and `format` is `"pointer"`).
fn go_buildinfo(rd: &Rd, region: Option<&Region>) -> Option<(Value, u64)> {
    let start = match region {
        Some(region) if rd.bytes(region.offset, 14) == Some(GO_MAGIC) => region.offset,
        _ => memmem::find_iter(rd.data, GO_MAGIC).take(64).map(|at| at as u64).find(|at| {
            // The header is 32 bytes: magic, pointer size (4 or 8), flags.
            matches!(rd.u8(at + 14), Some(4 | 8)) && rd.u8(at + 15).is_some_and(|flags| flags <= 3)
        })?,
    };
    let flags = rd.u8(start + 15)?;
    if flags & 2 == 0 {
        return Some((json!({ "format": "pointer", "version": null, "module": null }), start));
    }
    let (version, next) = go_string(rd, start + 32)?;
    if !(version.starts_with("go") || version.starts_with("devel")) {
        return None;
    }
    let mut value = json!({ "format": "inline", "version": version, "module": null });
    if let Some((modinfo, _)) = go_string_raw(rd, next) {
        // The module text sits between two 16-byte sentinels.
        let body = if modinfo.len() >= 33 { modinfo.get(16..modinfo.len() - 16).unwrap_or(&[]) } else { &[] };
        let mut deps = Vec::new();
        let mut deps_total = 0u64;
        let mut settings = serde_json::Map::new();
        for line in String::from_utf8_lossy(body).lines() {
            let mut fields = line.split('\t');
            match (fields.next(), fields.next(), fields.next()) {
                (Some("path"), Some(path), _) => value["path"] = text(path.as_bytes()).into(),
                (Some("mod"), Some(module), version) => {
                    value["module"] = text(module.as_bytes()).into();
                    value["module_version"] = version.map(|v| text(v.as_bytes())).into();
                }
                (Some("dep"), Some(path), version) => {
                    deps_total += 1;
                    if deps.len() < MAX_GO_DEPS {
                        deps.push(json!({ "path": text(path.as_bytes()), "version": version.map(|v| text(v.as_bytes())) }));
                    }
                }
                (Some("build"), Some(setting), _) => {
                    // Linker and compiler flags can carry arbitrary text; keep the settings that
                    // describe the build, not the ones that may embed values.
                    const KEPT: &[&str] = &[
                        "-compiler",
                        "-buildmode",
                        "CGO_ENABLED",
                        "GOARCH",
                        "GOOS",
                        "GOAMD64",
                        "GOARM",
                        "GOARM64",
                        "vcs",
                        "vcs.revision",
                        "vcs.time",
                        "vcs.modified",
                    ];
                    if let Some((key, val)) = setting.split_once('=')
                        && KEPT.contains(&key)
                    {
                        settings.insert(key.to_string(), text(val.as_bytes()).into());
                    }
                }
                _ => {}
            }
        }
        value["deps_total"] = deps_total.into();
        value["deps_truncated"] = (deps_total > deps.len() as u64).into();
        value["deps"] = deps.into();
        value["settings"] = settings.into();
    }
    Some((value, start))
}

/// A Go varint-length-prefixed string, as bytes, and the offset after it.
fn go_string_raw<'a>(rd: &Rd<'a>, mut offset: u64) -> Option<(&'a [u8], u64)> {
    let mut length = 0u64;
    let mut shift = 0;
    loop {
        let byte = rd.u8(offset)?;
        offset += 1;
        length |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    Some((rd.bytes(offset, length)?, offset + length))
}

fn go_string(rd: &Rd, offset: u64) -> Option<(String, u64)> {
    let (bytes, next) = go_string_raw(rd, offset)?;
    (bytes.len() <= 256).then(|| (text(bytes), next))
}

/// The Go build ID, from the marker the linker writes at the start of the text
/// (`\xff Go build ID: "…"`). ELF also has it in a note, which the ELF parser prefers.
pub fn go_build_id(data: &[u8]) -> Option<(String, u64)> {
    const MARK: &[u8] = b"\xff Go build ID: \"";
    let head = data.get(..data.len().min(1 << 20))?;
    let at = memmem::find(head, MARK)?;
    let rest = data.get(at + MARK.len()..)?;
    let end = rest.iter().take(512).position(|b| *b == b'"')?;
    Some((text(rest.get(..end)?), at as u64))
}
