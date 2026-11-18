//! Pieces shared by the three format parsers: checked reads, entropy, symbol-name markers, caps.

use std::collections::BTreeSet;

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Finding, Section, Severity};
use serde_json::{Map, Value, json};

/// Sections kept per binary in `binary.sections`.
pub const MAX_SECTIONS: usize = 1024;
/// Libraries kept per binary in `binary.libraries`.
pub const MAX_LIBRARIES: usize = 1024;
/// Symbols kept per list in `binary.imports` and `binary.exports`. Counts are always complete.
pub const MAX_SYMBOLS: usize = 2000;
/// Longest name read from a string table. Longer names are cut here.
pub const MAX_NAME: usize = 1024;
/// Limitations kept per artifact, so a mangled file cannot flood the report.
const MAX_LIMITATIONS: usize = 16;

/// Checked access to the bytes of one binary. Every read returns `None` instead of going out of
/// bounds; nothing here can panic on any input.
#[derive(Clone, Copy)]
pub struct Rd<'a> {
    pub data: &'a [u8],
    /// Byte order of multi-byte fields.
    pub le: bool,
}

impl<'a> Rd<'a> {
    pub fn new(data: &'a [u8], le: bool) -> Self {
        Rd { data, le }
    }

    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn bytes(&self, offset: u64, length: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(length).ok()?)?;
        self.data.get(start..end)
    }

    fn array<const N: usize>(&self, offset: u64) -> Option<[u8; N]> {
        self.bytes(offset, N as u64)?.try_into().ok()
    }

    pub fn u8(&self, offset: u64) -> Option<u8> {
        self.array::<1>(offset).map(|b| b[0])
    }

    pub fn u16(&self, offset: u64) -> Option<u16> {
        self.array(offset).map(|b| if self.le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    }

    pub fn u32(&self, offset: u64) -> Option<u32> {
        self.array(offset).map(|b| if self.le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    }

    pub fn u64(&self, offset: u64) -> Option<u64> {
        self.array(offset).map(|b| if self.le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
    }

    /// A 64-bit field when `wide`, else a 32-bit one widened.
    pub fn word(&self, offset: u64, wide: bool) -> Option<u64> {
        if wide { self.u64(offset) } else { self.u32(offset).map(u64::from) }
    }

    /// The NUL-terminated string at `offset`, at most [`MAX_NAME`] bytes, not reading past `end`
    /// (an absolute offset; pass `self.len()` for no limit). `None` when `offset` is outside.
    pub fn cstr(&self, offset: u64, end: u64) -> Option<String> {
        let end = end.min(self.len());
        if offset >= end {
            return None;
        }
        let window = self.bytes(offset, (end - offset).min(MAX_NAME as u64))?;
        Some(text(window))
    }
}

/// The text of a fixed-size or bounded name field: bytes up to the first NUL, lossily decoded,
/// with control characters replaced so a hostile name cannot disturb a report.
pub fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect()
}

/// Shannon entropy of `bytes` in bits per byte, rounded to three decimals. `None` when empty.
pub fn entropy(bytes: &[u8]) -> Option<f64> {
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0u64; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let total = bytes.len() as f64;
    let bits: f64 = counts.iter().filter(|c| **c > 0).map(|c| *c as f64 / total).map(|p| -p * p.log2()).sum();
    Some((bits * 1000.0).round() / 1000.0)
}

/// Entropy of regions of one binary, refusing to re-read the file more than a few times over when
/// a malformed file declares many overlapping sections.
pub struct EntropyBudget {
    left: u64,
}

impl EntropyBudget {
    pub fn new(file_len: u64) -> Self {
        EntropyBudget { left: file_len.saturating_mul(4) }
    }

    pub fn of(&mut self, rd: &Rd, offset: u64, length: u64) -> Option<f64> {
        if length == 0 || length > self.left {
            return None;
        }
        let bytes = rd.bytes(offset, length)?;
        self.left -= length;
        entropy(bytes)
    }
}

pub fn finding(section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    Finding::new(section, "binary", rule, confidence, severity)
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `0x`-prefixed hex, the way reference tools print addresses.
pub fn hx(value: u64) -> String {
    format!("{value:#x}")
}

/// The names of the bits of `value` that are in `names`, plus one hex entry for unnamed bits.
pub fn flag_names(value: u64, names: &[(u64, &str)]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().filter(|(bit, _)| value & bit != 0).map(|(_, name)| (*name).to_string()).collect();
    let known = names.iter().fold(0, |acc, (bit, _)| acc | bit);
    if value & !known != 0 {
        out.push(hx(value & !known));
    }
    out
}

/// A list that keeps the first `cap` items and counts the rest.
pub struct Capped<T> {
    pub items: Vec<T>,
    pub total: u64,
    cap: usize,
}

impl<T> Capped<T> {
    pub fn new(cap: usize) -> Self {
        Capped { items: Vec::new(), total: 0, cap }
    }

    pub fn push(&mut self, item: T) {
        self.total += 1;
        if self.items.len() < self.cap {
            self.items.push(item);
        }
    }

    pub fn truncated(&self) -> bool {
        self.total > self.items.len() as u64
    }
}

/// Limitations of one artifact, each distinct text once.
#[derive(Default)]
pub struct Problems {
    seen: BTreeSet<(&'static str, String)>,
}

impl Problems {
    /// A structure pointed outside the file, or was internally inconsistent.
    pub fn malformed(&mut self, detail: impl Into<String>) {
        self.seen.insert(("binary.malformed", detail.into()));
    }

    /// Something could not be decided from what the file holds.
    pub fn undetermined(&mut self, detail: impl Into<String>) {
        self.seen.insert(("binary.undetermined", detail.into()));
    }

    pub fn emit(self, file: &Artifact, out: &mut Output) {
        for (code, detail) in self.seen.into_iter().take(MAX_LIMITATIONS) {
            out.limitation(code, Some(file), Some(detail));
        }
    }
}

/// What the symbol names of a binary say about how it was built. Fed one name at a time while a
/// symbol table is walked, so nothing here grows with the size of the table.
#[derive(Default)]
pub struct Marks {
    /// A stack-protector symbol and the file offset of its symbol entry.
    pub canary: Option<(String, u64)>,
    /// Fortified libc entry points imported (`__memcpy_chk`, …).
    pub fortified: BTreeSet<String>,
    /// Imported libc functions that have a fortified twin but were imported plain.
    pub fortifiable: BTreeSet<String>,
    /// An Objective-C ARC runtime entry point and the offset of its symbol entry.
    pub arc: Option<(String, u64)>,
    pub objc_msgsend: bool,
    pub rust: Option<(String, u64)>,
    pub go: Option<(String, u64)>,
    pub cxx: Option<(String, u64)>,
    pub swift: Option<(String, u64)>,
}

/// libc functions `_FORTIFY_SOURCE` replaces with checked variants.
const FORTIFIABLE: &[&str] = &[
    "fgets", "fread", "gets", "memcpy", "memmove", "mempcpy", "memset", "pread", "read", "readlink", "recv", "recvfrom", "snprintf",
    "sprintf", "stpcpy", "stpncpy", "strcat", "strcpy", "strncat", "strncpy", "vsnprintf", "vsprintf", "wcscpy", "wcsncpy", "wmemcpy",
];

impl Marks {
    /// Looks at one symbol name. `skip` is the number of leading underscores the platform adds
    /// (1 on Mach-O). `imported` is true for undefined symbols. `offset` locates the symbol entry.
    pub fn see(&mut self, raw: &str, skip: usize, imported: bool, offset: u64) {
        let name = if skip == 1 { raw.strip_prefix('_').unwrap_or(raw) } else { raw };
        // Symbol versions (`memcpy@GLIBC_2.14`) are not part of the name.
        let name = name.split('@').next().unwrap_or(name);
        let at = |slot: &mut Option<(String, u64)>| {
            if slot.is_none() {
                *slot = Some((raw.to_string(), offset));
            }
        };
        match name {
            "__stack_chk_fail" | "__stack_chk_guard" | "__stack_chk_fail_local" | "__intel_security_cookie" => at(&mut self.canary),
            "__gxx_personality_v0" | "__gxx_personality_seh0" | "__gxx_personality_sj0" | "__cxa_throw" | "__cxa_begin_catch" => {
                at(&mut self.cxx)
            }
            "rust_begin_unwind" | "rust_eh_personality" | "__rust_alloc" | "__rust_dealloc" | "rust_panic" | "__rustc::rust_begin_unwind" => {
                at(&mut self.rust)
            }
            "runtime.main" | "runtime.goexit" | "runtime.gcStart" | "runtime.buildVersion" | "go:buildid" | "go.buildid" => at(&mut self.go),
            "objc_msgSend" => self.objc_msgsend = true,
            "swift_retain" | "swift_release" | "swift_allocObject" | "swift_once" => at(&mut self.swift),
            _ => {}
        }
        if name.starts_with("objc_release")
            || name.starts_with("objc_retain")
            || name == "objc_storeStrong"
            || name == "objc_autoreleaseReturnValue"
        {
            at(&mut self.arc);
        }
        if name.starts_with("_ZSt") || name.starts_with("_ZNSt") || name.starts_with("_ZNKSt") || name.starts_with("_ZTVN10__cxxabiv") {
            at(&mut self.cxx);
        }
        if name.contains("rust_begin_unwind") || name.contains("rust_eh_personality") {
            at(&mut self.rust);
        }
        if imported {
            if name.starts_with("__") && name.ends_with("_chk") && !name.starts_with("__stack_chk") {
                if self.fortified.len() < 256 {
                    self.fortified.insert(name.to_string());
                }
            } else if FORTIFIABLE.contains(&name) {
                self.fortifiable.insert(name.to_string());
            }
        }
    }
}

/// One named symbol kept for a fact.
pub struct Symbol {
    pub name: String,
    /// The library the format binds the symbol to, where it records one.
    pub library: Option<String>,
    /// Extra per-format fields (`ordinal`, `address`, `weak`, `forwarder`).
    pub extra: Map<String, Value>,
}

impl Symbol {
    pub fn new(name: String) -> Self {
        Symbol { name, library: None, extra: Map::new() }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }
}

/// `{ "count", "symbols": [{name, library?, …}], "truncated" }`, symbols sorted by library and name.
pub fn symbols_json(list: Capped<Symbol>, with_library: bool) -> Value {
    let truncated = list.truncated();
    let mut items = list.items;
    items.sort_by(|a, b| (&a.library, &a.name).cmp(&(&b.library, &b.name)));
    let symbols: Vec<Value> = items
        .into_iter()
        .map(|symbol| {
            let mut object = symbol.extra;
            object.insert("name".into(), symbol.name.into());
            if with_library {
                object.insert("library".into(), symbol.library.map_or(Value::Null, Value::from));
            }
            Value::Object(object)
        })
        .collect();
    json!({ "count": list.total, "symbols": symbols, "truncated": truncated })
}

/// The first few names of a list, for a sentence.
pub fn sample(names: &[String], count: usize) -> String {
    let mut text = names.iter().take(count).map(String::as_str).collect::<Vec<_>>().join(", ");
    if names.len() > count {
        text.push_str(", …");
    }
    text
}
