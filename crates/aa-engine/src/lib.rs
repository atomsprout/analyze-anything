//! The analysis engine: the one entry point the command line and the desktop app both call.
//!
//! [`analyze`] builds the artifact tree (listing the input and opening containers), runs every
//! analyzer over it, and returns a [`Report`]. It never prints, never exits the process and never
//! executes anything from the input. Progress is reported as [`Event`]s through a
//! [`ProgressSink`]; a run is stopped by setting [`Options::cancel`].

mod scan;
mod store;
mod tree;
mod walk;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aa_core::plugin::{Analyzer, Output, Rule, Tree, Unpacker};
use aa_core::{Input, InputKind, Limitation, Report, RuleText, SCHEMA_VERSION, Tool};
use rayon::prelude::*;

/// Bounds that keep a hostile or huge input from exhausting the machine.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Most artifacts in the tree, unpacked ones included.
    pub max_files: u64,
    /// Most bytes read from the input on disk.
    pub max_total_bytes: u64,
    /// Most bytes unpacked from containers in total.
    pub max_unpacked_bytes: u64,
    /// Largest single entry unpacked from a container.
    pub max_entry_bytes: u64,
    /// How many containers deep unpacking goes (an archive in an archive is depth 2).
    pub max_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        Limits { max_files: 200_000, max_total_bytes: 16 * GIB, max_unpacked_bytes: 8 * GIB, max_entry_bytes: 2 * GIB, max_depth: 6 }
    }
}

/// Settings for one run. Everything that changes the result is here, not in the environment.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub limits: Limits,
    /// Set to `true` from another thread to stop the run. What was finished is still returned.
    pub cancel: Option<Arc<AtomicBool>>,
}

/// A step of the run, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The files of the input have been listed.
    Listed {
        files: u64,
    },
    /// A file of the input is about to be read. `index` starts at 1.
    Reading {
        index: u64,
        total: u64,
        path: String,
    },
    /// A container was opened into `children` artifacts.
    Unpacked {
        path: String,
        children: u64,
    },
    /// The tree is complete and analysis of its `artifacts` begins.
    Analyzing {
        artifacts: u64,
    },
    /// Something was skipped or failed; the report records it as a limitation.
    Warning {
        code: String,
        path: Option<String>,
    },
    Finished,
}

/// Receives progress events. Implement it to draw a progress bar or update a window.
pub trait ProgressSink {
    fn event(&mut self, event: Event);
}

/// A sink that ignores every event.
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn event(&mut self, _event: Event) {}
}

/// Why a run could not start at all.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("cannot read {path}: {source}")]
    InputUnreadable { path: PathBuf, source: std::io::Error },
    #[error("{path} is neither a file nor a folder")]
    UnsupportedInput { path: PathBuf },
}

/// The formats the engine knows: which unpackers and analyzers run, and in what order.
///
/// Unpackers are offered each artifact in order and the first that recognises it wins, so
/// specific formats come before general ones. Analyzers run in order in the tree pass.
#[derive(Default)]
pub struct Registry {
    pub unpackers: Vec<Box<dyn Unpacker>>,
    pub analyzers: Vec<Box<dyn Analyzer>>,
}

impl Registry {
    /// Everything built into this version.
    pub fn standard() -> Self {
        let mut registry = Registry::default();
        registry.unpackers.extend(aa_apple::unpackers());
        registry.unpackers.extend(aa_windows::unpackers());
        registry.unpackers.extend(aa_android::unpackers());
        registry.unpackers.extend(aa_unpack::unpackers());
        registry.analyzers.extend(aa_content::analyzers());
        registry.analyzers.extend(aa_binary::analyzers());
        registry.analyzers.extend(aa_apple::analyzers());
        registry.analyzers.extend(aa_windows::analyzers());
        registry.analyzers.extend(aa_android::analyzers());
        registry.analyzers.extend(aa_correlate::analyzers());
        registry
    }

    /// Text of every rule and limitation code, the engine's own included.
    pub fn rules(&self) -> BTreeMap<&'static str, Rule> {
        let unpackers = self.unpackers.iter().flat_map(|u| u.rules().iter());
        let analyzers = self.analyzers.iter().flat_map(|a| a.rules().iter());
        ENGINE_RULES.iter().chain(unpackers).chain(analyzers).map(|rule| (rule.id, *rule)).collect()
    }
}

/// Analyzes the file or folder at `input` with every built-in format.
///
/// Problems with individual files do not fail the run: each becomes a limitation in the report.
pub fn analyze(input: &Path, options: &Options, sink: &mut dyn ProgressSink) -> Result<Report, EngineError> {
    analyze_with(&Registry::standard(), input, options, sink)
}

/// Like [`analyze`], with a chosen set of formats.
pub fn analyze_with(registry: &Registry, input: &Path, options: &Options, sink: &mut dyn ProgressSink) -> Result<Report, EngineError> {
    let unreadable = |source| EngineError::InputUnreadable { path: input.to_path_buf(), source };
    let metadata = std::fs::metadata(input).map_err(unreadable)?;
    let kind = if metadata.is_dir() {
        InputKind::Directory
    } else if metadata.is_file() {
        InputKind::File
    } else {
        return Err(EngineError::UnsupportedInput { path: input.to_path_buf() });
    };
    // The name of the input as given; a path such as `.` has none, so resolve it first.
    let name = match input.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => {
            let resolved = std::fs::canonicalize(input).map_err(unreadable)?;
            resolved.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "/".into())
        }
    };

    let built = tree::build(input, kind, &name, options, &registry.unpackers, sink);
    let (mut tree, mut limitations, mut coverage) = (built.tree, built.limitations, built.coverage);
    sink.event(Event::Analyzing { artifacts: tree.artifacts.len() as u64 });

    let cancelled = || options.cancel.as_ref().is_some_and(|flag| flag.load(Ordering::Relaxed));
    let mut findings = Vec::new();
    let mut summary = BTreeMap::new();

    // File pass: every analyzer looks at every readable artifact. Results come back in artifact
    // order whatever the thread scheduling, so the report does not depend on it.
    let outputs: Vec<Output> = tree
        .artifacts
        .par_iter()
        .map(|artifact| {
            let mut out = Output::default();
            if artifact.digests.is_none() || cancelled() {
                return out;
            }
            for analyzer in &registry.analyzers {
                guarded(analyzer.as_ref(), Some(&artifact.path), &mut out, |out| analyzer.analyze_file(&tree, artifact, out));
            }
            out
        })
        .collect();
    for out in outputs {
        merge(&mut tree, out, &mut findings, &mut limitations, &mut summary);
    }

    // Tree pass: one analyzer at a time, each seeing what the ones before it attached.
    for analyzer in &registry.analyzers {
        if cancelled() {
            break;
        }
        let mut out = Output::default();
        guarded(analyzer.as_ref(), None, &mut out, |out| analyzer.analyze_tree(&tree, out));
        merge(&mut tree, out, &mut findings, &mut limitations, &mut summary);
    }
    if cancelled() && !limitations.iter().any(|l| l.code == "cancelled") {
        limitations.push(Limitation::new("cancelled", None, None));
        coverage.truncated = true;
    }

    findings.sort_by(|a, b| {
        let key = |f: &aa_core::Finding| {
            (f.section, std::cmp::Reverse(f.severity), f.rule.clone(), f.evidence.first().map(|e| e.artifact.clone()), f.id.clone())
        };
        key(a).cmp(&key(b))
    });
    findings.dedup_by(|a, b| a.id == b.id);
    limitations.sort();
    limitations.dedup();

    let catalogue = registry.rules();
    let used = findings.iter().map(|f| f.rule.as_str()).chain(limitations.iter().map(|l| l.code.as_str()));
    let rules = used
        .filter_map(|id| catalogue.get(id))
        .map(|rule| {
            let text = RuleText {
                title_zh: rule.title_zh.to_string(),
                title_en: rule.title_en.to_string(),
                text_zh: rule.text_zh.to_string(),
                text_en: rule.text_en.to_string(),
            };
            (rule.id.to_string(), text)
        })
        .collect();

    let sha256 = match kind {
        InputKind::File => tree.get(&name).and_then(|a| a.digests.as_ref()).map(|d| d.sha256.clone()),
        InputKind::Directory => None,
    };
    sink.event(Event::Finished);
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool { name: "analyze-anything".into(), version: env!("CARGO_PKG_VERSION").into() },
        input: Input { name, kind, sha256 },
        summary,
        artifacts: tree.artifacts,
        findings,
        limitations,
        coverage,
        rules,
    })
}

/// Runs one analyzer call, turning a panic into a limitation instead of a crash.
fn guarded(analyzer: &dyn Analyzer, artifact: Option<&str>, out: &mut Output, call: impl FnOnce(&mut Output)) {
    let mut scratch = Output::default();
    match catch_unwind(AssertUnwindSafe(|| call(&mut scratch))) {
        Ok(()) => {
            out.findings.append(&mut scratch.findings);
            out.facts.append(&mut scratch.facts);
            out.kinds.append(&mut scratch.kinds);
            out.limitations.append(&mut scratch.limitations);
        }
        Err(panic) => {
            let message = panic.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| panic.downcast_ref::<String>().cloned());
            let detail = format!("{}: {}", analyzer.id(), message.unwrap_or_else(|| "panic".into()));
            out.limitations.push(Limitation::new("analyzer_failed", artifact, Some(detail)));
        }
    }
}

fn merge(
    tree: &mut tree::BuiltTree,
    out: Output,
    findings: &mut Vec<aa_core::Finding>,
    limitations: &mut Vec<Limitation>,
    summary: &mut BTreeMap<String, serde_json::Value>,
) {
    findings.extend(out.findings);
    limitations.extend(out.limitations);
    let index = |tree: &tree::BuiltTree, path: &str| tree.artifacts.binary_search_by(|a| a.path.as_str().cmp(path)).ok();
    for (path, kind) in out.kinds {
        if let Some(i) = index(tree, &path) {
            tree.artifacts[i].kind = Some(kind);
        }
    }
    for fact in out.facts {
        match fact.artifact {
            None => {
                summary.insert(fact.key, fact.value);
            }
            Some(path) => {
                if let Some(i) = index(tree, &path) {
                    tree.artifacts[i].facts.insert(fact.key, fact.value);
                }
            }
        }
    }
}

/// Text for the limitation codes the engine itself records.
const ENGINE_RULES: &[Rule] = &[
    Rule {
        id: "read_failed",
        title_zh: "无法读取",
        title_en: "Could not be read",
        text_zh: "文件无法读取，因此没有分析。",
        text_en: "The file could not be read, so it was not analyzed.",
    },
    Rule {
        id: "symlink_skipped",
        title_zh: "跳过符号链接",
        title_en: "Symbolic link skipped",
        text_zh: "这是符号链接。为避免读到输入之外的文件，分析不跟随链接。",
        text_en: "This is a symbolic link. Links are not followed, so nothing outside the input is read.",
    },
    Rule {
        id: "special_file_skipped",
        title_zh: "跳过特殊文件",
        title_en: "Special file skipped",
        text_zh: "这不是普通文件（设备、管道等），已跳过。",
        text_en: "This is not a regular file (a device, a pipe, …) and was skipped.",
    },
    Rule {
        id: "limit_reached",
        title_zh: "达到限额",
        title_en: "Limit reached",
        text_zh: "达到了大小或数量限额，超出的部分没有分析。",
        text_en: "A size or count limit was reached; what lies beyond it was not analyzed.",
    },
    Rule {
        id: "depth_limit",
        title_zh: "嵌套过深",
        title_en: "Nested too deeply",
        text_zh: "这个容器嵌套层数超过限额，没有继续解包，里面的内容没有分析。",
        text_en: "This container is nested deeper than the limit allows. It was not unpacked and its content was not analyzed.",
    },
    Rule {
        id: "cancelled",
        title_zh: "分析被取消",
        title_en: "Run cancelled",
        text_zh: "分析被中途取消，剩余部分没有分析。",
        text_en: "The run was cancelled; the rest was not analyzed.",
    },
    Rule {
        id: "unpack_failed",
        title_zh: "解包失败",
        title_en: "Could not be unpacked",
        text_zh: "识别出了容器格式，但无法完整解包。已解出的部分仍被分析，其余内容不可见。",
        text_en: "The container format was recognised but could not be unpacked in full. What was extracted was analyzed; the rest is not visible.",
    },
    Rule {
        id: "entry_unreadable",
        title_zh: "容器内的文件无法读取",
        title_en: "Entry could not be read",
        text_zh: "容器内的这个文件无法解出（可能已损坏或被加密），因此没有分析。",
        text_en: "This entry could not be extracted from its container (it may be damaged or encrypted), so it was not analyzed.",
    },
    Rule {
        id: "unsafe_path",
        title_zh: "不安全的文件名",
        title_en: "Unsafe entry name",
        text_zh: "容器内有一个文件的名字试图指向容器之外（含 ..），已跳过。正常打包工具不会产生这样的名字。",
        text_en: "An entry's name points outside its container (it contains ..) and was skipped. Ordinary packaging tools do not produce such names.",
    },
    Rule {
        id: "analyzer_failed",
        title_zh: "分析器出错",
        title_en: "Analyzer failed",
        text_zh: "一个分析器在处理时出错，它对这个对象的结论缺失。其他分析器不受影响。",
        text_en: "An analyzer failed here, so its conclusions about this item are missing. Other analyzers are unaffected.",
    },
];
