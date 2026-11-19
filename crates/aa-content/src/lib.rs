//! Analysis that applies to any file, whatever its format: disguised executables, opaque
//! high-entropy data, the URLs a file mentions, and embedded credentials.

mod secrets;
mod urls;
pub mod yara;

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(Content)]
}

struct Content;

/// Entropy at or above this, in a file of unrecognised type, suggests packed or encrypted data.
const HIGH_ENTROPY: f64 = 7.5;
/// Small files reach high entropy by chance, so the rule ignores them.
const HIGH_ENTROPY_MIN_SIZE: u64 = 4096;

/// Types the operating system can run directly.
const EXECUTABLE_MIMES: &[&str] =
    &["application/vnd.microsoft.portable-executable", "application/x-executable", "application/x-mach-binary"];
/// Extensions people expect to be safe to open: documents, pictures, media, text.
const HARMLESS_EXTENSIONS: &[&str] = &[
    "txt", "md", "csv", "json", "xml", "log", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "jpg", "jpeg", "png", "gif",
    "bmp", "webp", "svg", "mp3", "wav", "mp4", "mov", "avi", "mkv",
];

/// Largest file a similarity digest is computed for.
const TLSH_MAX: u64 = 256 * 1024 * 1024;

/// Hosts listed in the report's summary. The per-file facts always hold every URL kept.
const SUMMARY_HOSTS: usize = 2000;

const RULES: &[Rule] = &[
    Rule {
        id: "content.executable-disguised",
        title_zh: "可执行程序伪装成其他类型",
        title_en: "Executable under a harmless name",
        text_zh: "文件扩展名是 .{extension}，但内容是可执行程序（{mime}）。扩展名与内容不符，打开时可能被当作程序运行。",
        text_en: "The file is named .{extension} but its content is an executable program ({mime}). The name does not match the content.",
    },
    Rule {
        id: "content.high-entropy",
        title_zh: "无法识别的高熵数据",
        title_en: "Unrecognised high-entropy data",
        text_zh: "文件类型无法识别，且熵为 {entropy}（上限 8）。这类数据通常是压缩、加密或加壳后的内容，里面有什么无法判断。",
        text_en: "The file type is not recognised and its entropy is {entropy} (of 8). Data like this is usually compressed, encrypted or packed; what it holds cannot be told.",
    },
    Rule {
        id: "content.hosts",
        title_zh: "文件中出现的网络地址",
        title_en: "Hosts mentioned in the files",
        text_zh: "在 {files} 个文件中找到 {urls} 个不同的 URL，指向 {hosts} 个主机。这些是文件里写着的地址，不代表程序一定会访问它们。",
        text_en: "{urls} distinct URLs pointing at {hosts} hosts were found in {files} files. These are addresses written in the files; the program does not necessarily contact them.",
    },
    Rule {
        id: "content.secret",
        title_zh: "疑似硬编码的凭据",
        title_en: "Possible hard-coded credential",
        text_zh: "发现形似 {kind} 的字符串（已脱敏：{redacted}）。这是按格式匹配的结果，可能是示例值或误报，需要人工确认。",
        text_en: "A string shaped like a {kind} was found (redacted: {redacted}). This is a pattern match; it may be a sample value or a false positive and needs a person to confirm.",
    },
    Rule {
        id: "content.private-key",
        title_zh: "内嵌私钥",
        title_en: "Embedded private key",
        text_zh: "文件中有 {kind} 的起始标记。私钥随程序分发后，任何拿到程序的人都能取出它。",
        text_en: "The file contains the opening marker of a {kind}. A private key shipped with a program can be extracted by anyone who has the program.",
    },
];

impl Analyzer for Content {
    fn id(&self) -> &'static str {
        "content"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if let Some(extension) = file.extension()
            && EXECUTABLE_MIMES.contains(&file.mime())
            && HARMLESS_EXTENSIONS.contains(&extension.as_str())
            && let Ok(bytes) = tree.read(&file.path)
        {
            let magic = &bytes[..bytes.len().min(16)];
            out.finding(
                // The header bytes are read directly, and the rule is a fixed comparison.
                Finding::new(Section::Anomalies, "content", "content.executable-disguised", Confidence::Derived, Severity::High)
                    .param("extension", extension)
                    .param("mime", file.mime())
                    .evidence(Evidence::bytes(file, 0, magic.len() as u64, hex::encode(magic))),
            );
        }
        if let Some(entropy) = file.entropy
            && entropy >= HIGH_ENTROPY
            && file.size >= HIGH_ENTROPY_MIN_SIZE
            && file.mime() == "application/octet-stream"
        {
            out.finding(
                Finding::new(Section::Anomalies, "content", "content.high-entropy", Confidence::Heuristic, Severity::Info)
                    .param("entropy", entropy)
                    .evidence(Evidence::whole(file, entropy)),
            );
        }
        // A container's content is examined through its children; its own bytes are compressed.
        if file.unpacked_by.is_some() {
            return;
        }
        let Ok(bytes) = tree.read(&file.path) else { return };
        // A similarity digest: files that differ a little get digests that differ a little.
        if file.size <= TLSH_MAX
            && let Some(tlsh) = tlsh2::TlshDefaultBuilder::build_from(&bytes)
        {
            out.fact(file, "content.tlsh", String::from_utf8_lossy(&tlsh.hash()).into_owned());
        }
        let found = urls::find(&bytes);
        if !found.urls.is_empty() {
            out.fact(file, "content.urls", json!({ "urls": found.urls, "truncated": found.truncated }));
        }
        secrets::find(file, &bytes, out);
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        // host -> (distinct URLs, files mentioning it)
        let mut hosts: BTreeMap<String, (std::collections::BTreeSet<&str>, Vec<&Artifact>)> = BTreeMap::new();
        let mut files = 0u64;
        for artifact in tree.artifacts() {
            let Some(urls) = artifact.facts.get("content.urls").and_then(|f| f.get("urls")).and_then(Value::as_array) else { continue };
            files += 1;
            for url in urls.iter().filter_map(Value::as_str) {
                let Some(host) = urls::host(url) else { continue };
                let entry = hosts.entry(host).or_default();
                entry.0.insert(url);
                if entry.1.last().is_none_or(|last| last.path != artifact.path) {
                    entry.1.push(artifact);
                }
            }
        }
        if hosts.is_empty() {
            return;
        }
        let total_urls: usize = hosts.values().map(|(urls, _)| urls.len()).sum();
        let listed: Vec<Value> = hosts
            .iter()
            .take(SUMMARY_HOSTS)
            .map(|(host, (urls, files))| {
                json!({
                    "host": host,
                    "urls": urls.len(),
                    "files": files.len(),
                    "sample_files": files.iter().take(3).map(|a| a.path.as_str()).collect::<Vec<_>>(),
                    "namespace": urls::is_namespace_host(host),
                })
            })
            .collect();
        out.summary("content.hosts", json!({ "hosts": listed, "total": hosts.len(), "truncated": hosts.len() > SUMMARY_HOSTS }));
        let mut finding = Finding::new(Section::Network, "content", "content.hosts", Confidence::Verified, Severity::Info)
            .param("hosts", hosts.len())
            .param("urls", total_urls)
            .param("files", files);
        // A few examples as evidence; the summary fact and the per-file facts hold the rest.
        for (host, (_, files)) in hosts.iter().filter(|(host, _)| !urls::is_namespace_host(host)).take(10) {
            if let Some(file) = files.first() {
                finding = finding.evidence(Evidence::whole(file, host.as_str()));
            }
        }
        out.finding(finding);
    }
}
