//! The words of a report, in each language.

use aa_core::{Confidence, Finding, InputKind, Limitation, Severity};
use serde_json::Value;

use crate::Lang;

pub struct Words {
    pub title: &'static str,
    pub tool: &'static str,
    pub input_sha256: &'static str,
    pub summary: &'static str,
    pub input: &'static str,
    pub files: &'static str,
    pub bytes_read: &'static str,
    pub findings: &'static str,
    pub none: &'static str,
    pub inventory: &'static str,
    pub path: &'static str,
    pub size: &'static str,
    pub kind: &'static str,
    pub entropy: &'static str,
    pub confidence: &'static str,
    pub evidence: &'static str,
    pub finding_id: &'static str,
    pub coverage: &'static str,
    pub complete: &'static str,
    pub truncated: &'static str,
    pub limitations: &'static str,
    pub no_limitations: &'static str,
    pub unknown: &'static str,
    /// For a value that does not exist for this input, as opposed to one that could not be read.
    pub not_applicable: &'static str,
}

pub fn words(lang: Lang) -> Words {
    match lang {
        Lang::Zh => Words {
            title: "分析报告",
            tool: "工具",
            input_sha256: "输入 SHA-256",
            summary: "摘要",
            input: "输入",
            files: "文件数",
            bytes_read: "已读取字节",
            findings: "结论",
            none: "没有发现需要报告的结论。这只代表已启用的规则没有命中，不代表输入没有问题。",
            inventory: "文件清单",
            path: "路径",
            size: "大小（字节）",
            kind: "识别类型",
            entropy: "熵",
            confidence: "置信度",
            evidence: "证据",
            finding_id: "结论 ID",
            coverage: "覆盖度与局限",
            complete: "列出的文件全部读取完毕。",
            truncated: "分析提前停止，下面的局限说明了原因。未读取的部分没有任何结论。",
            limitations: "局限",
            no_limitations: "没有记录到局限。",
            unknown: "未知",
            not_applicable: "不适用（输入是文件夹，各文件的哈希见文件清单）",
        },
        Lang::En => Words {
            title: "Analysis report",
            tool: "Tool",
            input_sha256: "Input SHA-256",
            summary: "Summary",
            input: "Input",
            files: "Files",
            bytes_read: "Bytes read",
            findings: "Findings",
            none: "Nothing to report. This means no enabled rule matched, not that the input is free of problems.",
            inventory: "File inventory",
            path: "Path",
            size: "Size (bytes)",
            kind: "Detected type",
            entropy: "Entropy",
            confidence: "Confidence",
            evidence: "Evidence",
            finding_id: "Finding ID",
            coverage: "Coverage and limitations",
            complete: "Every listed file was read in full.",
            truncated: "The analysis stopped early; the limitations below say why. Nothing is concluded about what was not read.",
            limitations: "Limitations",
            no_limitations: "No limitations were recorded.",
            unknown: "unknown",
            not_applicable: "not applicable (the input is a folder; each file's digest is in the inventory)",
        },
    }
}

pub fn input_kind(lang: Lang, kind: InputKind) -> &'static str {
    match (lang, kind) {
        (Lang::Zh, InputKind::File) => "单个文件",
        (Lang::Zh, InputKind::Directory) => "文件夹",
        (Lang::En, InputKind::File) => "single file",
        (Lang::En, InputKind::Directory) => "folder",
    }
}

pub fn severity(lang: Lang, severity: Severity) -> &'static str {
    match (lang, severity) {
        (Lang::Zh, Severity::Info) => "提示",
        (Lang::Zh, Severity::Low) => "低",
        (Lang::Zh, Severity::Medium) => "中",
        (Lang::Zh, Severity::High) => "高",
        (Lang::En, Severity::Info) => "Info",
        (Lang::En, Severity::Low) => "Low",
        (Lang::En, Severity::Medium) => "Medium",
        (Lang::En, Severity::High) => "High",
    }
}

pub fn confidence(lang: Lang, confidence: Confidence) -> &'static str {
    match (lang, confidence) {
        (Lang::Zh, Confidence::Verified) => "已验证（直接读取）",
        (Lang::Zh, Confidence::Derived) => "推导（由已读取的事实确定得出）",
        (Lang::Zh, Confidence::Heuristic) => "启发式（规则猜测，可能误报）",
        (Lang::En, Confidence::Verified) => "Verified (read directly)",
        (Lang::En, Confidence::Derived) => "Derived (follows from what was read)",
        (Lang::En, Confidence::Heuristic) => "Heuristic (a rule's guess; may be wrong)",
    }
}

fn param(finding: &Finding, name: &str) -> String {
    match finding.params.get(name) {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => "?".to_string(),
    }
}

/// The sentence for a finding. A rule without text yet is shown by its id, never dropped.
pub fn finding(lang: Lang, finding: &Finding) -> String {
    let p = |name| param(finding, name);
    match (finding.rule.as_str(), lang) {
        ("content.executable-disguised", Lang::Zh) => {
            format!("文件扩展名是 .{}，但内容是可执行程序（{}）。扩展名与内容不符，打开时可能被当作程序运行。", p("extension"), p("mime"))
        }
        ("content.executable-disguised", Lang::En) => format!(
            "The file is named .{} but its content is an executable program ({}). The name does not match the content.",
            p("extension"),
            p("mime")
        ),
        ("content.high-entropy", Lang::Zh) => {
            format!("文件类型无法识别，且熵为 {}（上限 8）。这类数据通常是压缩、加密或加壳后的内容。", p("entropy"))
        }
        ("content.high-entropy", Lang::En) => format!(
            "The file type is not recognised and its entropy is {} (of 8). Data like this is usually compressed, encrypted or packed.",
            p("entropy")
        ),
        (rule, _) => rule.to_string(),
    }
}

/// The sentence for a limitation. An unknown code is shown as it is.
pub fn limitation(lang: Lang, limitation: &Limitation) -> String {
    let text = match (limitation.code.as_str(), lang) {
        ("read_failed", Lang::Zh) => "无法读取，未分析",
        ("read_failed", Lang::En) => "Could not be read; not analyzed",
        ("symlink_skipped", Lang::Zh) => "是符号链接，按安全策略不跟随",
        ("symlink_skipped", Lang::En) => "Is a symbolic link; links are not followed",
        ("special_file_skipped", Lang::Zh) => "不是普通文件（设备、管道等），已跳过",
        ("special_file_skipped", Lang::En) => "Is not a regular file (device, pipe, …); skipped",
        ("limit_reached", Lang::Zh) => "达到限额，其余部分未分析",
        ("limit_reached", Lang::En) => "A limit was reached; the rest was not analyzed",
        ("cancelled", Lang::Zh) => "分析被取消，其余部分未分析",
        ("cancelled", Lang::En) => "The run was cancelled; the rest was not analyzed",
        (code, _) => code,
    };
    text.to_string()
}
