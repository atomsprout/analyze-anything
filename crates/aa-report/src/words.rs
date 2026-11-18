//! The fixed words of a report, in each language. Everything about a specific rule comes from
//! the report's own rule texts instead.

use aa_core::{Confidence, InputKind, Section, Severity};

use crate::Lang;

pub struct Words {
    pub title: &'static str,
    pub tool: &'static str,
    pub input_sha256: &'static str,
    pub summary: &'static str,
    pub input: &'static str,
    pub artifacts: &'static str,
    pub containers: &'static str,
    pub bytes_read: &'static str,
    pub findings: &'static str,
    pub by_severity: &'static str,
    pub no_findings_here: &'static str,
    pub inventory: &'static str,
    pub path: &'static str,
    pub size: &'static str,
    pub kind: &'static str,
    pub entropy: &'static str,
    pub confidence: &'static str,
    pub evidence: &'static str,
    pub references: &'static str,
    pub finding_id: &'static str,
    pub coverage: &'static str,
    pub complete: &'static str,
    pub truncated: &'static str,
    pub no_limitations: &'static str,
    pub unknown: &'static str,
    /// For a value that does not exist for this input, as opposed to one that could not be read.
    pub not_applicable: &'static str,
    pub affected: &'static str,
    pub whole_run: &'static str,
    pub reading_guide: &'static str,
    pub reading_guide_text: &'static str,
}

pub fn words(lang: Lang) -> Words {
    match lang {
        Lang::Zh => Words {
            title: "分析报告",
            tool: "工具",
            input_sha256: "输入 SHA-256",
            summary: "摘要",
            input: "输入",
            artifacts: "已分析文件 / 全部文件（含解包得到的）",
            containers: "已解包的容器",
            bytes_read: "已读取字节",
            findings: "结论数",
            by_severity: "按严重度",
            no_findings_here: "本章没有结论。这只代表已启用的检查没有命中，不代表不存在相关内容。",
            inventory: "文件清单",
            path: "路径",
            size: "大小（字节）",
            kind: "类型",
            entropy: "熵",
            confidence: "置信度",
            evidence: "证据",
            references: "对应标准",
            finding_id: "结论 ID",
            coverage: "覆盖度与局限",
            complete: "树中的文件全部读取完毕。",
            truncated: "分析提前停止或有内容被跳过，下面的局限说明了原因。没有读到的部分没有任何结论。",
            no_limitations: "没有记录到局限。",
            unknown: "未知",
            not_applicable: "不适用（输入是文件夹，各文件的哈希见文件清单）",
            affected: "涉及",
            whole_run: "整次分析",
            reading_guide: "如何阅读",
            reading_guide_text: "每条结论都标有置信度：“已验证”是直接从文件结构读出或经密码学校验的；“推导”是由已读出的事实按固定规则得出的；“启发式”是规则匹配的猜测，可能误报。严重度为“提示”的条目是中性事实，不是问题。",
        },
        Lang::En => Words {
            title: "Analysis report",
            tool: "Tool",
            input_sha256: "Input SHA-256",
            summary: "Summary",
            input: "Input",
            artifacts: "Files analyzed / all files (unpacked ones included)",
            containers: "Containers unpacked",
            bytes_read: "Bytes read",
            findings: "Findings",
            by_severity: "By severity",
            no_findings_here: "No findings in this chapter. This means no enabled check matched, not that nothing of the kind exists.",
            inventory: "File inventory",
            path: "Path",
            size: "Size (bytes)",
            kind: "Type",
            entropy: "Entropy",
            confidence: "Confidence",
            evidence: "Evidence",
            references: "Standards",
            finding_id: "Finding ID",
            coverage: "Coverage and limitations",
            complete: "Every file in the tree was read in full.",
            truncated: "The analysis stopped early or skipped content; the limitations below say why. Nothing is concluded about what was not read.",
            no_limitations: "No limitations were recorded.",
            unknown: "unknown",
            not_applicable: "not applicable (the input is a folder; each file's digest is in the inventory)",
            affected: "Affects",
            whole_run: "the whole run",
            reading_guide: "How to read this",
            reading_guide_text: "Every finding states its confidence: \"Verified\" was read directly from a file structure or checked cryptographically; \"Derived\" follows from what was read by a fixed rule; \"Heuristic\" is a rule's guess and may be wrong. Entries with severity \"Info\" are neutral facts, not problems.",
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
        (Lang::Zh, Confidence::Verified) => "已验证",
        (Lang::Zh, Confidence::Derived) => "推导",
        (Lang::Zh, Confidence::Heuristic) => "启发式",
        (Lang::En, Confidence::Verified) => "Verified",
        (Lang::En, Confidence::Derived) => "Derived",
        (Lang::En, Confidence::Heuristic) => "Heuristic",
    }
}

pub fn section(lang: Lang, section: Section) -> &'static str {
    match (lang, section) {
        (Lang::Zh, Section::Overview) => "概览",
        (Lang::Zh, Section::Identity) => "身份",
        (Lang::Zh, Section::Provenance) => "来源与签名",
        (Lang::Zh, Section::Structure) => "结构",
        (Lang::Zh, Section::Composition) => "技术栈与组成",
        (Lang::Zh, Section::Capabilities) => "权限与能力",
        (Lang::Zh, Section::Hardening) => "安全加固",
        (Lang::Zh, Section::Network) => "网络与端点",
        (Lang::Zh, Section::Secrets) => "敏感信息",
        (Lang::Zh, Section::Privacy) => "隐私",
        (Lang::Zh, Section::Code) => "代码洞察",
        (Lang::Zh, Section::Anomalies) => "异常与可疑点",
        (Lang::En, Section::Overview) => "Overview",
        (Lang::En, Section::Identity) => "Identity",
        (Lang::En, Section::Provenance) => "Provenance and signing",
        (Lang::En, Section::Structure) => "Structure",
        (Lang::En, Section::Composition) => "Technology and composition",
        (Lang::En, Section::Capabilities) => "Permissions and capabilities",
        (Lang::En, Section::Hardening) => "Hardening",
        (Lang::En, Section::Network) => "Network and endpoints",
        (Lang::En, Section::Secrets) => "Secrets",
        (Lang::En, Section::Privacy) => "Privacy",
        (Lang::En, Section::Code) => "Code insight",
        (Lang::En, Section::Anomalies) => "Anomalies",
    }
}
