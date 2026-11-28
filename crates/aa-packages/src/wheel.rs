//! Python wheel declarations. No Python module, entry point or installer is loaded.
use crate::{MAX_FIELD, MAX_FIELDS, MAX_TEXT, Result, inventory, members, read_text, scalar};
use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub struct Wheel;
const RULES: &[Rule] = &[
    Rule {
        id: "wheel.identity",
        title_en: "Declared Python wheel identity",
        title_zh: "Python wheel 身份声明",
        text_en: "Captured wheel metadata declares {name} {version}. This is a distribution declaration, not an installed-state or import check.",
        text_zh: "已捕获的 wheel 元数据声明了 {name} {version}。这是分发包声明，没有检查安装状态或导入模块。",
    },
    Rule {
        id: "wheel.dependencies",
        title_en: "Wheel dependency declarations",
        title_zh: "Wheel 依赖声明",
        text_en: "The metadata contains {count} declarations of Requires-Dist. Version ranges, extras and environment markers remain literal; no dependency or environment resolution was performed.",
        text_zh: "元数据包含 {count} 个 Requires-Dist 声明。版本范围、附加项和环境标记按字面保留，没有解析依赖或运行环境。",
    },
    Rule {
        id: "wheel.entry-points",
        title_en: "Declared Python entry points",
        title_zh: "Python 入口点声明",
        text_en: "The wheel contains {count} declarations of entry points. Targets remain source data and were not imported, called or resolved to runtime objects.",
        text_zh: "Wheel 包含 {count} 个入口点声明。目标仍为源数据，没有导入、调用或解析为运行时对象。",
    },
    Rule {
        id: "wheel.package-unread",
        title_en: "Wheel metadata could not be established",
        title_zh: "无法确定 wheel 元数据",
        text_en: "A wheel candidate has missing, ambiguous, malformed or unsupported metadata, or its captured namespace is incomplete.",
        text_zh: "Wheel 候选项缺少元数据、元数据不唯一、格式错误或不受支持，或已捕获命名空间不完整。",
    },
    Rule {
        id: "wheel.inventory-truncated",
        title_en: "Wheel inventory reached its limit",
        title_zh: "Wheel 清单达到上限",
        text_en: "Only the bounded inventory preview is listed; captured artifact bytes remain available in the report tree.",
        text_zh: "仅列出受限的清单预览，已捕获的制品字节仍可在报告树中查看。",
    },
    Rule {
        id: "wheel.integrity-unverified",
        title_en: "Wheel authenticity and RECORD checks remain unresolved",
        title_zh: "Wheel 来源真实性与 RECORD 校验未确定",
        text_en: "RECORD, signature declarations and installer compatibility were not verified. Python source, bytecode, .pth files, entry-point effects and metadata description bodies were not executed or interpreted.",
        text_zh: "没有验证 RECORD、签名声明或安装器兼容性。没有执行或解释 Python 源码、字节码、.pth 文件、入口点效果或元数据描述正文。",
    },
];

#[derive(Clone)]
struct Header {
    name: String,
    value: String,
    offset: usize,
    length: usize,
    line: usize,
}
fn headers(text: &str) -> Result<Vec<Header>> {
    let mut fields: Vec<Header> = Vec::new();
    let mut offset = 0;
    for (line_number, line) in text.split_inclusive('\n').enumerate() {
        if line.len() > MAX_FIELD {
            return Err("wheel header line exceeds 16 KiB".into());
        }
        let raw = line.trim_end_matches(['\r', '\n']);
        if raw.is_empty() {
            break;
        }
        if raw.starts_with([' ', '\t']) {
            let last = fields.last_mut().ok_or("wheel header continuation has no preceding field")?;
            if last.value.len() + raw.len() + 1 > MAX_FIELD {
                return Err("unfolded wheel header exceeds 16 KiB".into());
            }
            last.value.push(' ');
            last.value.push_str(raw.trim_start_matches([' ', '\t']));
            last.length += line.len();
        } else {
            if fields.len() >= MAX_FIELDS {
                return Err("wheel metadata field count exceeds 8192".into());
            }
            let (name, value) = raw.split_once(':').ok_or("wheel header has no colon")?;
            if name.is_empty() || name.len() > 128 || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
                return Err("invalid wheel header name".into());
            }
            fields.push(Header {
                name: name.into(),
                value: value.trim_matches([' ', '\t']).into(),
                offset,
                length: line.len(),
                line: line_number + 1,
            });
        }
        offset += line.len();
    }
    Ok(fields)
}
fn one(fields: &[Header], name: &str) -> Result<String> {
    let values: Vec<_> = fields.iter().filter(|field| field.name.eq_ignore_ascii_case(name)).collect();
    let [field] = values.as_slice() else {
        return Err(format!("wheel scalar {name} is missing or repeated"));
    };
    scalar(&field.value)
}
fn supported_version(value: &str, major: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 2
        && parts[0] == major
        && !parts[1].is_empty()
        && parts[1].len() <= 5
        && parts[1].bytes().all(|byte| byte.is_ascii_digit())
}
fn fields_json(fields: &[Header]) -> Result<Value> {
    Ok(Value::Array(
        fields
            .iter()
            .map(|field| {
                Ok(json!({"name":field.name,"value":aa_core::text::redact_sensitive_text(&field.value).map_err(str::to_string)?,
        "utf8_offset":field.offset,"length":field.length,"line":field.line}))
            })
            .collect::<Result<_>>()?,
    ))
}
fn entry_points(text: &str) -> Result<Vec<Value>> {
    let mut group = None;
    let mut groups = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut rows = Vec::new();
    let mut offset = 0;
    for (line_number, line) in text.split_inclusive('\n').enumerate() {
        if line.len() > MAX_FIELD {
            return Err("wheel entry-point line exceeds 16 KiB".into());
        }
        let raw = line.trim();
        if raw.is_empty() || raw.starts_with(['#', ';']) {
            offset += line.len();
            continue;
        }
        if line.starts_with([' ', '\t']) {
            return Err("indented wheel entry-point continuations are outside the supported literal profile".into());
        }
        if let Some(name) = raw.strip_prefix('[').and_then(|raw| raw.strip_suffix(']')) {
            let name = scalar(name)?;
            if !groups.insert(name.clone()) {
                return Err("repeated wheel entry-point group".into());
            }
            group = Some(name);
        } else {
            let group = group.as_ref().ok_or("wheel entry point has no group")?;
            let (name, value) = raw.split_once('=').ok_or("wheel entry point has no equals sign")?;
            let name = scalar(name.trim())?;
            let value = scalar(value.trim())?;
            if !keys.insert((group.clone(), name.clone())) || rows.len() >= MAX_FIELDS {
                return Err("duplicate wheel entry-point key or count budget exhausted".into());
            }
            rows.push(json!({"group":group,"name":name,"target":value,"utf8_offset":offset,"length":line.len(),"line":line_number+1,"runtime_target_resolved":false}));
        }
        offset += line.len();
    }
    Ok(rows)
}

fn analyze(tree: &dyn Tree, container: &Artifact, out: &mut Output) -> Result<()> {
    let files = members(tree, container)?;
    let roots: BTreeSet<_> = files
        .keys()
        .filter_map(|path| path.split_once('/').filter(|(root, _)| root.ends_with(".dist-info")).map(|(root, _)| root))
        .collect();
    if roots.len() != 1 {
        return Err("wheel must contain exactly one root dist-info directory".into());
    }
    let root = roots.first().ok_or("wheel dist-info root missing")?.to_string();
    let wheel = *files.get(format!("{root}/WHEEL").as_str()).ok_or("wheel has no root WHEEL metadata")?;
    let metadata = *files.get(format!("{root}/METADATA").as_str()).ok_or("wheel has no root METADATA")?;
    let wheel_headers = headers(&read_text(tree, wheel, MAX_TEXT)?)?;
    let metadata_headers = headers(&read_text(tree, metadata, MAX_TEXT)?)?;
    let wheel_version = one(&wheel_headers, "Wheel-Version")?;
    if !supported_version(&wheel_version, "1") {
        return Err("only numeric Wheel-Version 1.x is interpreted".into());
    }
    let metadata_version = one(&metadata_headers, "Metadata-Version")?;
    if !supported_version(&metadata_version, "2") {
        return Err("only numeric Core Metadata 2.x is interpreted".into());
    }
    let name = one(&metadata_headers, "Name")?;
    let version = one(&metadata_headers, "Version")?;
    if !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) {
        return Err("wheel distribution name is outside the literal identity profile".into());
    }
    let purelib = one(&wheel_headers, "Root-Is-Purelib")?;
    if !matches!(purelib.as_str(), "true" | "false") {
        return Err("invalid Root-Is-Purelib declaration".into());
    }
    let tags: Vec<_> = wheel_headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("Tag"))
        .map(|field| scalar(&field.value))
        .collect::<Result<_>>()?;
    if tags.is_empty() {
        return Err("wheel declares no compatibility tags".into());
    }
    let dependencies: Vec<_> = metadata_headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("Requires-Dist"))
        .map(|field| {
            Ok(json!({
        "declaration":scalar(&field.value)?,"utf8_offset":field.offset,"length":field.length,"line":field.line,"markers_evaluated":false}))
        })
        .collect::<Result<_>>()?;
    let entry_file = files.get(format!("{root}/entry_points.txt").as_str()).copied();
    let points = entry_file.map(|file| read_text(tree, file, MAX_TEXT).and_then(|text| entry_points(&text))).transpose()?;
    let contents = inventory(&files);
    if contents["truncated"] == true {
        out.limitation("wheel.inventory-truncated", Some(container), None);
    }
    out.kind(container, "wheel");
    out.fact(container,"wheel.package",json!({"name":name,"version":version,"source_metadata":metadata.path,"source_wheel":wheel.path,
        "wheel_version":wheel_version,"metadata_version":metadata_version,"root_is_purelib":purelib=="true","tags":tags,
        "metadata_headers":fields_json(&metadata_headers)?,"wheel_headers":fields_json(&wheel_headers)?,"dependencies":dependencies,
        "entry_points":points,"source_entry_points":entry_file.map(|file|&file.path),"inventory":contents,"record_verified":false,"runtime_effects_established":false}));
    out.finding(
        Finding::new(Section::Identity, "wheel", "wheel.identity", Confidence::Verified, Severity::Info)
            .param("name", name.as_str())
            .param("version", version.as_str())
            .evidence(Evidence::field(metadata, "Core Metadata Name/Version", json!({"name":name,"version":version}))),
    );
    if !dependencies.is_empty() {
        out.finding(
            Finding::new(Section::Composition, "wheel", "wheel.dependencies", Confidence::Verified, Severity::Info)
                .param("count", dependencies.len())
                .evidence(Evidence::field(metadata, "Requires-Dist", json!(dependencies))),
        );
    }
    if let (Some(file), Some(points)) = (entry_file, points.as_ref())
        && !points.is_empty()
    {
        out.finding(
            Finding::new(Section::Capabilities, "wheel", "wheel.entry-points", Confidence::Verified, Severity::Info)
                .param("count", points.len())
                .evidence(Evidence::bytes(file, 0, file.size, json!(points))),
        );
    }
    out.limitation("wheel.integrity-unverified", Some(container), None);
    Ok(())
}
impl Analyzer for Wheel {
    fn id(&self) -> &'static str {
        "wheel"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let candidates: BTreeSet<_> = tree
            .artifacts()
            .iter()
            .filter(|member| member.path.ends_with(".dist-info/WHEEL"))
            .filter_map(|member| member.parent.as_deref())
            .collect();
        for (index, file) in tree
            .artifacts()
            .iter()
            .filter(|file| {
                file.unpacked_by.as_deref() == Some("zip")
                    && (file.extension().as_deref() == Some("whl") || candidates.contains(file.path.as_str()))
            })
            .enumerate()
        {
            if index >= crate::MAX_PACKAGES {
                out.limitation("wheel.package-unread", None, Some("wheel candidate count exceeds 256".into()));
                break;
            }
            if let Err(error) = analyze(tree, file, out) {
                out.limitation("wheel.package-unread", Some(file), Some(error));
            }
        }
        for file in
            tree.artifacts().iter().filter(|file| file.extension().as_deref() == Some("whl") && file.unpacked_by.as_deref() != Some("zip"))
        {
            out.limitation("wheel.package-unread", Some(file), Some("wheel ZIP contents were not captured".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::Fixture;
    fn fixture() -> Fixture {
        let mut tree = Fixture::new("demo.whl", "zip");
        tree.add("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n");
        tree.add("demo-1.0.dist-info/METADATA",b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nRequires-Dist: extra>=2; python_version < '4'\n\nDescription: never another header\n");
        tree.add("demo/__init__.py", b"raise RuntimeError('never imported')\n");
        tree
    }
    #[test]
    fn literal_metadata_markers_and_entry_points_have_source_evidence() {
        let mut tree = fixture();
        tree.add("demo-1.0.dist-info/entry_points.txt", b"[console_scripts]\ndemo = demo:main [extra]\n");
        let mut out = Output::default();
        Wheel.analyze_tree(&tree, &mut out);
        assert_eq!(out.findings.len(), 3);
        let fact = &out.facts[0].value;
        assert_eq!(fact["name"], "demo");
        assert_eq!(fact["dependencies"][0]["markers_evaluated"], false);
        assert_eq!(fact["entry_points"][0]["target"], "demo:main [extra]");
        assert_eq!(fact["inventory"]["total"], 4);
        assert!(out.findings.iter().all(|finding| !finding.evidence.is_empty()));
    }
    #[test]
    fn duplicate_scalar_dist_info_and_normalized_members_prevent_identity() {
        for mode in ["duplicate", "two-roots", "collision", "partial"] {
            let mut tree = fixture();
            if mode == "duplicate" {
                tree.replace("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.1\nName: demo\nName: other\nVersion: 1\n");
            }
            if mode == "two-roots" {
                tree.add("other-1.dist-info/WHEEL", b"Wheel-Version: 1.0\n");
            }
            if mode == "collision" {
                tree.files.last_mut().expect("member").facts.insert("engine.entry-name".into(), json!({"colliding":true}));
            }
            if mode == "partial" {
                tree.files[0].facts.insert("engine.container-listing".into(), json!({"complete":false}));
            }
            let mut out = Output::default();
            Wheel.analyze_tree(&tree, &mut out);
            assert!(out.findings.is_empty(), "{mode}");
            assert!(out.limitations.iter().any(|limit| limit.code == "wheel.package-unread"), "{mode}");
        }
    }
    #[test]
    fn malformed_headers_groups_and_budgets_are_explicit() {
        assert!(headers(" continuation\n").is_err());
        assert!(headers(&format!("Name: {}\n", "a".repeat(MAX_FIELD))).is_err());
        assert!(entry_points("[console_scripts]\na=x\na=y\n").is_err());
        assert!(entry_points("[a]\nx=y\n[a]\nz=q\n").is_err());
        assert!(
            entry_points("[console_scripts]\na=one:main\n b=two:main\n").is_err(),
            "a continuation cannot become a new verified entry point"
        );
        assert!(!supported_version("1.evil", "1"));
        assert!(!supported_version("2.bad", "2"));
        assert!(!supported_version("1.0.0", "1"));
        let mut tree = fixture();
        tree.add("demo-1.0.dist-info/entry_points.txt", &[b'x'; MAX_TEXT + 1]);
        let mut out = Output::default();
        Wheel.analyze_tree(&tree, &mut out);
        assert!(out.limitations.iter().any(|limit| limit.code == "wheel.package-unread"));
        assert!(out.findings.is_empty());
    }
    #[test]
    fn published_mit_sampleproject_wheel_reads_real_metadata_and_inventory() {
        let bytes = include_bytes!("../tests/data/wheel/sampleproject-4.0.0-py3-none-any.whl");
        assert_eq!(aa_core::sha256_hex(bytes), "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b");
        let tree = Fixture::zip("sampleproject.whl", bytes);
        let mut out = Output::default();
        Wheel.analyze_tree(&tree, &mut out);
        let fact = &out.facts[0].value;
        assert_eq!(fact["name"], "sampleproject");
        assert_eq!(fact["version"], "4.0.0");
        assert_eq!(fact["tags"], json!(["py3-none-any"]));
        assert_eq!(fact["entry_points"][0]["name"], "sample");
        assert!(
            fact["dependencies"]
                .as_array()
                .expect("dependencies")
                .iter()
                .any(|dependency| dependency["declaration"].as_str().expect("literal dependency").starts_with("peppercorn"))
        );
        let reference: Value = serde_json::from_str(include_str!("../tests/data/native.ref.json")).expect("native package references");
        let record = reference["records"]
            .as_array()
            .expect("native records")
            .iter()
            .find(|record| record["kind"] == "wheel")
            .expect("wheel reference");
        let actual: Vec<_> = fact["inventory"]["members"]
            .as_array()
            .expect("inventory")
            .iter()
            .map(|row| json!({"path":row["path"],"size":row["size"],"sha256":row["sha256"]}))
            .collect();
        assert_eq!(json!(actual), record["members"], "all members agree with independent ZIP/native jar listing");
    }
}
