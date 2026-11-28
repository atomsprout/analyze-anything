//! Literal npm tarball metadata and original TAR declarations, without lifecycle execution.
use crate::{MAX_TEXT, Result, inventory, members, read_text, redacted, scalar, unique_json};
use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub struct Npm;
const RULES: &[Rule] = &[
    Rule {
        id: "npm.identity",
        title_en: "Declared npm package identity",
        title_zh: "npm 软件包身份声明",
        text_en: "The captured canonical package/package.json declares {name} {version}. The package was not installed or loaded.",
        text_zh: "已捕获的规范路径 package/package.json 声明了 {name} {version}。没有安装或加载软件包。",
    },
    Rule {
        id: "npm.dependencies",
        title_en: "npm dependency declarations",
        title_zh: "npm 依赖声明",
        text_en: "The package declares {count} dependencies across supported dependency groups. Ranges, URLs, aliases and platform constraints remain literal and were not resolved.",
        text_zh: "软件包在受支持的依赖分组中声明了 {count} 个依赖。范围、网址、别名和平台约束按字面保留，没有进行解析。",
    },
    Rule {
        id: "npm.scripts",
        title_en: "Declared npm lifecycle scripts",
        title_zh: "npm 生命周期脚本声明",
        text_en: "The package contains {count} declarations in scripts. Redacted command text is evidence; no lifecycle, shell control flow or runtime effect was evaluated.",
        text_zh: "软件包声明了 {count} 个脚本。遮盖敏感信息后的命令文本作为证据，没有求值生命周期、Shell 控制流或运行时效果。",
    },
    Rule {
        id: "npm.package-unread",
        title_en: "npm package metadata could not be established",
        title_zh: "无法确定 npm 软件包元数据",
        text_en: "The canonical package metadata or archive namespace is missing, ambiguous, malformed or outside the bounded supported profile.",
        text_zh: "规范软件包元数据或归档命名空间缺失、不唯一、格式错误或超出受限支持范围。",
    },
    Rule {
        id: "npm.archive-semantics",
        title_en: "npm link and package layout declarations remain unresolved",
        title_zh: "npm 链接与软件包布局声明未确定",
        text_en: "TAR links, special entries or paths outside package/ remain declarations. Targets were not followed and installation layout was not established.",
        text_zh: "TAR 链接、特殊条目或 package/ 以外的路径仍为声明。没有跟随目标，也没有确定安装布局。",
    },
    Rule {
        id: "npm.inventory-truncated",
        title_en: "npm inventory reached its limit",
        title_zh: "npm 清单达到上限",
        text_en: "The bounded inventory preview omitted some captured members; the report artifact tree retains captured files.",
        text_zh: "受限清单预览省略了部分已捕获成员，报告制品树仍保留已捕获文件。",
    },
    Rule {
        id: "npm.runtime-unresolved",
        title_en: "npm runtime and package authenticity remain unresolved",
        title_zh: "npm 运行时与软件包来源真实性未确定",
        text_en: "Package signatures, registry attestations and installation eligibility were not verified. JavaScript, module resolution, entry points, lifecycle invocation and effective platform behavior were not evaluated.",
        text_zh: "没有验证软件包签名、注册表证明或安装适用性。没有求值 JavaScript、模块解析、入口点、生命周期调用或实际平台行为。",
    },
];

fn range(bytes: &[u8], at: usize, length: usize) -> Result<&[u8]> {
    bytes.get(at..at.checked_add(length).ok_or("npm TAR extent overflow")?).ok_or_else(|| "npm TAR extent exceeds captured bytes".into())
}
fn text(bytes: &[u8]) -> Result<&str> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("TAR name contains bytes after NUL".into());
    }
    std::str::from_utf8(&bytes[..end]).map_err(|_| "npm TAR name is not UTF-8".into())
}
fn octal(bytes: &[u8]) -> Result<u64> {
    let value = std::str::from_utf8(bytes).map_err(|_| "npm TAR integer is not ASCII")?.trim_matches([' ', '\0']);
    if value.is_empty() {
        return Ok(0);
    }
    if !value.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return Err("npm TAR numeric encoding is outside the octal profile".into());
    }
    u64::from_str_radix(value, 8).map_err(|_| "npm TAR integer exceeds u64".into())
}
fn archive(bytes: &[u8]) -> Result<Vec<Value>> {
    if bytes.len() > 256 * 1024 * 1024 {
        return Err("npm TAR metadata profile is limited to 256 MiB captured TAR bytes".into());
    }
    let mut at = 0usize;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut path_bytes = 0usize;
    loop {
        let header = range(bytes, at, 512)?;
        if header.iter().all(|byte| *byte == 0) {
            if range(bytes, at + 512, 512)?.iter().any(|byte| *byte != 0) || bytes[at + 1024..].iter().any(|byte| *byte != 0) {
                return Err("concatenated or nonzero trailing npm TAR data is outside the profile".into());
            }
            return Ok(entries);
        }
        if entries.len() >= 100_000 {
            return Err("npm TAR member count exceeds 100000".into());
        }
        let checksum = octal(&header[148..156])?;
        let observed: u64 =
            header.iter().enumerate().map(|(index, byte)| if (148..156).contains(&index) { 32 } else { u64::from(*byte) }).sum();
        if checksum != observed {
            return Err("npm TAR header checksum mismatch".into());
        }
        let kind = header[156];
        if !matches!(kind, 0 | b'0' | b'1' | b'2' | b'3' | b'4' | b'5' | b'6') {
            return Err("npm TAR extended/PAX/sparse metadata is outside the initial profile".into());
        }
        let name = text(&header[..100])?;
        let prefix = if &header[257..262] == b"ustar" { text(&header[345..500])? } else { "" };
        let path = if prefix.is_empty() { name.into() } else { format!("{prefix}/{name}") };
        path_bytes += path.len();
        if path.is_empty() || path_bytes > 16 * 1024 * 1024 || !seen.insert(path.clone()) {
            return Err("npm TAR path is empty, duplicated or exceeds its aggregate budget".into());
        }
        let size = octal(&header[124..136])?;
        let stored = usize::try_from(size).map_err(|_| "npm TAR size exceeds address space")?;
        let start = at.checked_add(512).ok_or("npm TAR offset overflow")?;
        range(bytes, start, stored)?;
        let next = start
            .checked_add(stored)
            .and_then(|end| end.checked_add(511))
            .map(|end| end / 512 * 512)
            .ok_or("npm TAR padded extent overflow")?;
        range(bytes, start, next - start)?;
        entries.push(json!({"path":path,"type":match kind{0|b'0'=>"file",b'5'=>"directory",b'1'=>"hardlink",b'2'=>"symlink",_=>"special"},
            "header_offset":at,"offset":start,"size":size,"mode":octal(&header[100..108])?,"link_target":if matches!(kind,b'1'|b'2'){Some(text(&header[157..257])?)}else{None}}));
        at = next;
    }
}

fn declarations(value: &Value, key: &str) -> Result<Vec<Value>> {
    let Some(value) = value.get(key) else { return Ok(Vec::new()) };
    let object = value.as_object().ok_or_else(|| format!("npm {key} must be an object"))?;
    object.iter().map(|(name,value)|{
        let name=scalar(name)?;let value=value.as_str().ok_or_else(||format!("npm {key}/{name} must be a string"))?;
        Ok(json!({"name":name,"declaration":aa_core::text::redact_sensitive_text(value).map_err(str::to_string)?,"field":format!("{key}/{name}")}))
    }).collect()
}
fn analyze(tree: &dyn Tree, container: &Artifact, out: &mut Output) -> Result<()> {
    let files = members(tree, container)?;
    let control = *files.get("package/package.json").ok_or("canonical package/package.json is missing")?;
    let bytes = tree.read(&container.path).map_err(|error| error.to_string())?;
    let entries = archive(&bytes)?;
    let controls: Vec<_> = entries.iter().filter(|entry| entry["path"] == "package/package.json").collect();
    if controls.len() != 1 || controls[0]["type"] != "file" {
        return Err("canonical npm control is not one original regular TAR member".into());
    }
    let source = read_text(tree, control, MAX_TEXT)?;
    let offset = usize::try_from(controls[0]["offset"].as_u64().ok_or("npm control offset missing")?)
        .map_err(|_| "npm control offset exceeds address space")?;
    if controls[0]["size"].as_u64() != Some(source.len() as u64) || range(&bytes, offset, source.len())? != source.as_bytes() {
        return Err("captured npm control bytes disagree with the original canonical TAR member".into());
    }
    let value = unique_json(&source)?;
    if !value.is_object() {
        return Err("npm package.json is not an object".into());
    }
    let name = scalar(value["name"].as_str().ok_or("npm name is missing or not a string")?)?;
    let version = scalar(value["version"].as_str().ok_or("npm version is missing or not a string")?)?;
    if name.len() > 214 || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'/' | b'-' | b'_' | b'.')) {
        return Err("npm name is outside the literal identity profile".into());
    }
    let mut dependencies = Vec::new();
    for key in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        for mut row in declarations(&value, key)? {
            row["group"] = key.into();
            row["resolved"] = false.into();
            dependencies.push(row);
        }
    }
    let scripts = declarations(&value, "scripts")?;
    let mut selected = serde_json::Map::new();
    for key in [
        "main",
        "module",
        "type",
        "types",
        "typings",
        "bin",
        "exports",
        "imports",
        "engines",
        "os",
        "cpu",
        "license",
        "packageManager",
        "peerDependenciesMeta",
        "bundledDependencies",
        "bundleDependencies",
    ] {
        if let Some(value) = value.get(key) {
            selected.insert(key.into(), redacted(value)?);
        }
    }
    let contents = inventory(&files);
    if contents["truncated"] == true {
        out.limitation("npm.inventory-truncated", Some(container), None);
    }
    out.kind(container, "npm");
    out.fact(container,"npm.package",json!({"name":name,"version":version,"source_metadata":control.path,"dependencies":dependencies,
        "scripts":scripts,"declarations":selected,"archive_entries":entries,"inventory":contents,"runtime_effects_established":false,"package_authenticity_verified":false}));
    out.finding(
        Finding::new(Section::Identity, "npm", "npm.identity", Confidence::Verified, Severity::Info)
            .param("name", name.as_str())
            .param("version", version.as_str())
            .evidence(Evidence::field(control, "package.json/name,version", json!({"name":name,"version":version}))),
    );
    if !dependencies.is_empty() {
        out.finding(
            Finding::new(Section::Composition, "npm", "npm.dependencies", Confidence::Verified, Severity::Info)
                .param("count", dependencies.len())
                .evidence(Evidence::field(control, "package.json dependency groups", json!(dependencies))),
        );
    }
    if !scripts.is_empty() {
        out.finding(
            Finding::new(Section::Capabilities, "npm", "npm.scripts", Confidence::Verified, Severity::Info)
                .param("count", scripts.len())
                .evidence(Evidence::field(control, "package.json/scripts", json!(scripts))),
        );
    }
    if entries.iter().any(|entry| {
        !matches!(entry["type"].as_str(), Some("file" | "directory"))
            || !entry["path"].as_str().is_some_and(|path| path == "package" || path.starts_with("package/"))
    }) {
        out.limitation("npm.archive-semantics", Some(container), None);
    }
    out.limitation("npm.runtime-unresolved", Some(container), None);
    Ok(())
}
impl Analyzer for Npm {
    fn id(&self) -> &'static str {
        "npm"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let candidates: BTreeSet<_> = tree
            .artifacts()
            .iter()
            .filter(|file| file.path.ends_with("/package/package.json"))
            .filter_map(|file| file.parent.as_deref())
            .collect();
        for (index, file) in tree
            .artifacts()
            .iter()
            .filter(|file| file.unpacked_by.as_deref() == Some("tar") && candidates.contains(file.path.as_str()))
            .enumerate()
        {
            if index >= crate::MAX_PACKAGES {
                out.limitation("npm.package-unread", None, Some("npm candidate count exceeds 256".into()));
                break;
            }
            if let Err(error) = analyze(tree, file, out) {
                out.limitation("npm.package-unread", Some(file), Some(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::Fixture;
    use std::io::Write;
    fn fixture(control: &[u8]) -> Fixture {
        let mut writer = tar::Builder::new(Vec::new());
        for (name, data) in [("package/package.json", control), ("package/index.js", b"throw Error('never loaded');\n".as_slice())] {
            let mut header = tar::Header::new_ustar();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            writer.append_data(&mut header, name, data).expect("fixture member");
        }
        let bytes = writer.into_inner().expect("fixture TAR");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&bytes).expect("fixture gzip");
        Fixture::tgz("package.tar", &encoder.finish().expect("fixture compression"))
    }
    #[test]
    fn dependencies_and_scripts_are_literal_source_declarations() {
        let tree=fixture(br#"{"name":"@scope/demo","version":"1.0.0","dependencies":{"dep":"npm:other@^2"},"scripts":{"install":"node never-run.js"},"exports":{".":"./index.js"}}"#);
        let mut out = Output::default();
        Npm.analyze_tree(&tree, &mut out);
        assert_eq!(out.findings.len(), 3);
        let fact = &out.facts[0].value;
        assert_eq!(fact["name"], "@scope/demo");
        assert_eq!(fact["dependencies"][0]["declaration"], "npm:other@^2");
        assert_eq!(fact["scripts"][0]["declaration"], "node never-run.js");
        assert_eq!(fact["runtime_effects_established"], false);
        assert_eq!(fact["archive_entries"].as_array().expect("entries").len(), 2);
        assert!(out.findings.iter().all(|finding| finding.evidence[0].artifact.ends_with("package/package.json")));
    }
    #[test]
    fn duplicate_json_keys_nested_keys_and_value_budgets_cannot_collapse_declarations() {
        for text in [r#"{"name":"a","name":"b","version":"1"}"#, r#"{"name":"a","version":"1","scripts":{"install":"a","install":"b"}}"#] {
            let tree = fixture(text.as_bytes());
            let mut out = Output::default();
            Npm.analyze_tree(&tree, &mut out);
            assert!(out.findings.is_empty());
            assert!(out.limitations.iter().any(|limit| limit.code == "npm.package-unread"));
        }
        assert!(unique_json(&format!("{}0{}", "[".repeat(33), "]".repeat(33))).is_err());
        assert!(unique_json(&format!("[{}]", vec!["0"; crate::MAX_FIELDS + 1].join(","))).is_err());
    }
    #[test]
    fn incomplete_and_renamed_namespaces_do_not_establish_identity() {
        for mode in ["partial", "normalized"] {
            let mut tree = fixture(br#"{"name":"demo","version":"1"}"#);
            if mode == "partial" {
                tree.files[0].facts.insert("engine.container-listing".into(), json!({"complete":false}));
            } else {
                tree.files.last_mut().expect("member").facts.insert("engine.entry-name".into(), json!({"normalized":true}));
            }
            let mut out = Output::default();
            Npm.analyze_tree(&tree, &mut out);
            assert!(out.findings.is_empty(), "{mode}");
            assert_eq!(out.limitations[0].code, "npm.package-unread");
        }
    }
    #[test]
    fn canonical_control_bytes_and_original_tar_headers_must_agree() {
        let mut tree = fixture(br#"{"name":"demo","version":"1"}"#);
        tree.replace("package/package.json", br#"{"name":"fake","version":"9"}"#);
        let mut out = Output::default();
        Npm.analyze_tree(&tree, &mut out);
        assert!(out.findings.is_empty());
        assert!(out.limitations[0].detail.as_deref().is_some_and(|detail| detail.contains("disagree")));
        let tree = fixture(br#"{"name":"demo","version":"1"}"#);
        let bytes = tree.data.get(&tree.root().path).expect("TAR fixture");
        for length in [0, 1, 511, 512, bytes.len() - 1] {
            assert!(archive(&bytes[..length]).is_err(), "truncated TAR {length}");
        }
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(archive(&bad).is_err(), "header checksum must be checked");
    }

    #[test]
    fn link_declarations_never_create_captured_host_targets() {
        let control = br#"{"name":"demo","version":"1"}"#;
        let mut writer = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(control.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        writer.append_data(&mut header, "package/package.json", control.as_slice()).expect("control fixture");
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../../outside").expect("literal link target");
        header.set_cksum();
        writer.append_data(&mut header, "package/link", std::io::empty()).expect("link fixture");
        let bytes = writer.into_inner().expect("finish link TAR");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&bytes).expect("fixture gzip");
        let tree = Fixture::tgz("links.tar", &encoder.finish().expect("gzip bytes"));
        let mut output = Output::default();
        Npm.analyze_tree(&tree, &mut output);
        let package = &output.facts[0].value;
        assert_eq!(package["archive_entries"][1]["type"], "symlink");
        assert_eq!(package["archive_entries"][1]["link_target"], "../../outside");
        assert_eq!(package["inventory"]["total"], 1);
        assert!(output.limitations.iter().any(|limit| limit.code == "npm.archive-semantics"));
        assert!(tree.files.iter().all(|file| !file.path.ends_with("package/link")), "the declaration is not a host link or file artifact");
    }
    #[test]
    fn real_isarray_tarball_metadata_is_read_without_installing_it() {
        let bytes = include_bytes!("../tests/data/npm/isarray-2.0.5.tgz");
        assert_eq!(aa_core::sha256_hex(bytes), "72bae463b81a604b4a118c00012c76ee9b8d155b9da62d1f362876c9f8b5f793");
        let tree = Fixture::tgz("isarray.tar", bytes);
        let mut out = Output::default();
        Npm.analyze_tree(&tree, &mut out);
        let fact = &out.facts[0].value;
        assert_eq!(fact["name"], "isarray");
        assert_eq!(fact["version"], "2.0.5");
        assert_eq!(fact["inventory"]["total"], 4);
        assert_eq!(fact["declarations"]["main"], "index.js");
        let reference: Value = serde_json::from_str(include_str!("../tests/data/native.ref.json")).expect("native package references");
        let record =
            reference["records"].as_array().expect("records").iter().find(|record| record["kind"] == "npm").expect("npm reference");
        let actual: Vec<_> = fact["inventory"]["members"]
            .as_array()
            .expect("inventory")
            .iter()
            .map(|row| json!({"path":row["path"],"size":row["size"],"sha256":row["sha256"]}))
            .collect();
        assert_eq!(json!(actual), record["members"], "all members agree with independent TAR/native tar listing");
    }
}
