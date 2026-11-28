//! Literal JAR manifest and Maven declarations over already captured ZIP members.
//! Classes, module descriptors, agents and signature blocks are never loaded or executed.

use std::collections::BTreeSet;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::{Result, inventory, members, read_text};

pub struct Java;

const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_FIELDS: usize = 8192;
const MAX_SECTIONS: usize = 256;
const MAX_VALUE: usize = 65_535;
const MAX_PROPERTIES: usize = 64 * 1024;
const MAX_MAVEN: usize = 256;
const MAX_CLASS_PATH: usize = 1024;

const RULES: &[Rule] = &[
    Rule {
        id: "java.manifest",
        title_en: "Declared JAR identity and launch metadata",
        title_zh: "JAR 身份与启动元数据声明",
        text_en: "The captured manifest contains {count} declarations in its main attributes, including identity and launch metadata where present. Main-class, module, agent and class-path attributes remain literal declarations; no class was loaded or run.",
        text_zh: "已捕获的清单包含 {count} 个主属性，并保留其中的身份和启动元数据。主类、模块、代理和类路径属性仍为字面声明，没有加载或运行类。",
    },
    Rule {
        id: "java.class-path",
        title_en: "Declared JAR class path",
        title_zh: "JAR 类路径声明",
        text_en: "The main manifest contains {count} declarations in Class-Path. URLs remain literal; no remote, host or runtime class-path resolution was performed.",
        text_zh: "主清单包含 {count} 个类路径引用。按字面保留 URL，没有解析远程、主机或运行时类路径。",
    },
    Rule {
        id: "java.maven",
        title_en: "Embedded Maven identity declarations",
        title_zh: "内嵌 Maven 身份声明",
        text_en: "The JAR contains {count} declarations of supported Maven pom.properties identity. These identify declared embedded components, not resolved dependencies or installed packages.",
        text_zh: "JAR 包含 {count} 个受支持的 Maven pom.properties 身份。这些是内嵌组件声明，没有解析依赖或检查安装状态。",
    },
    Rule {
        id: "java.contents",
        title_en: "Captured JAR contents",
        title_zh: "已捕获的 JAR 内容",
        text_en: "The JAR inventory contains {count} files captured from the archive. Class files and resources remain data; versioned class selection was not evaluated.",
        text_zh: "已捕获的 JAR 清单包含 {count} 个普通成员。类文件和资源仍为数据，没有求值版本化类选择。",
    },
    Rule {
        id: "java.package-unread",
        title_en: "JAR package information could not be read",
        title_zh: "JAR 软件包信息无法读取",
        text_en: "A JAR candidate did not have an unambiguous complete captured ZIP namespace within the bounded package profile.",
        text_zh: "JAR 候选项没有可在有界软件包范围内唯一确定的完整 ZIP 命名空间。",
    },
    Rule {
        id: "java.metadata-unread",
        title_en: "JAR metadata could not be interpreted",
        title_zh: "JAR 元数据无法解释",
        text_en: "A metadata declaration was missing, malformed, ambiguous, used an unsupported encoding or exceeded its bounded text profile. It was not treated as a confirmed identity.",
        text_zh: "元数据声明缺失、格式错误、不唯一、使用不受支持的编码，或超出有界文本范围。没有将其视为已确定身份。",
    },
    Rule {
        id: "java.profile-limit",
        title_en: "JAR metadata budget reached",
        title_zh: "JAR 元数据达到上限",
        text_en: "Some metadata or inventory declarations were omitted because a bounded count or size limit was reached. Remaining declarations do not establish a complete dependency graph.",
        text_zh: "部分元数据或清单声明因数量或大小达到有界限制而省略。已读取的声明不能确定完整依赖图。",
    },
    Rule {
        id: "java.variant-unread",
        title_en: "Java application archive variant remains unread",
        title_zh: "Java 应用归档变体未读取",
        text_en: "WAR and EAR application/server semantics are outside this initial JAR profile. Their supported ZIP members can still be read as data.",
        text_zh: "WAR 和 EAR 的应用、服务器语义不在初始 JAR 范围内。仍可按数据读取受支持的 ZIP 成员。",
    },
    Rule {
        id: "java.code-semantics",
        title_en: "Java code and module behavior remain unresolved",
        title_zh: "Java 代码与模块行为未确定",
        text_en: "Class files, module-info descriptors, OSGi fields, service providers and manifest agents remain captured data or literal metadata. Bytecode, module dependencies, class loading and runtime behavior were not established.",
        text_zh: "类文件、module-info 描述、OSGi 字段、服务提供者和清单代理仍为已捕获数据或字面元数据。没有确定字节码、模块依赖、类加载或运行时行为。",
    },
    Rule {
        id: "java.integrity-unverified",
        title_en: "JAR authenticity was not established",
        title_zh: "JAR 来源真实性未确定",
        text_en: "Manifest digests and signature-related members are declarations only. JAR signatures, certificates, per-entry digests and package authenticity were not verified.",
        text_zh: "清单摘要和签名相关成员仅为声明。没有验证 JAR 签名、证书、成员摘要或软件包来源真实性。",
    },
    Rule {
        id: "java.manifest-semantics",
        title_en: "Effective JAR manifest semantics remain unresolved",
        title_zh: "JAR 清单的实际生效语义未确定",
        text_en: "Per-entry attributes, package sealing, versioned entries and launch settings remain source declarations. Their merged values, runtime selection and effective privileges were not evaluated.",
        text_zh: "成员属性、包密封、版本化条目和启动设置仍为源声明。没有求值合并值、运行时选择或实际权限。",
    },
];

#[derive(Debug)]
struct Field {
    name: String,
    value: String,
    offset: usize,
    length: usize,
    line: usize,
}
#[derive(Debug)]
struct Manifest {
    sections: Vec<Vec<Field>>,
}

fn lines(text: &str) -> Vec<(usize, &str, usize)> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while at < bytes.len() && !matches!(bytes[at], b'\r' | b'\n') {
            at += 1;
        }
        let end = at;
        if at < bytes.len() {
            let previous = bytes[at];
            at += 1;
            if previous == b'\r' && bytes.get(at) == Some(&b'\n') {
                at += 1;
            }
        }
        lines.push((start, &text[start..end], at - start));
    }
    lines
}

fn manifest(text: &str) -> Result<Manifest> {
    if text.len() > MAX_MANIFEST || !text.ends_with(['\n', '\r']) || text.contains('\0') {
        return Err("manifest is oversized, contains NUL or lacks a final newline".into());
    }
    let mut sections = Vec::new();
    let mut fields: Vec<Field> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut count = 0;
    for (number, (offset, line, length)) in lines(text).into_iter().enumerate() {
        if line.len() > 72 {
            return Err("manifest physical line exceeds 72 bytes".into());
        }
        if line.is_empty() {
            if !fields.is_empty() {
                if sections.len() >= MAX_SECTIONS {
                    return Err("manifest exceeds 256 sections".into());
                }
                sections.push(std::mem::take(&mut fields));
                seen.clear();
            }
            continue;
        }
        if let Some(tail) = line.strip_prefix(' ') {
            let field = fields.last_mut().ok_or("manifest continuation has no preceding attribute")?;
            if field.value.len().checked_add(tail.len()).is_none_or(|length| length > MAX_VALUE) {
                return Err("manifest attribute exceeds 65535 bytes".into());
            }
            field.value.push_str(tail);
            field.length = offset + length - field.offset;
            continue;
        }
        let (name, value) = line.split_once(": ").ok_or("manifest attribute has no colon-space separator")?;
        if name.is_empty()
            || name.len() > 70
            || !name.as_bytes()[0].is_ascii_alphanumeric()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("manifest attribute name is outside the JAR grammar".into());
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err("duplicate case-insensitive manifest attribute within one section".into());
        }
        count += 1;
        if count > MAX_FIELDS {
            return Err("manifest exceeds 8192 attributes".into());
        }
        fields.push(Field { name: name.into(), value: value.into(), offset, length, line: number + 1 });
    }
    if !fields.is_empty() {
        return Err("manifest section lacks its final empty line".into());
    }
    let main = sections.first().ok_or("manifest has no main attributes")?;
    if main.first().is_none_or(|field| field.name != "Manifest-Version" || field.value != "1.0")
        || main.iter().any(|field| field.name.eq_ignore_ascii_case("Name"))
    {
        return Err("manifest main section must begin with Manifest-Version: 1.0 and contain no Name attribute".into());
    }
    for section in sections.iter().skip(1) {
        if section.first().is_none_or(|field| !field.name.eq_ignore_ascii_case("Name")) {
            return Err("manifest entry section does not begin with Name".into());
        }
    }
    for section in &mut sections {
        for field in section {
            field.value = aa_core::text::redact_named_value(&field.name, &field.value).map_err(str::to_string)?;
        }
    }
    Ok(Manifest { sections })
}

fn field<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|field| field.name.eq_ignore_ascii_case(name))
}
fn value(fields: &[Field], name: &str) -> Option<String> {
    field(fields, name).map(|field| field.value.clone())
}
fn property_value(fields: &[Field], name: &str) -> Option<String> {
    fields.iter().find(|field| field.name == name).map(|field| field.value.clone())
}
fn evidence(file: &Artifact, field: &Field) -> Evidence {
    Evidence::bytes(file, field.offset as u64, field.length as u64, json!({"name":field.name,"value":field.value,"line":field.line}))
}
fn attributes(fields: &[Field]) -> Result<Vec<Value>> {
    fields
        .iter()
        .map(|field| {
            Ok(json!({"name":field.name,"value":aa_core::text::redact_named_value(&field.name,&field.value).map_err(str::to_string)?,
        "offset":field.offset,"length":field.length,"line":field.line}))
        })
        .collect()
}

/// Maven's generated simple properties normally need no Java escape interpretation.
/// Ambiguous/escaped profiles remain gaps instead of silently changing identity text.
fn properties(text: &str) -> Result<Vec<Field>> {
    if text.len() > MAX_PROPERTIES || text.contains('\0') {
        return Err("Maven properties exceed 64 KiB or contain NUL".into());
    }
    let mut fields = Vec::new();
    let mut seen = BTreeSet::new();
    for (number, (offset, line, length)) in lines(text).into_iter().enumerate() {
        let body = line.trim_start_matches([' ', '\t', '\x0c']);
        if body.is_empty() || body.starts_with(['#', '!']) {
            continue;
        }
        if line.len() > 8192 || line.contains('\\') {
            return Err("escaped, continued or oversized Java properties are outside the literal profile".into());
        }
        let (name, value) = body.split_once('=').ok_or("Maven properties require a literal equals separator")?;
        let name = name.trim_end_matches([' ', '\t', '\x0c']);
        let value = value.trim_start_matches([' ', '\t', '\x0c']);
        if name.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || !seen.insert(name.to_string())
        {
            return Err("Maven properties have a malformed or duplicate key".into());
        }
        if fields.len() >= 256 {
            return Err("Maven properties exceed 256 fields".into());
        }
        fields.push(Field { name: name.into(), value: value.into(), offset, length, line: number + 1 });
    }
    for field in &mut fields {
        field.value = aa_core::text::redact_named_value(&field.name, &field.value).map_err(str::to_string)?;
    }
    Ok(fields)
}

fn maven_path(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.split('/');
    if parts.next() != Some("META-INF") || parts.next() != Some("maven") {
        return None;
    }
    let group = parts.next()?;
    let artifact = parts.next()?;
    (parts.next() == Some("pom.properties") && parts.next().is_none() && !group.is_empty() && !artifact.is_empty())
        .then_some((group, artifact))
}
fn module_descriptor(path: &str) -> bool {
    if path == "module-info.class" {
        return true;
    }
    let Some(path) = path.strip_prefix("META-INF/versions/") else { return false };
    let Some((version, name)) = path.split_once('/') else { return false };
    name == "module-info.class"
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && version.parse::<u32>().is_ok_and(|version| version >= 9)
}
fn signature(path: &str) -> bool {
    let Some(name) = path.strip_prefix("META-INF/") else { return false };
    if name.contains('/') {
        return false;
    }
    let name = name.to_ascii_uppercase();
    name.starts_with("SIG-") || [".SF", ".RSA", ".DSA", ".EC"].iter().any(|suffix| name.ends_with(suffix))
}

impl Analyzer for Java {
    fn id(&self) -> &'static str {
        "java"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        for (index, package) in
            tree.artifacts().iter().filter(|file| matches!(file.extension().as_deref(), Some("jar" | "war" | "ear"))).enumerate()
        {
            if index == crate::MAX_PACKAGES {
                out.limitation("java.profile-limit", None, Some("JAR candidate count exceeds 256 packages".into()));
                break;
            }
            if matches!(package.extension().as_deref(), Some("war" | "ear")) {
                out.limitation("java.variant-unread", Some(package), None);
                continue;
            }
            if package.unpacked_by.as_deref() != Some("zip") {
                out.limitation("java.package-unread", Some(package), Some("candidate is not a captured ZIP container".into()));
                continue;
            }
            let files = match members(tree, package) {
                Ok(files) => files,
                Err(error) => {
                    out.limitation("java.package-unread", Some(package), Some(error));
                    continue;
                }
            };
            out.kind(package, "jar");
            let captured = inventory(&files);
            if captured["truncated"] == true {
                out.limitation("java.profile-limit", Some(package), Some("captured inventory preview exceeds 5000 members".into()));
            }
            let modules: Vec<_> = files.keys().filter(|path| module_descriptor(path)).take(256).copied().collect();
            let signatures: Vec<_> = files.keys().filter(|path| signature(path)).take(256).copied().collect();
            if files.keys().filter(|path| module_descriptor(path)).count() > 256
                || files.keys().filter(|path| signature(path)).count() > 256
            {
                out.limitation("java.profile-limit", Some(package), Some("module/signature descriptor preview exceeds 256 paths".into()));
            }
            out.finding(
                Finding::new(Section::Structure, "java", "java.contents", Confidence::Verified, Severity::Info)
                    .param("count", files.len())
                    .evidence(Evidence::whole(package, json!({"captured_members":files.len(),"container":"zip"}))),
            );
            let mut manifest_value = Value::Null;
            let mut title = None;
            let mut version = None;
            let mut class_path = Vec::new();
            let mut manifest_source = None;
            if let Some(source) = files.get("META-INF/MANIFEST.MF") {
                match read_text(tree, source, MAX_MANIFEST).and_then(|text| manifest(&text)).and_then(|manifest| {
                    let main = &manifest.sections[0];
                    let main_attributes = attributes(main)?;
                    let sections: Result<Vec<_>> =
                        manifest.sections.iter().skip(1).map(|section| Ok(json!({"attributes":attributes(section)?}))).collect();
                    Ok((manifest, main_attributes, sections?))
                }) {
                    Ok((manifest, main_attributes, sections)) => {
                        let main = &manifest.sections[0];
                        title = value(main, "Implementation-Title").or_else(|| value(main, "Bundle-Name"));
                        version = value(main, "Implementation-Version").or_else(|| value(main, "Bundle-Version"));
                        manifest_source = Some(source.path.as_str());
                        if let Some(classpath) = field(main, "Class-Path") {
                            class_path = classpath
                                .value
                                .split(' ')
                                .filter(|part| !part.is_empty())
                                .take(MAX_CLASS_PATH)
                                .map(|reference| json!({"declared":reference,"offset":classpath.offset,"resolution_performed":false}))
                                .collect();
                            let count = classpath.value.split(' ').filter(|part| !part.is_empty()).count();
                            if count > MAX_CLASS_PATH {
                                out.limitation("java.profile-limit", Some(source), Some("Class-Path exceeds 1024 URL declarations".into()));
                            }
                            out.finding(
                                Finding::new(Section::Composition, "java", "java.class-path", Confidence::Verified, Severity::Info)
                                    .param("count", count)
                                    .evidence(evidence(source, classpath)),
                            );
                        }
                        let mut finding = Finding::new(Section::Identity, "java", "java.manifest", Confidence::Verified, Severity::Info)
                            .param("count", main.len())
                            .param("name", title.clone())
                            .param("version", version.clone());
                        for field in main
                            .iter()
                            .filter(|field| {
                                [
                                    "Manifest-Version",
                                    "Implementation-Title",
                                    "Implementation-Version",
                                    "Bundle-Name",
                                    "Bundle-Version",
                                    "Main-Class",
                                    "Automatic-Module-Name",
                                    "Multi-Release",
                                    "Premain-Class",
                                    "Agent-Class",
                                    "Launcher-Agent-Class",
                                ]
                                .iter()
                                .any(|name| field.name.eq_ignore_ascii_case(name))
                            })
                            .take(12)
                        {
                            finding = finding.evidence(evidence(source, field));
                        }
                        out.finding(finding);
                        manifest_value = json!({"source":source.path,"main_attributes":main_attributes,"entry_sections":sections,
                            "main_class":value(main,"Main-Class"),"automatic_module_name":value(main,"Automatic-Module-Name"),"multi_release":value(main,"Multi-Release"),"class_path":class_path,
                            "runtime_selection_performed":false,"per_entry_sealing_or_digest_semantics_established":false});
                    }
                    Err(error) => out.limitation("java.metadata-unread", Some(source), Some(error)),
                }
            } else {
                out.limitation("java.metadata-unread", Some(package), Some("canonical META-INF/MANIFEST.MF was not captured".into()));
            }
            let mut maven = Vec::new();
            let mut candidates = 0;
            for (path, source) in &files {
                let Some((group, artifact)) = maven_path(path) else { continue };
                candidates += 1;
                if candidates > MAX_MAVEN {
                    out.limitation("java.profile-limit", Some(package), Some("Maven properties exceed 256 files".into()));
                    break;
                }
                match read_text(tree, source, MAX_PROPERTIES).and_then(|text| properties(&text)) {
                    Ok(fields) => {
                        let declared_group = property_value(&fields, "groupId");
                        let declared_artifact = property_value(&fields, "artifactId");
                        let declared_version = property_value(&fields, "version");
                        let agrees = declared_group.as_deref() == Some(group)
                            && declared_artifact.as_deref() == Some(artifact)
                            && declared_version.as_ref().is_some_and(|version| !version.is_empty());
                        if !agrees {
                            out.limitation(
                                "java.metadata-unread",
                                Some(source),
                                Some("Maven identity is missing or disagrees with its source path".into()),
                            );
                        }
                        match attributes(&fields){Ok(fields)=>maven.push(json!({"source":source.path,"group_id":declared_group,"artifact_id":declared_artifact,"version":declared_version,"path_identity_agrees":agrees,"fields":fields})),Err(error)=>out.limitation("java.metadata-unread",Some(source),Some(error))}
                    }
                    Err(error) => out.limitation("java.metadata-unread", Some(source), Some(error)),
                }
            }
            if !maven.is_empty() {
                let mut finding = Finding::new(Section::Composition, "java", "java.maven", Confidence::Verified, Severity::Info)
                    .param("count", maven.iter().filter(|entry| entry["path_identity_agrees"] == true).count());
                for entry in maven.iter().take(8) {
                    if let Some(source) = entry["source"].as_str().and_then(|path| tree.get(path)) {
                        finding=finding.evidence(Evidence::bytes(source,0,source.size,json!({"group_id":entry["group_id"],"artifact_id":entry["artifact_id"],"version":entry["version"],"path_identity_agrees":entry["path_identity_agrees"]})));
                    }
                }
                out.finding(finding);
            }
            out.fact(package,"java.jar",json!({"name":title,"version":version,"source_manifest":manifest_source,"manifest":manifest_value,"maven":maven,
                "module_descriptors":modules,"signature_members":signatures,"inventory":captured,"class_count":files.keys().filter(|path|path.ends_with(".class")).count(),"runtime_selection_performed":false}));
            out.limitation("java.code-semantics", Some(package), None);
            out.limitation("java.integrity-unverified", Some(package), None);
            out.limitation("java.manifest-semantics", Some(package), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::Fixture;
    use std::collections::BTreeMap;

    fn run(fixture: &Fixture) -> Output {
        let mut output = Output::default();
        Java.analyze_tree(fixture, &mut output);
        output
    }
    fn fact(output: &Output) -> &Value {
        &output.facts.iter().find(|fact| fact.key == "java.jar").expect("JAR fact").value
    }

    #[test]
    fn manifest_continuations_sections_and_offsets_remain_literal() {
        let text = "Manifest-Version: 1.0\r\nMain-Class: example.Main\r\nClass-Path: lib/a.jar https://example.invalid/b.jar\r\nAutomatic-Module-Name: example.\r\n module\r\n\r\nName: example/Main.class\r\nSealed: true\r\n\r\n";
        let parsed = manifest(text).expect("manifest");
        let main = &parsed.sections[0];
        assert_eq!(value(main, "Automatic-Module-Name").as_deref(), Some("example.module"));
        assert_eq!(parsed.sections.len(), 2);
        let continued = field(main, "Automatic-Module-Name").expect("module attribute");
        assert_eq!(&text[continued.offset..continued.offset + continued.length], "Automatic-Module-Name: example.\r\n module\r\n");
        assert_eq!(value(&parsed.sections[1], "Name").as_deref(), Some("example/Main.class"));
    }

    #[test]
    fn malformed_duplicate_case_continuation_and_budget_manifests_are_not_identities() {
        for text in [
            "Manifest-Version: 1.0\nMain-Class: A\nmain-class: B\n\n",
            "Manifest-Version: 1.0\n\n orphan\n\n",
            "Manifest-Version: 1.0\nName: forged\n\n",
            "Manifest-Version: 2.0\n\n",
            "Manifest-Version: 1.0\n\nMain-Class: forged\n\n",
            "Manifest-Version: 1.0\n",
        ] {
            assert!(manifest(text).is_err(), "{text:?}");
        }
        assert!(manifest(&format!("Manifest-Version: 1.0\nX: {}\n\n", "a".repeat(73))).is_err());
        let mut text = "Manifest-Version: 1.0\nX: a\n".to_string();
        for _ in 0..1000 {
            text.push_str(&format!(" {}\n", "a".repeat(71)));
        }
        text.push('\n');
        assert!(manifest(&text).is_err(), "folding cannot bypass the total attribute cap");
        assert!(manifest(&"a".repeat(MAX_MANIFEST + 1)).is_err());
        let mut text = "Manifest-Version: 1.0\n".to_string();
        for index in 0..MAX_FIELDS {
            text.push_str(&format!("X{index}: a\n"));
        }
        text.push('\n');
        assert!(manifest(&text).is_err(), "field count must be bounded independently of bytes");
        let mut text = "Manifest-Version: 1.0\n\n".to_string();
        for index in 0..MAX_SECTIONS {
            text.push_str(&format!("Name: entry{index}\n\n"));
        }
        assert!(manifest(&text).is_err(), "section count includes the main section");
    }

    #[test]
    fn maven_properties_keep_simple_values_and_reject_java_escape_or_duplicate_ambiguity() {
        let parsed = properties("# generated\ngroupId=org.example\nartifactId=demo\nversion=1.2.3\n").expect("literal Maven properties");
        assert_eq!(value(&parsed, "version").as_deref(), Some("1.2.3"));
        assert_eq!(maven_path("META-INF/maven/org.example/demo/pom.properties"), Some(("org.example", "demo")));
        for text in ["groupId=a\ngroupId=b\n", "groupId=org\\u002eexample\n", "version=1\\\n 2\n", "version: 1\n"] {
            assert!(properties(text).is_err(), "{text:?}");
        }
        assert!(maven_path("nested/META-INF/maven/org.example/demo/pom.properties").is_none());
    }

    #[test]
    fn modules_and_signatures_are_bounded_inventory_declarations() {
        assert!(module_descriptor("module-info.class"));
        assert!(module_descriptor("META-INF/versions/9/module-info.class"));
        assert!(!module_descriptor("META-INF/versions/8/module-info.class"));
        assert!(!module_descriptor("META-INF/versions/9/nested/module-info.class"));
        assert!(signature("META-INF/A.RSA"));
        assert!(signature("META-INF/a.sf"));
        assert!(!signature("META-INF/nested/A.RSA"));
    }

    #[test]
    fn captured_manifest_actions_and_maven_identity_use_only_their_source_members() {
        let mut fixture = Fixture::new("app.jar", "zip");
        fixture.add("META-INF/MANIFEST.MF",b"Manifest-Version: 1.0\nImplementation-Title: example\nImplementation-Version: 1.2\nMain-Class: example.Main\nClass-Path: file:/outside.jar https://example.invalid/a.jar\n\n");
        fixture.add("META-INF/maven/org.example/example/pom.properties", b"groupId=org.example\nartifactId=example\nversion=1.2\n");
        fixture.add("example/Main.class", b"not loaded");
        fixture.add("module-info.class", b"not loaded");
        fixture.add("payload/MANIFEST.MF", b"Main-Class: forged\n");
        let output = run(&fixture);
        let jar = fact(&output);
        assert_eq!(jar["name"], "example");
        assert_eq!(jar["version"], "1.2");
        assert_eq!(jar["manifest"]["main_class"], "example.Main");
        assert_eq!(jar["manifest"]["class_path"][0]["declared"], "file:/outside.jar");
        assert_eq!(jar["manifest"]["class_path"][0]["resolution_performed"], false);
        assert_eq!(jar["module_descriptors"], json!(["module-info.class"]));
        assert_eq!(jar["class_count"], 2);
        assert_eq!(jar["maven"][0]["path_identity_agrees"], true);
        for finding in &output.findings {
            assert!(!finding.evidence.is_empty());
            assert!(finding.evidence.iter().all(|evidence| !evidence.artifact.contains("payload/MANIFEST.MF")));
        }
        assert!(output.limitations.iter().any(|limit| limit.code == "java.code-semantics"));
    }

    #[test]
    fn ambiguous_names_incomplete_capture_and_war_ear_are_explicitly_unread() {
        for mode in ["normalized", "colliding", "incomplete"] {
            let mut fixture = Fixture::new("app.jar", "zip");
            fixture.add("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n\n");
            if mode == "incomplete" {
                fixture
                    .files
                    .iter_mut()
                    .find(|file| file.parent.is_none())
                    .expect("root")
                    .facts
                    .insert("engine.container-listing".into(), json!({"complete":false}));
            } else {
                fixture
                    .files
                    .iter_mut()
                    .find(|file| file.parent.is_some())
                    .expect("manifest")
                    .facts
                    .insert("engine.entry-name".into(), json!({mode:true}));
            }
            let output = run(&fixture);
            assert!(output.facts.is_empty(), "{mode}");
            assert!(output.findings.is_empty(), "{mode}");
            assert!(output.limitations.iter().any(|limit| limit.code == "java.package-unread"));
        }
        for name in ["app.war", "app.ear"] {
            let fixture = Fixture::new(name, "zip");
            let output = run(&fixture);
            assert!(output.facts.is_empty());
            assert_eq!(output.limitations[0].code, "java.variant-unread");
        }
    }

    #[test]
    fn properties_are_case_sensitive_and_path_mismatches_are_not_confirmed_components() {
        let mut fixture = Fixture::new("app.jar", "zip");
        fixture.add("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n\n");
        fixture.add("META-INF/maven/org.example/demo/pom.properties", b"GroupId=org.example\nartifactId=demo\nversion=1.0\n");
        let output = run(&fixture);
        assert_eq!(fact(&output)["maven"][0]["path_identity_agrees"], false);
        assert!(fact(&output)["maven"][0]["group_id"].is_null());
        assert!(output.limitations.iter().any(|limit| limit.code == "java.metadata-unread"));
    }

    #[test]
    fn class_path_and_embedded_property_budgets_are_explicit() {
        let mut fixture = Fixture::new("app.jar", "zip");
        let classpath = std::iter::repeat_n("a.jar", MAX_CLASS_PATH + 1).collect::<Vec<_>>().join(" ");
        let mut text = "Manifest-Version: 1.0\nClass-Path: ".to_string();
        let first = 72 - "Class-Path: ".len();
        text.push_str(&classpath[..first]);
        text.push('\n');
        for chunk in classpath.as_bytes()[first..].chunks(71) {
            text.push(' ');
            text.push_str(std::str::from_utf8(chunk).expect("ASCII fixture"));
            text.push('\n');
        }
        text.push('\n');
        fixture.add("META-INF/MANIFEST.MF", text.as_bytes());
        for index in 0..MAX_MAVEN + 1 {
            fixture.add(
                &format!("META-INF/maven/org.example/p{index}/pom.properties"),
                format!("groupId=org.example\nartifactId=p{index}\nversion=1\n").as_bytes(),
            );
        }
        let output = run(&fixture);
        let jar = fact(&output);
        assert_eq!(jar["manifest"]["class_path"].as_array().expect("class path rows").len(), MAX_CLASS_PATH);
        assert_eq!(jar["maven"].as_array().expect("Maven identities").len(), MAX_MAVEN);
        assert!(output.limitations.iter().filter(|limit| limit.code == "java.profile-limit").count() >= 2);
    }

    #[test]
    fn repeated_class_path_entries_do_not_repeat_a_long_archive_namespace() {
        let name = format!("{}.jar", "z".repeat(7000));
        let mut fixture = Fixture::new(&name, "zip");
        let classpath = std::iter::repeat_n("a.jar", MAX_CLASS_PATH).collect::<Vec<_>>().join(" ");
        let mut text = "Manifest-Version: 1.0\nClass-Path: ".to_string();
        let first = 72 - "Class-Path: ".len();
        text.push_str(&classpath[..first]);
        text.push('\n');
        for chunk in classpath.as_bytes()[first..].chunks(71) {
            text.push(' ');
            text.push_str(std::str::from_utf8(chunk).expect("ASCII declaration"));
            text.push('\n');
        }
        text.push('\n');
        fixture.add("META-INF/MANIFEST.MF", text.as_bytes());
        let output = run(&fixture);
        let jar = fact(&output);
        assert_eq!(jar["manifest"]["class_path"].as_array().expect("Class-Path declarations").len(), MAX_CLASS_PATH);
        assert!(jar["source_manifest"].as_str().expect("retained source provenance").starts_with(&name));
        assert!(jar.to_string().len() < 256 * 1024, "short declarations retain compact shared provenance");

        let mut excessive = Fixture::new(&format!("{}.jar", "z".repeat(8170)), "zip");
        excessive.add("META-INF/MANIFEST.MF", text.as_bytes());
        let output = run(&excessive);
        assert!(!output.facts.iter().any(|fact| fact.key == "java.jar"));
        assert!(!output.limitations.is_empty());
    }

    #[test]
    fn real_slf4j_jar_identity_inventory_and_native_manifest_are_hash_bound() {
        let bytes = include_bytes!("../tests/data/java/slf4j-api-2.0.16.jar");
        assert_eq!(aa_core::sha256_hex(bytes), "a12578dde1ba00bd9b816d388a0b879928d00bab3c83c240f7013bf4196c579a");
        let fixture = Fixture::zip("slf4j-api-2.0.16.jar", bytes);
        let output = run(&fixture);
        let jar = fact(&output);
        assert_eq!(jar["name"], "slf4j-api");
        assert_eq!(jar["version"], "2.0.16");
        assert_eq!(jar["manifest"]["multi_release"], "true");
        assert_eq!(jar["maven"][0]["group_id"], "org.slf4j");
        assert_eq!(jar["maven"][0]["artifact_id"], "slf4j-api");
        assert_eq!(jar["maven"][0]["path_identity_agrees"], true);
        let native: Value = serde_json::from_str(include_str!("../tests/data/java/native.ref.json")).expect("JDK native reference");
        assert_eq!(native["sha256"], aa_core::sha256_hex(bytes));
        let attributes: BTreeMap<_, _> = jar["manifest"]["main_attributes"]
            .as_array()
            .expect("attributes")
            .iter()
            .map(|attribute| (attribute["name"].as_str().expect("name"), attribute["value"].clone()))
            .collect();
        for (name, value) in native["main_attributes"].as_object().expect("native manifest attributes") {
            assert_eq!(attributes.get(name.as_str()), Some(value), "native JDK manifest {name}");
        }
        let captured: BTreeMap<_, _> = jar["inventory"]["members"]
            .as_array()
            .expect("inventory")
            .iter()
            .map(|member| (member["path"].as_str().expect("path"), member))
            .collect();
        assert_eq!(captured.len(), native["members"].as_array().expect("native members").len());
        for member in native["members"].as_array().expect("native members") {
            let observed = captured.get(member["path"].as_str().expect("path")).expect("captured member");
            assert_eq!(observed["size"], member["size"]);
            assert_eq!(observed["sha256"], member["sha256"]);
        }
        assert!(!output.limitations.iter().any(|limit| limit.code == "java.metadata-unread" || limit.code == "java.package-unread"));
    }
}
