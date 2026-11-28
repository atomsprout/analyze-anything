//! Snap package declarations from a captured, complete SquashFS namespace.

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::text::redact_named_value;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use yaml_rust2::parser::{Event, Parser};

pub struct Snap;

const MAX_BYTES: usize = 256 * 1024;
const MAX_EVENTS: usize = 12_000;
const MAX_DEPTH: usize = 24;
const MAX_SCALAR: usize = 16 * 1024;
const MAX_APPS: usize = 256;
const MAX_REFERENCES: usize = 1024;
type Result<T> = std::result::Result<T, &'static str>;

const RULES: &[Rule] = &[
    Rule {
        id: "snap.identity",
        title_en: "Declared snap package identity",
        title_zh: "Snap 包身份声明",
        text_en: "The captured meta/snap.yaml declares {name}, version {version}. Package authenticity, installation and host compatibility were not established.",
        text_zh: "已捕获的 meta/snap.yaml 声明了 {name}，版本 {version}。没有确定包来源真实性、安装状态或本机兼容性。",
    },
    Rule {
        id: "snap.applications",
        title_en: "Snap application declarations",
        title_zh: "Snap 应用声明",
        text_en: "The package contains {count} application declarations, retaining command, daemon, interface and environment fields as source data. No commands or confinement policy were evaluated.",
        text_zh: "包包含 {count} 个应用声明，将命令、守护进程、接口和环境字段作为源数据保留，没有求值命令或限制策略。",
    },
    Rule {
        id: "snap.hooks",
        title_en: "Captured snap hook declarations",
        title_zh: "已捕获 Snap 钩子声明",
        text_en: "The package contains {count} hook declarations or captured hook files. Their names and bytes do not establish activation, ordering or effects.",
        text_zh: "包包含 {count} 个钩子声明或已捕获钩子文件。名称和字节不能确定其激活、顺序或效果。",
    },
    Rule {
        id: "snap.supplied-target",
        title_en: "Snap declaration matches a supplied file",
        title_zh: "Snap 声明匹配所提供的文件",
        text_en: "A literal package-relative command or hook declaration matches an original captured regular file. This is a supplied-file relationship, not a runtime target resolution.",
        text_zh: "相对于包的字面命令或钩子声明匹配了原始的已捕获普通文件。这是所提供文件之间的关系，没有解析运行时目标。",
    },
    Rule {
        id: "snap.unread",
        title_en: "Snap metadata could not be qualified",
        title_zh: "Snap 元数据无法确认",
        text_en: "A snap candidate lacks one original captured root meta/snap.yaml in a complete SquashFS namespace, or its metadata is malformed or outside the bounded YAML profile.",
        text_zh: "Snap 候选项在完整 SquashFS 命名空间内缺少唯一原始的根 meta/snap.yaml，或元数据损坏或超出有界 YAML 支持范围。",
    },
    Rule {
        id: "snap.partial",
        title_en: "Some snap declarations remain unresolved",
        title_zh: "部分 Snap 声明未确定",
        text_en: "Unknown fields were retained as declarations. Some field types, substitutions, target relationships or metadata semantics could not be established within this profile.",
        text_zh: "将未知字段作为声明保留。无法在此范围内确定部分字段类型、替换、目标关系或元数据语义。",
    },
    Rule {
        id: "snap.runtime-unchecked",
        title_en: "Snap installation and runtime semantics were not established",
        title_zh: "Snap 安装及运行时语义未确定",
        text_en: "Store assertions, signatures, base/content dependencies, interfaces, confinement, command-chain behavior and hook execution were not verified or evaluated. The host and repositories were not queried.",
        text_zh: "没有验证或求值商店声明、签名、基础及内容依赖、接口、限制、命令链行为或钩子执行，没有查询本机或仓库。",
    },
];

#[derive(Debug)]
struct Node {
    line: usize,
    value: Yaml,
}

#[derive(Debug)]
enum Yaml {
    Scalar(String),
    Mapping(BTreeMap<String, Node>),
    Sequence(Vec<Node>),
}

impl Node {
    fn field(&self, key: &str) -> Option<&Self> {
        self.mapping()?.get(key)
    }
    fn mapping(&self) -> Option<&BTreeMap<String, Self>> {
        if let Yaml::Mapping(fields) = &self.value { Some(fields) } else { None }
    }
    fn scalar(&self) -> Option<&str> {
        if let Yaml::Scalar(value) = &self.value { Some(value) } else { None }
    }
    fn identity(&self, key: &str) -> Option<String> {
        let value = self.field(key)?.scalar()?;
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return None;
        }
        redact_named_value(key, value).ok().filter(|redacted| redacted == value)
    }
    fn retained(&self, name: &str) -> Result<Value> {
        let value = match &self.value {
            Yaml::Scalar(value) => json!(redact_named_value(name, value)?),
            Yaml::Mapping(fields) => {
                let mut retained = BTreeMap::new();
                for (key, value) in fields {
                    retained.insert(key, value.retained(key)?);
                }
                json!(retained)
            }
            Yaml::Sequence(values) => json!(values.iter().map(|value| value.retained(name)).collect::<Result<Vec<_>>>()?),
        };
        Ok(json!({"line":self.line,"value":value}))
    }
}

struct Reader<'a> {
    parser: Parser<std::str::Chars<'a>>,
    events: usize,
}

impl Reader<'_> {
    fn next(&mut self) -> Result<(Event, usize)> {
        self.events += 1;
        if self.events > MAX_EVENTS {
            return Err("snap YAML event budget exhausted");
        }
        self.parser.next_token().map(|(event, mark)| (event, mark.line())).map_err(|_| "malformed snap YAML")
    }
    fn node(&mut self, event: Event, line: usize, depth: usize) -> Result<Node> {
        if depth > MAX_DEPTH {
            return Err("snap YAML depth budget exhausted");
        }
        let value = match event {
            Event::Scalar(value, _, 0, None) if value.len() <= MAX_SCALAR => Yaml::Scalar(value),
            Event::MappingStart(0, None) => {
                let mut fields = BTreeMap::new();
                loop {
                    let key = match self.next()?.0 {
                        Event::MappingEnd => break,
                        Event::Scalar(key, _, 0, None)
                            if !key.is_empty() && key.len() <= 256 && key != "<<" && !key.chars().any(char::is_control) =>
                        {
                            key
                        }
                        _ => return Err("unsupported snap YAML mapping key or merge"),
                    };
                    let (event, line) = self.next()?;
                    let value = self.node(event, line, depth + 1)?;
                    if fields.insert(key, value).is_some() {
                        return Err("duplicate snap YAML key");
                    }
                }
                Yaml::Mapping(fields)
            }
            Event::SequenceStart(0, None) => {
                let mut values = Vec::new();
                loop {
                    let (event, line) = self.next()?;
                    if event == Event::SequenceEnd {
                        break;
                    }
                    values.push(self.node(event, line, depth + 1)?);
                }
                Yaml::Sequence(values)
            }
            _ => return Err("unsupported snap YAML scalar, tag, anchor or alias"),
        };
        Ok(Node { line, value })
    }
}

fn parse(bytes: &[u8]) -> Result<Node> {
    if bytes.len() > MAX_BYTES {
        return Err("snap.yaml exceeds the 256 KiB byte budget");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "snap.yaml is not UTF-8")?;
    if text.contains('\0') || text.starts_with('\u{feff}') {
        return Err("NUL or a byte-order mark is outside the snap YAML profile");
    }
    let mut reader = Reader { parser: Parser::new_from_str(text), events: 0 };
    if reader.next()?.0 != Event::StreamStart || reader.next()?.0 != Event::DocumentStart {
        return Err("missing snap YAML document");
    }
    let (event, line) = reader.next()?;
    let root = reader.node(event, line, 0)?;
    if root.mapping().is_none() || reader.next()?.0 != Event::DocumentEnd || reader.next()?.0 != Event::StreamEnd {
        return Err("expected exactly one snap YAML mapping document");
    }
    Ok(root)
}

fn original(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_none_or(|name| name["normalized"] != true && name["colliding"] != true)
}

fn relative(value: &str, command: bool) -> Option<&str> {
    let value = if command { value.split_whitespace().next()? } else { value };
    let value = value.strip_prefix("./").unwrap_or(value);
    if value.is_empty()
        || value.len() > 4096
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || value.contains(['\\', '$', '%', '\'', '"', ';', ':', '|', '&', '<', '>', '(', ')', '[', ']'])
        || value.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(value)
}

struct Context<'a> {
    tree: &'a dyn Tree,
    package: &'a Artifact,
    metadata: &'a Artifact,
    references: Vec<Value>,
    incomplete: bool,
}

impl Context<'_> {
    fn reference(&mut self, field: &str, node: Option<&Node>, literal: &str, command: bool) {
        if self.references.len() == MAX_REFERENCES {
            self.incomplete = true;
            return;
        }
        let declared = match redact_named_value(field, literal) {
            Ok(value) => value,
            Err(_) => {
                self.incomplete = true;
                return;
            }
        };
        let path = relative(&declared, command).map(|relative| format!("{}/{relative}", self.package.path));
        let target = path
            .as_deref()
            .and_then(|path| self.tree.get(path))
            .filter(|file| original(file) && file.digests.is_some() && file.parent.as_deref() == Some(self.package.path.as_str()));
        if target.is_none() || literal.contains(['$', '%', '\\', '\'', '"']) {
            self.incomplete = true;
        }
        self.references.push(json!({"field":field,"line":node.map(|node|node.line),"basis":"captured-package-root",
            "declared":declared,"status":if target.is_some(){"matched-supplied-declaration"}else{"unresolved"},
            "target":target.map(|file|&file.path),"target_sha256":target.and_then(|file|file.digests.as_ref().map(|digest|&digest.sha256)),
            "runtime_target_resolved":false,"reason":if target.is_some(){None}else{Some("no unambiguous original captured regular file for the supported literal path")}}));
    }
}

fn read_package(tree: &dyn Tree, package: &Artifact, metadata: &Artifact, out: &mut Output) -> Result<()> {
    if metadata.size > MAX_BYTES as u64 {
        return Err("snap.yaml exceeds the 256 KiB byte budget");
    }
    let bytes = tree.read(&metadata.path).map_err(|_| "snap.yaml bytes unavailable")?;
    let root = parse(&bytes)?;
    let name = root.identity("name").ok_or("missing, nonliteral or redacted snap name")?;
    let version = root.identity("version").ok_or("missing, nonliteral or redacted snap version")?;
    let mut context = Context { tree, package, metadata, references: Vec::new(), incomplete: false };
    let known = [
        "name",
        "version",
        "summary",
        "description",
        "type",
        "architectures",
        "assumes",
        "base",
        "confinement",
        "grade",
        "epoch",
        "license",
        "apps",
        "hooks",
        "plugs",
        "slots",
        "environment",
        "layout",
        "system-usernames",
        "provenance",
        "links",
        "title",
        "icon",
        "passthrough",
        "components",
    ];
    if root.mapping().expect("validated root mapping").keys().any(|key| !known.contains(&key.as_str())) {
        context.incomplete = true;
    }
    let mut applications = Vec::new();
    if let Some(apps) = root.field("apps") {
        if let Some(fields) = apps.mapping() {
            for (index, (app_name, app)) in fields.iter().enumerate() {
                if index == MAX_APPS {
                    context.incomplete = true;
                    break;
                }
                let Some(settings) = app.mapping() else {
                    context.incomplete = true;
                    continue;
                };
                let known_app = [
                    "command",
                    "command-chain",
                    "stop-command",
                    "reload-command",
                    "post-stop-command",
                    "completer",
                    "daemon",
                    "daemon-scope",
                    "plugs",
                    "slots",
                    "environment",
                    "common-id",
                    "adapter",
                    "desktop",
                    "restart-condition",
                    "restart-delay",
                    "stop-timeout",
                    "start-timeout",
                    "stop-mode",
                    "refresh-mode",
                    "install-mode",
                    "bus-name",
                    "sockets",
                    "socket",
                    "timer",
                    "activates-on",
                    "after",
                    "before",
                    "autostart",
                    "watchdog-timeout",
                ];
                if settings.keys().any(|key| !known_app.contains(&key.as_str())) {
                    context.incomplete = true;
                }
                for key in ["command", "stop-command", "reload-command", "post-stop-command", "completer"] {
                    if let Some(node) = settings.get(key) {
                        if let Some(value) = node.scalar() {
                            context.reference(&format!("apps/{app_name}/{key}"), Some(node), value, key != "completer");
                        } else {
                            context.incomplete = true;
                        }
                    }
                }
                if let Some(chain) = settings.get("command-chain") {
                    if let Yaml::Sequence(values) = &chain.value {
                        for (index, node) in values.iter().enumerate() {
                            if let Some(value) = node.scalar() {
                                context.reference(&format!("apps/{app_name}/command-chain/{index}"), Some(node), value, false);
                            } else {
                                context.incomplete = true;
                            }
                        }
                    } else {
                        context.incomplete = true;
                    }
                }
                applications.push(json!({"name":app_name,"line":app.line,"declarations":app.retained(app_name)?}));
            }
        } else {
            context.incomplete = true;
        }
    }
    let mut hooks = BTreeMap::new();
    if let Some(declared) = root.field("hooks") {
        if let Some(fields) = declared.mapping() {
            for (index, (name, node)) in fields.iter().enumerate() {
                if index == MAX_APPS {
                    context.incomplete = true;
                    break;
                }
                hooks.insert(
                    name.clone(),
                    json!({"name":name,"line":node.line,"declarations":node.retained(name)?,"source":"meta/snap.yaml"}),
                );
                context.reference(&format!("hooks/{name}"), Some(node), &format!("meta/hooks/{name}"), false);
            }
        } else {
            context.incomplete = true;
        }
    }
    let prefix = format!("{}/meta/hooks/", package.path);
    for file in tree.artifacts().iter().filter(|file| file.parent.as_deref() == Some(package.path.as_str())) {
        let Some(name) = file.path.strip_prefix(&prefix).filter(|name| !name.is_empty() && !name.contains('/')) else {
            continue;
        };
        if hooks.len() == MAX_APPS && !hooks.contains_key(name) {
            context.incomplete = true;
            break;
        }
        if !original(file) {
            context.incomplete = true;
            continue;
        }
        if !hooks.contains_key(name) {
            hooks.insert(name.to_string(),json!({"name":name,"source":"captured meta/hooks file","path":file.path,"sha256":file.digests.as_ref().map(|digest|&digest.sha256)}));
            context.reference(&format!("meta/hooks/{name}"), None, &format!("meta/hooks/{name}"), false);
        }
    }
    let metadata_value = root.retained("snap.yaml")?;
    out.kind(package, "snap");
    out.fact(
        package,
        "snap.package",
        json!({"name":name,"version":version,"source":metadata.path,
        "source_sha256":metadata.digests.as_ref().map(|digest|&digest.sha256),"metadata":metadata_value,
        "applications":applications,"hooks":hooks.into_values().collect::<Vec<_>>(),"references":context.references,
        "schema_validated":false,"runtime_target_resolved":false,"store_queried":false,"signatures_verified":false}),
    );
    out.finding(
        Finding::new(Section::Identity, "snap", "snap.identity", Confidence::Verified, Severity::Info)
            .param("name", name)
            .param("version", version)
            .evidence(Evidence::field(
                metadata,
                format!("snap.yaml/name (line {})", root.field("name").expect("validated name").line),
                root.field("name").expect("validated name").retained("name")?,
            ))
            .evidence(Evidence::field(
                metadata,
                format!("snap.yaml/version (line {})", root.field("version").expect("validated version").line),
                root.field("version").expect("validated version").retained("version")?,
            )),
    );
    if !applications.is_empty() {
        out.finding(
            Finding::new(Section::Capabilities, "snap", "snap.applications", Confidence::Verified, Severity::Info)
                .param("count", applications.len())
                .evidence(Evidence::field(metadata, "snap.yaml/apps", json!(applications))),
        );
    }
    let hook_count = context
        .references
        .iter()
        .filter(|reference| {
            reference["field"].as_str().is_some_and(|field| field.starts_with("hooks/") || field.starts_with("meta/hooks/"))
        })
        .count();
    if hook_count > 0 {
        out.finding(
            Finding::new(Section::Capabilities, "snap", "snap.hooks", Confidence::Verified, Severity::Info)
                .param("count", hook_count)
                .evidence(Evidence::field(
                    metadata,
                    "snap hook declarations and captured files",
                    json!(
                        context
                            .references
                            .iter()
                            .filter(|reference| reference["field"]
                                .as_str()
                                .is_some_and(|field| field.starts_with("hooks/") || field.starts_with("meta/hooks/")))
                            .collect::<Vec<_>>()
                    ),
                )),
        );
    }
    for reference in context.references.iter().filter(|reference| reference["status"] == "matched-supplied-declaration").take(64) {
        let target = reference["target"].as_str().and_then(|path| tree.get(path)).expect("matched captured reference");
        out.finding(
            Finding::new(Section::Structure, "snap", "snap.supplied-target", Confidence::Verified, Severity::Info)
                .evidence(Evidence::field(context.metadata, reference["field"].as_str().unwrap_or("snap declaration"), reference.clone()))
                .evidence(Evidence::whole(
                    target,
                    json!({"path":target.path,"sha256":target.digests.as_ref().map(|digest|&digest.sha256)}),
                )),
        );
    }
    if context.incomplete {
        out.limitation(
            "snap.partial",
            Some(package),
            Some("unknown fields, unsupported field types, substitutions, references or output limits remain unresolved".into()),
        );
    }
    out.limitation("snap.runtime-unchecked", Some(package), None);
    Ok(())
}

impl Analyzer for Snap {
    fn id(&self) -> &'static str {
        "snap"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let artifacts = tree.artifacts();
        if !artifacts.iter().any(|file| file.unpacked_by.as_deref() == Some("squashfs")) {
            return;
        }
        if artifacts.len() > 100_000 {
            out.limitation("snap.partial", None, Some("snap namespace index exceeds 100,000 artifacts".into()));
            return;
        }
        let mut metadata_bytes = 0u64;
        for (index, package) in artifacts.iter().filter(|file| file.unpacked_by.as_deref() == Some("squashfs")).enumerate() {
            if index == 1024 {
                out.limitation("snap.partial", None, Some("snap candidate count budget exhausted".into()));
                break;
            }
            let path = format!("{}/meta/snap.yaml", package.path);
            let metadata = tree.get(&path).filter(|metadata| metadata.parent.as_deref() == Some(package.path.as_str()));
            if let Some(metadata) = metadata {
                metadata_bytes = metadata_bytes.saturating_add(metadata.size);
                if metadata_bytes > 16 * 1024 * 1024 {
                    out.limitation("snap.partial", Some(package), Some("aggregate snap metadata byte budget exhausted".into()));
                    break;
                }
            }
            if metadata.is_none() && package.extension().as_deref() != Some("snap") {
                continue;
            }
            let complete = package.facts.get("engine.container-listing").is_some_and(|listing| listing["complete"] == true);
            let result = if !complete || !original(package) {
                Err("filesystem listing or original package name is incomplete or ambiguous")
            } else if let Some(metadata) = metadata.filter(|metadata| original(metadata)) {
                read_package(tree, package, metadata, out)
            } else {
                Err("one original root meta/snap.yaml was not captured")
            };
            if let Err(reason) = result {
                out.limitation("snap.unread", Some(package), Some(reason.into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;
    use aa_core::plugin::{SinkError, Unpack, UnpackSink, Unpacker};

    #[derive(Default)]
    struct Captured {
        files: Vec<(String, Vec<u8>)>,
        limitations: Vec<String>,
    }
    impl UnpackSink for Captured {
        fn add(&mut self, path: &str, reader: &mut dyn std::io::Read) -> std::result::Result<(), SinkError> {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).map_err(|error| SinkError::Read(error.to_string()))?;
            self.files.push((path.to_string(), bytes));
            Ok(())
        }
        fn limitation(&mut self, code: &str, _detail: Option<String>) {
            self.limitations.push(code.to_string());
        }
    }

    struct Supplied {
        files: Vec<Artifact>,
        data: BTreeMap<String, Vec<u8>>,
    }
    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.data.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::other("missing bytes"))
        }
    }
    fn artifact(path: &str, parent: Option<&str>, bytes: &[u8]) -> Artifact {
        Artifact {
            path: path.into(),
            parent: parent.map(str::to_string),
            size: bytes.len() as u64,
            digests: Some(aa_core::Digests { md5: "0".repeat(32), sha1: "0".repeat(40), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }
    fn supplied_yaml(bytes: &[u8]) -> Supplied {
        let mut package = artifact("example.snap", None, b"image");
        package.unpacked_by = Some("squashfs".into());
        package.facts.insert("engine.container-listing".into(), json!({"complete":true}));
        let mut files = vec![
            package,
            artifact("example.snap/meta/snap.yaml", Some("example.snap"), bytes),
            artifact("example.snap/bin/example", Some("example.snap"), b"inert executable fixture"),
            artifact("example.snap/meta/hooks/install", Some("example.snap"), b"inert hook fixture"),
        ];
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Supplied { files, data: BTreeMap::from([("example.snap/meta/snap.yaml".into(), bytes.to_vec())]) }
    }
    fn analyze(tree: &Supplied) -> Output {
        let mut out = Output::default();
        Snap.analyze_tree(tree, &mut out);
        out
    }
    fn package(out: &Output) -> &Value {
        &out.facts.iter().find(|fact| fact.key == "snap.package").expect("snap package fact").value
    }

    #[test]
    fn literal_apps_interfaces_hooks_and_original_payload_links_have_evidence() {
        let tree=supplied_yaml(b"name: example\nversion: '1.0'\nconfinement: strict\napps:\n  example:\n    command: bin/example --token fixture-secret\n    daemon: simple\n    plugs: [network]\n    environment:\n      PASSWORD: fixture-hidden\nhooks:\n  install:\n    plugs: [network]\nslots:\n  fixture: {interface: content}\n");
        let out = analyze(&tree);
        let fact = package(&out);
        assert_eq!(fact["name"], "example");
        assert_eq!(fact["applications"].as_array().expect("apps").len(), 1);
        assert_eq!(fact["references"][0]["target"], "example.snap/bin/example");
        assert_eq!(fact["hooks"].as_array().expect("hooks").len(), 1);
        assert_eq!(fact["runtime_target_resolved"], false);
        let published = serde_json::to_string(&out.facts.iter().map(|fact| &fact.value).collect::<Vec<_>>()).expect("facts JSON");
        assert!(!published.contains("fixture-secret"));
        assert!(!published.contains("fixture-hidden"));
        assert!(out.findings.iter().all(|finding| !finding.evidence.is_empty()));
        let again = analyze(&tree);
        assert_eq!(out.facts, again.facts);
        assert_eq!(out.findings, again.findings);
    }

    #[test]
    fn duplicate_keys_aliases_tags_merges_and_extra_documents_are_not_collapsed() {
        for bytes in [
            b"name: one\nname: two\nversion: 1\n".as_slice(),
            b"name: &id one\nversion: *id\n",
            b"name: !!str one\nversion: 1\n",
            b"name: one\nversion: 1\n<<: {}\n",
            b"name: one\nversion: 1\n---\nname: two\n",
        ] {
            assert!(parse(bytes).is_err());
            let out = analyze(&supplied_yaml(bytes));
            assert!(out.facts.is_empty());
            assert!(out.limitations.iter().any(|limit| limit.code == "snap.unread"));
        }
    }

    #[test]
    fn byte_scalar_event_and_nesting_budgets_fail_explicitly() {
        assert!(parse(&vec![b'x'; MAX_BYTES + 1]).is_err());
        assert!(parse(format!("name: {}\nversion: 1\n", "x".repeat(MAX_SCALAR + 1)).as_bytes()).is_err());
        assert!(parse(format!("name: one\nversion: {}1{}\n", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1)).as_bytes()).is_err());
        assert!(parse(format!("name: one\nversion: 1\nunknown: [{}]\n", "x,".repeat(MAX_EVENTS)).as_bytes()).is_err());
    }

    #[test]
    fn names_incomplete_listing_and_dynamic_or_escaping_commands_do_not_link() {
        for command in ["../bin/example", "/bin/example", "$SNAP/bin/example", "'bin/example'", "bin\\example"] {
            let out =
                analyze(&supplied_yaml(format!("name: example\nversion: 1\napps:\n  example:\n    command: {command:?}\n").as_bytes()));
            if !out.facts.is_empty() {
                assert_eq!(package(&out)["references"][0]["status"], "unresolved", "{command}");
            }
        }
        let mut tree = supplied_yaml(b"name: example\nversion: 1\n");
        tree.files[0].facts.insert("engine.container-listing".into(), json!({"complete":false}));
        assert!(analyze(&tree).facts.is_empty());
        let mut tree = supplied_yaml(b"name: example\nversion: 1\n");
        let metadata = tree.files.iter_mut().find(|file| file.path.ends_with("meta/snap.yaml")).expect("metadata");
        metadata.facts.insert("engine.entry-name".into(), json!({"colliding":true}));
        assert!(analyze(&tree).facts.is_empty());
    }

    #[test]
    fn real_canonical_snap_connects_captured_metadata_to_all_four_application_files() {
        let bytes = include_bytes!("../tests/data/upstream-hello-world-29.snap");
        let mut root = artifact("upstream-hello-world-29.snap", None, bytes);
        let mut captured = Captured::default();
        assert_eq!(crate::squashfs::Squashfs.unpack(&root, bytes, &mut captured), Unpack::Done { kind: "squashfs" });
        assert!(captured.limitations.is_empty());
        root.unpacked_by = Some("squashfs".into());
        root.facts.insert("engine.container-listing".into(), json!({"complete":true}));
        let mut files = vec![root];
        let mut data = BTreeMap::new();
        for (path, bytes) in captured.files {
            let path = format!("upstream-hello-world-29.snap/{path}");
            files.push(artifact(&path, Some("upstream-hello-world-29.snap"), &bytes));
            data.insert(path, bytes);
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let tree = Supplied { files, data };
        let out = analyze(&tree);
        let fact = package(&out);
        assert_eq!(fact["name"], "hello-world");
        assert_eq!(fact["version"], "6.4");
        assert_eq!(fact["applications"].as_array().expect("real apps").len(), 4);
        let references = fact["references"].as_array().expect("captured references");
        assert_eq!(references.len(), 4);
        assert!(references.iter().all(|reference| reference["status"] == "matched-supplied-declaration"));
        assert!(fact["source"].as_str().expect("source metadata").ends_with("/meta/snap.yaml"));
    }
}
