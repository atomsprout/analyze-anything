//! Task Scheduler XML declarations. No task service, command resolver or COM handler is used.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::Output;
use aa_core::text::{redact_named_value, redact_sensitive_text};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use roxmltree::Node;
use serde::Serialize;
use serde_json::json;

const NAMESPACE: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_DECLARATIONS: usize = 4096;
const MAX_DEPTH: usize = 32;
const MAX_TEXT: usize = 64 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Serialize)]
struct Declaration {
    element: String,
    namespace: Option<String>,
    path: String,
    line: u32,
    attributes: BTreeMap<String, String>,
    text: Option<String>,
    children: Vec<Declaration>,
    interpreted: bool,
}

#[derive(Debug, Default)]
struct State {
    declarations: usize,
    issue_count: usize,
    issues: Vec<(String, &'static str)>,
    ids: BTreeSet<String>,
}

impl State {
    fn issue(&mut self, path: &str, reason: &'static str) {
        self.issue_count += 1;
        if self.issues.len() < 64 {
            self.issues.push((path.to_string(), reason));
        }
    }
}

fn children_of(parent: &str) -> &'static [&'static str] {
    match parent {
        "Task" => &["RegistrationInfo", "Triggers", "Principals", "Settings", "Actions", "Data"],
        "RegistrationInfo" => &["URI", "SecurityDescriptor", "Source", "Date", "Author", "Version", "Description", "Documentation"],
        "Triggers" => &[
            "BootTrigger",
            "RegistrationTrigger",
            "IdleTrigger",
            "TimeTrigger",
            "EventTrigger",
            "LogonTrigger",
            "SessionStateChangeTrigger",
            "CalendarTrigger",
        ],
        "Repetition" => &["Interval", "Duration", "StopAtDurationEnd"],
        "BootTrigger" | "RegistrationTrigger" => &["Enabled", "StartBoundary", "EndBoundary", "Repetition", "ExecutionTimeLimit", "Delay"],
        "IdleTrigger" => &["Enabled", "StartBoundary", "EndBoundary", "Repetition", "ExecutionTimeLimit"],
        "TimeTrigger" => &["Enabled", "StartBoundary", "EndBoundary", "Repetition", "ExecutionTimeLimit", "RandomDelay"],
        "EventTrigger" => &[
            "Enabled",
            "StartBoundary",
            "EndBoundary",
            "Repetition",
            "ExecutionTimeLimit",
            "Subscription",
            "Delay",
            "PeriodOfOccurrence",
            "NumberOfOccurrences",
            "MatchingElement",
            "ValueQueries",
        ],
        "LogonTrigger" => &["Enabled", "StartBoundary", "EndBoundary", "Repetition", "ExecutionTimeLimit", "UserId", "Delay"],
        "SessionStateChangeTrigger" => {
            &["Enabled", "StartBoundary", "EndBoundary", "Repetition", "ExecutionTimeLimit", "UserId", "Delay", "StateChange"]
        }
        "CalendarTrigger" => &[
            "Enabled",
            "StartBoundary",
            "EndBoundary",
            "Repetition",
            "ExecutionTimeLimit",
            "RandomDelay",
            "ScheduleByDay",
            "ScheduleByWeek",
            "ScheduleByMonth",
            "ScheduleByMonthDayOfWeek",
        ],
        "ValueQueries" => &["Value"],
        "ScheduleByDay" => &["DaysInterval"],
        "ScheduleByWeek" => &["WeeksInterval", "DaysOfWeek"],
        "ScheduleByMonth" => &["DaysOfMonth", "Months"],
        "ScheduleByMonthDayOfWeek" => &["Weeks", "DaysOfWeek", "Months"],
        "DaysOfWeek" => &["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
        "Months" => {
            &["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
        }
        "DaysOfMonth" => &["Day"],
        "Weeks" => &["Week"],
        "Principals" => &["Principal"],
        "Principal" => &["UserId", "GroupId", "DisplayName", "LogonType", "RunLevel", "ProcessTokenSidType", "RequiredPrivileges"],
        "RequiredPrivileges" => &["Privilege"],
        "Actions" => &["Exec", "ComHandler", "SendEmail", "ShowMessage"],
        "Exec" => &["Command", "Arguments", "WorkingDirectory"],
        "ComHandler" => &["ClassId", "Data"],
        "SendEmail" => &["Server", "Subject", "To", "Cc", "Bcc", "ReplyTo", "From", "HeaderFields", "Body", "Attachments"],
        "HeaderFields" => &["HeaderField"],
        "HeaderField" => &["Name", "Value"],
        "Attachments" => &["File"],
        "ShowMessage" => &["Title", "Body"],
        "Settings" => &[
            "AllowStartOnDemand",
            "RestartOnFailure",
            "MultipleInstancesPolicy",
            "DisallowStartIfOnBatteries",
            "StopIfGoingOnBatteries",
            "AllowHardTerminate",
            "StartWhenAvailable",
            "NetworkProfileName",
            "RunOnlyIfNetworkAvailable",
            "WakeToRun",
            "Enabled",
            "Hidden",
            "DeleteExpiredTaskAfter",
            "IdleSettings",
            "NetworkSettings",
            "ExecutionTimeLimit",
            "Priority",
            "RunOnlyIfIdle",
            "UseUnifiedSchedulingEngine",
            "DisallowStartOnRemoteAppSession",
        ],
        "RestartOnFailure" => &["Interval", "Count"],
        "IdleSettings" => &["Duration", "WaitTimeout", "StopOnIdleEnd", "RestartOnIdle"],
        "NetworkSettings" => &["Name", "Id"],
        _ => &[],
    }
}

fn repeated(parent: &str, child: &str) -> bool {
    matches!(parent, "Triggers" | "Actions" | "ValueQueries" | "RequiredPrivileges" | "HeaderFields" | "Attachments")
        || matches!((parent, child), ("DaysOfMonth", "Day") | ("Weeks", "Week"))
}

fn known_attribute(element: &str, name: &str) -> bool {
    match element {
        "Task" => name == "version",
        "Actions" => name == "Context",
        "Value" => name == "name",
        "Principal"
        | "Exec"
        | "ComHandler"
        | "SendEmail"
        | "ShowMessage"
        | "BootTrigger"
        | "RegistrationTrigger"
        | "IdleTrigger"
        | "TimeTrigger"
        | "EventTrigger"
        | "LogonTrigger"
        | "SessionStateChangeTrigger"
        | "CalendarTrigger" => name == "id",
        _ => false,
    }
}

fn capture(node: Node<'_, '_>, path: String, depth: usize, supported: bool, state: &mut State) -> Result<Declaration> {
    if depth > MAX_DEPTH || state.declarations >= MAX_DECLARATIONS {
        return Err("task declaration depth or count exceeds the reader limit");
    }
    state.declarations += 1;
    let name = node.tag_name().name();
    let namespace = node.tag_name().namespace();
    if name.len() > 128 || namespace.is_some_and(|s| s.len() > 2048) || path.len() > 8192 {
        return Err("task element name, namespace or path exceeds the reader limit");
    }
    let path = redact_sensitive_text(&path)?;
    let mut declaration = Declaration {
        element: redact_sensitive_text(name)?,
        namespace: namespace.map(redact_sensitive_text).transpose()?,
        path,
        line: node.document().text_pos_at(node.range().start).row,
        attributes: BTreeMap::new(),
        text: None,
        children: Vec::new(),
        interpreted: supported && namespace == Some(NAMESPACE) && name != "Data",
    };
    if !declaration.interpreted {
        state.issue(&declaration.path, "element or namespace is unsupported; its payload is not interpreted or copied");
        return Ok(declaration);
    }
    if node.attributes().len() > 32 {
        return Err("task element has too many attributes");
    }
    for attribute in node.attributes() {
        if attribute.name().len() > 128 || attribute.value().len() > MAX_TEXT {
            return Err("task attribute exceeds the reader limit");
        }
        if attribute.namespace().is_some() || !known_attribute(name, attribute.name()) {
            state.issue(&declaration.path, "unsupported attribute value is not interpreted or copied");
            continue;
        }
        if attribute.name() == "id" && !state.ids.insert(attribute.value().to_string()) {
            state.issue(&declaration.path, "duplicate task XML id; references are ambiguous");
        }
        declaration.attributes.insert(attribute.name().into(), redact_named_value(attribute.name(), attribute.value())?);
    }
    let has_elements = node.children().any(|n| n.is_element());
    let text: String = node.children().filter(|n| n.is_text()).filter_map(|n| n.text()).collect();
    if text.len() > MAX_TEXT {
        return Err("task text field exceeds the 64 KiB reader limit");
    }
    if !has_elements && children_of(name).is_empty() {
        let hint = node
            .attribute("name")
            .or_else(|| {
                if name == "Value" {
                    node.parent()
                        .filter(|p| p.tag_name().name() == "HeaderField")
                        .and_then(|p| p.children().find(|c| c.is_element() && c.tag_name().name() == "Name"))
                        .and_then(|n| n.text())
                } else {
                    None
                }
            })
            .unwrap_or(name);
        declaration.text = Some(redact_named_value(hint, &text)?);
    } else if !text.trim().is_empty() {
        state.issue(&declaration.path, "mixed or unexpected container text is not interpreted");
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for child in node.children().filter(Node::is_element) {
        let child_name = child.tag_name().name();
        if child_name.len() > 128 {
            return Err("task element name exceeds the reader limit");
        }
        let count = counts.entry(child_name).or_default();
        *count += 1;
        if *count > 1 && !repeated(name, child_name) {
            state.issue(&declaration.path, "duplicate singleton declarations are preserved without choosing one");
        }
        let child_path = format!("{}/{}[{}]", declaration.path, child_name, count);
        declaration.children.push(capture(child, child_path, depth + 1, children_of(name).contains(&child_name), state)?);
    }
    Ok(declaration)
}

fn candidate(bytes: &[u8]) -> bool {
    let prefix = &bytes[..bytes.len().min(16 * 1024)];
    let starts_as_xml = if let Some(body) = prefix.strip_prefix(&[0xff, 0xfe]) {
        body.chunks_exact(2).find(|b| !matches!(b, [b' ' | b'\t' | b'\r' | b'\n', 0])).is_some_and(|b| b == [b'<', 0])
    } else if let Some(body) = prefix.strip_prefix(&[0xfe, 0xff]) {
        body.chunks_exact(2).find(|b| !matches!(b, [0, b' ' | b'\t' | b'\r' | b'\n'])).is_some_and(|b| b == [0, b'<'])
    } else {
        let body = prefix.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(prefix);
        body.starts_with(&[b'<', 0])
            || body.starts_with(&[0, b'<'])
            || body.iter().find(|b| !b.is_ascii_whitespace()).is_some_and(|&b| b == b'<')
    };
    if !starts_as_xml {
        return false;
    }
    let mut has_namespace = prefix.windows(NAMESPACE.len()).any(|w| w == NAMESPACE.as_bytes());
    for wide in [
        NAMESPACE.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>(),
        NAMESPACE.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    ] {
        if prefix.windows(wide.len()).any(|w| w == wide) {
            has_namespace = true;
            break;
        }
    }
    if !has_namespace {
        return false;
    }
    // This prefix is only a recognition probe. The full document is decoded strictly before use.
    let wide = if let Some(body) = prefix.strip_prefix(&[0xff, 0xfe]) {
        Some((body, true))
    } else if let Some(body) = prefix.strip_prefix(&[0xfe, 0xff]) {
        Some((body, false))
    } else if prefix.get(1) == Some(&0) {
        Some((prefix, true))
    } else if prefix.first() == Some(&0) {
        Some((prefix, false))
    } else {
        None
    };
    let text = if let Some((body, little)) = wide {
        let units: Vec<_> = body
            .chunks_exact(2)
            .map(|b| if little { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(prefix.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(prefix)).into_owned()
    };
    let mut rest = text.trim_start();
    loop {
        let terminator = if rest.starts_with("<?") {
            Some("?>")
        } else if rest.starts_with("<!--") {
            Some("-->")
        } else {
            None
        };
        if let Some(terminator) = terminator {
            let Some((_, tail)) = rest.split_once(terminator) else {
                return false;
            };
            rest = tail.trim_start();
            continue;
        }
        let name = if let Some(body) = rest.strip_prefix("<!DOCTYPE") {
            body.trim_start()
        } else if let Some(body) = rest.strip_prefix('<') {
            body
        } else {
            return false;
        };
        let name = name.split(|c: char| c.is_whitespace() || matches!(c, '/' | '>' | '[')).next().unwrap_or("");
        return name.rsplit(':').next() == Some("Task");
    }
}

fn parse(bytes: &[u8]) -> Result<Option<(Declaration, State)>> {
    let text = crate::text::decode(bytes, MAX_BYTES)?;
    // DOCTYPE inside a comment or CDATA value is literal data, not a document declaration.
    let mut prolog = text.trim_start();
    loop {
        let end = if prolog.starts_with("<?") {
            Some("?>")
        } else if prolog.starts_with("<!--") {
            Some("-->")
        } else {
            None
        };
        let Some(end) = end else {
            break;
        };
        let Some((_, tail)) = prolog.split_once(end) else {
            break;
        };
        prolog = tail.trim_start();
    }
    if prolog.starts_with("<!DOCTYPE") {
        return Err("DTDs are not supported in task XML");
    }
    let options = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 20_000 };
    let document =
        roxmltree::Document::parse_with_options(&text, options).map_err(|_| "task XML is malformed or exceeds the XML parser limit")?;
    let root = document.root_element();
    if root.tag_name().name() != "Task" || root.tag_name().namespace() != Some(NAMESPACE) {
        return Ok(None);
    }
    let mut state = State::default();
    if text.starts_with("<?xml") {
        let header = text.split_once("?>").map(|(header, _)| header).unwrap_or("");
        if let Some((_, encoding)) = header.split_once("encoding") {
            let value = encoding.trim_start().strip_prefix('=').map(str::trim_start).unwrap_or("");
            if let Some(quote @ ('\'' | '"')) = value.chars().next() {
                let declared = value.get(1..).and_then(|s| s.split(quote).next()).unwrap_or("").to_ascii_lowercase();
                let matches = match declared.as_str() {
                    "utf-8" => !bytes.starts_with(&[0xff, 0xfe]) && !bytes.starts_with(&[0xfe, 0xff]),
                    "us-ascii" => text.is_ascii() && !bytes.starts_with(&[0xff, 0xfe]) && !bytes.starts_with(&[0xfe, 0xff]),
                    "utf-16" => bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]),
                    "utf-16le" => bytes.starts_with(&[0xff, 0xfe]),
                    "utf-16be" => bytes.starts_with(&[0xfe, 0xff]),
                    _ => return Err("unsupported declared task XML encoding"),
                };
                if !matches {
                    state.issue("Task", "declared XML encoding differs from the decoded bytes; importer compatibility is not established");
                }
            }
        }
    }
    let declarations = capture(root, "Task".into(), 0, true, &mut state)?;
    if !declarations.children.iter().any(|c| c.element == "Actions" && c.interpreted) {
        state.issue("Task", "required Actions declaration was not found");
    }
    Ok(Some((declarations, state)))
}

fn group<'a>(task: &'a Declaration, name: &str) -> Vec<&'a Declaration> {
    task.children.iter().filter(|n| n.interpreted && n.element == name).flat_map(|n| n.children.iter()).filter(|n| n.interpreted).collect()
}

fn finding(file: &Artifact, rule: &str, nodes: &[&Declaration], severity: Severity) -> Finding {
    let mut finding = Finding::new(Section::Capabilities, "windows", rule, Confidence::Verified, severity).param("count", nodes.len());
    for node in nodes.iter().take(12) {
        finding = finding.evidence(Evidence::field(file, format!("{} (line {})", node.path, node.line), json!(node)));
    }
    finding
}

pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !candidate(bytes) {
        return;
    }
    let (task, state) = match parse(bytes) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return,
        Err(reason) => {
            out.limitation("windows.task-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    let actions = group(&task, "Actions");
    let triggers = group(&task, "Triggers");
    let principals = group(&task, "Principals");
    out.kind(file, "scheduled-task");
    out.fact(file, "windows.scheduled-task", json!({"declarations": task, "actions": actions.len(), "triggers": triggers.len(), "principals": principals.len(), "issues": state.issues,
        "issue_count": state.issue_count, "registered": false, "targets_resolved": false, "schema_validated": false}));
    let overview = Finding::new(Section::Capabilities, "windows", "windows.scheduled-task", Confidence::Verified, Severity::Info)
        .param("actions", actions.len())
        .param("triggers", triggers.len())
        .param("principals", principals.len())
        .evidence(Evidence::field(file, "Task/@xmlns", NAMESPACE));
    out.finding(overview);
    for (rule, nodes) in
        [("windows.task-actions", &actions), ("windows.task-triggers", &triggers), ("windows.task-principals", &principals)]
    {
        if !nodes.is_empty() {
            out.finding(finding(file, rule, nodes, Severity::Info));
        }
    }
    let elevated: Vec<_> = principals
        .iter()
        .flat_map(|n| &n.children)
        .filter(|n| n.interpreted && n.element == "RunLevel" && n.text.as_deref() == Some("HighestAvailable"))
        .collect();
    if !elevated.is_empty() {
        out.finding(finding(file, "windows.task-highest-available", &elevated, Severity::Low));
    }
    let startup: Vec<_> = triggers.iter().copied().filter(|n| matches!(n.element.as_str(), "BootTrigger" | "LogonTrigger")).collect();
    if !startup.is_empty() {
        out.finding(finding(file, "windows.task-startup-trigger", &startup, Severity::Low));
    }
    out.limitation("windows.task-semantics-unchecked", Some(file), None);
    if state.issue_count > 0 {
        out.limitation(
            "windows.task-partial",
            Some(file),
            Some(format!(
                "{}; first issues: {}",
                aa_core::counted(state.issue_count as u64, "declarations were unsupported or ambiguous"),
                state.issues.iter().map(|(path, reason)| format!("{path}: {reason}")).collect::<Vec<_>>().join("; ")
            )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml(body: &str) -> Vec<u8> {
        format!("<Task xmlns=\"{NAMESPACE}\">{body}</Task>").into_bytes()
    }

    #[test]
    fn trigger_families_calendar_and_action_types_remain_literal_declarations() {
        let mut triggers = String::new();
        for name in children_of("Triggers") {
            triggers.push_str(&format!("<{name}><Enabled>false</Enabled></{name}>"));
        }
        let body = format!(
            "<Triggers>{triggers}<CalendarTrigger><ScheduleByMonthDayOfWeek><Weeks><Week>Last</Week></Weeks><DaysOfWeek><Monday/></DaysOfWeek><Months><January/></Months></ScheduleByMonthDayOfWeek></CalendarTrigger></Triggers><Actions><Exec><Command>%X%\\app.exe</Command><Arguments>--password 'fixture secret'</Arguments></Exec><ComHandler><ClassId>{{00000000-0000-0000-0000-000000000000}}</ClassId><Data><Opaque>private payload</Opaque></Data></ComHandler><SendEmail><Server>mail.example.invalid</Server><HeaderFields><HeaderField><Name>Authorization</Name><Value>fixture header secret</Value></HeaderField></HeaderFields><Attachments><File>\\\\server\\share\\file</File></Attachments></SendEmail><ShowMessage><Title>Example</Title><Body>Message</Body></ShowMessage></Actions>"
        );
        let bytes = xml(&body);
        assert!(candidate(&bytes));
        let (task, state) = parse(&bytes).expect("task XML").expect("Task root");
        assert_eq!(group(&task, "Triggers").len(), 9);
        assert_eq!(group(&task, "Actions").len(), 4);
        assert_eq!(state.issue_count, 1, "opaque Data is not interpreted");
        let serialized = serde_json::to_string(&task).expect("declarations JSON");
        assert!(!serialized.contains("fixture secret"));
        assert!(!serialized.contains("fixture header secret"));
        assert!(!serialized.contains("private payload"));
        assert!(serialized.contains("%X%"));
        assert!(serialized.contains("Last"));
        for bytes in [
            [0xff, 0xfe]
                .into_iter()
                .chain(String::from_utf8(xml("<Actions/>")).expect("UTF-8 text").encode_utf16().flat_map(u16::to_le_bytes))
                .collect::<Vec<_>>(),
            [0xfe, 0xff]
                .into_iter()
                .chain(String::from_utf8(xml("<Actions/>")).expect("UTF-8 text").encode_utf16().flat_map(u16::to_be_bytes))
                .collect(),
        ] {
            assert!(candidate(&bytes));
            assert!(parse(&bytes).expect("UTF-16 task").is_some());
        }
    }

    #[test]
    fn unknown_namespaces_attributes_and_duplicates_are_explicit_and_opaque() {
        let (task, state) = parse(&xml("<Actions Context=\"x\" Unknown=\"fixture unknown secret\"><Exec id=\"same\"><Command>a</Command><Command>b</Command><Foreign xmlns=\"urn:other\">fixture payload secret</Foreign></Exec><Exec id=\"same\"><Command>c</Command></Exec></Actions><Actions/>")).expect("ambiguous task").expect("Task");
        assert!(state.issue_count >= 5);
        assert_eq!(group(&task, "Actions").len(), 2);
        assert_eq!(group(&task, "Actions")[0].children.iter().filter(|c| c.element == "Command").count(), 2);
        let serialized = serde_json::to_string(&task).expect("task JSON");
        assert!(!serialized.contains("fixture unknown secret"));
        assert!(!serialized.contains("fixture payload secret"));
        assert!(parse(b"<Task xmlns=\"urn:other\"><Actions/></Task>").expect("foreign namespace").is_none());
        let mut binary = b"MZ".to_vec();
        binary.extend(xml("<Actions/>"));
        assert!(!candidate(&binary), "a namespace inside a binary is not task XML");
        let html = format!("<html><body><![CDATA[<Task xmlns=\"{NAMESPACE}\">]]></body></html>");
        assert!(!candidate(html.as_bytes()), "an embedded example is not a task document");
        let prefixed = format!("<!-- example --><t:Task xmlns:t=\"{NAMESPACE}\"><t:Actions/></t:Task>");
        assert!(candidate(prefixed.as_bytes()));
        assert!(parse(prefixed.as_bytes()).expect("prefixed task namespace").is_some());
    }

    #[test]
    fn malformed_dtd_and_oversized_documents_are_refused_without_reading_external_data() {
        let dtd = format!(
            "<!DOCTYPE Task [<!ENTITY target SYSTEM \"file:///outside-input\">]><Task xmlns=\"{NAMESPACE}\"><Actions><Exec><Command>&target;</Command></Exec></Actions></Task>"
        );
        assert!(parse(dtd.as_bytes()).is_err());
        let literal = xml(
            "<!-- <!DOCTYPE is literal comment text --><Actions><Exec><Arguments><![CDATA[<!DOCTYPE example>]]></Arguments></Exec></Actions>",
        );
        let (_, state) = parse(&literal).expect("literal text is not a DTD").expect("Task");
        assert_eq!(state.issue_count, 0);
        assert!(parse(&xml("<Actions>")).is_err());
        assert!(parse(&vec![b' '; MAX_BYTES + 1]).is_err());
        assert!(parse(&xml(&format!("<Actions><Exec><Arguments>{}</Arguments></Exec></Actions>", "x".repeat(MAX_TEXT + 1)))).is_err());
        assert!(parse(&xml(&format!("<Actions>{}</Actions>", "<Exec/>".repeat(MAX_DECLARATIONS)))).is_err());
        assert!(parse(&xml(&format!("<Actions>{}</Actions>", "<Exec/>".repeat(20_001)))).is_err());
        assert!(parse(&xml(&format!("<{} />", "a".repeat(129)))).is_err());
    }
}
