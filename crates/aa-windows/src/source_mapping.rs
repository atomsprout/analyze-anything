//! Associates declared sources only under an explicitly configured logical distribution root.

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

fn directory(text: &str) -> Result<Vec<&str>, &'static str> {
    if text.starts_with('/')
        || text.starts_with("\\\\")
        || text.starts_with("\\/")
        || text.contains([':', '%'])
        || text.contains("[redacted")
    {
        return Err("unsupported-media-or-source-directory");
    }
    let text = text.strip_prefix('\\').unwrap_or(text).trim_end_matches(['\\', '/']);
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for component in text.split(['\\', '/']) {
        if component == "." {
            continue;
        }
        if !crate::references::ordinary_component(component) {
            return Err("unsupported-media-or-source-directory");
        }
        result.push(component);
        if result.len() > 256 {
            return Err("source-directory-component-limit");
        }
    }
    Ok(result)
}

fn zero_flags(text: &str) -> bool {
    text.is_empty()
        || text.bytes().all(|b| b == b'0')
        || text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b == b'0'))
}

fn relative(source: &Value, media: &Value) -> Result<String, &'static str> {
    if !media["tag_or_cab"].as_str().unwrap_or("").is_empty()
        || !media["tag_file"].as_str().unwrap_or("").is_empty()
        || !zero_flags(media["flags"].as_str().unwrap_or(""))
    {
        return Err("cabinet-tag-or-media-flags-not-interpreted");
    }
    if source["extra_fields"].as_array().is_some_and(|v| !v.is_empty()) {
        return Err("unsupported-source-file-fields");
    }
    let filename = source["filename_literal"].as_str().ok_or("source-filename-unreadable")?;
    if !crate::references::ordinary_component(filename) {
        return Err("source-filename-outside-match-profile");
    }
    let mut parts = directory(media["path"].as_str().unwrap_or(""))?;
    parts.extend(directory(source["subdirectory"].as_str().unwrap_or(""))?);
    parts.push(filename);
    if parts.len() > 512 || parts.iter().map(|p| p.len() + 1).sum::<usize>() > 8192 {
        return Err("source-relative-path-limit");
    }
    Ok(parts.join("/"))
}

fn entry<'a>(source: &'a Artifact, record: &Value) -> Option<&'a Value> {
    let section = usize::try_from(record["section"].as_u64()?).ok()?;
    let row = usize::try_from(record["entry"].as_u64()?).ok()?;
    source.facts.get("windows.inf")?.get("sections")?.get(section)?.get("entries")?.get(row)
}

pub fn analyze(tree: &dyn Tree, out: &mut Output) {
    let Some(value) = tree.summary().get("engine.windows-source-roots") else { return };
    let roots = value
        .as_array()
        .filter(|roots| roots.len() <= 32)
        .and_then(|_| serde_json::from_value::<Vec<crate::source_roots::SourceRoot>>(value.clone()).ok())
        .and_then(|roots| crate::source_roots::validate(&roots).ok());
    let Some(roots) = roots else {
        out.limitation("windows.source-files-unresolved", None, Some("logical source-root settings were rejected".into()));
        return;
    };
    let complete = tree.summary().get("engine.input-listing").and_then(|v| v.get("complete")).and_then(Value::as_bool) == Some(true);
    let index = match crate::references::Index::for_distribution_roots(tree.artifacts(), complete) {
        Ok(index) => index,
        Err(reason) => {
            out.limitation("windows.source-files-limit", None, Some(reason.into()));
            return;
        }
    };
    let mut attempts_left = 4096usize;
    let mut bytes_left = 4 * 1024 * 1024usize;
    for root in roots {
        let sources: Vec<_> = tree.artifacts().iter().filter(|file| file.path.eq_ignore_ascii_case(&root.inf)).collect();
        if sources.len() != 1 {
            out.limitation(
                "windows.source-files-unresolved",
                None,
                Some(format!("configured logical INF {} is absent or ambiguous", root.inf)),
            );
            continue;
        }
        let source = sources[0];
        let Some(graph) = source.facts.get("windows.inf-declarations").filter(|g| g["omitted"] == 0) else {
            out.limitation("windows.source-files-unresolved", Some(source), Some("source declarations were unread or incomplete".into()));
            continue;
        };
        let mut records = Vec::new();
        let mut associated = 0;
        let mut unresolved = 0;
        let mut truncated = false;
        let mut finding = Finding::new(Section::Structure, "windows", "windows.inf-source-files", Confidence::Derived, Severity::Info)
            .param("root", root.root.as_str());
        let mut examples = 0;
        for relationship in
            graph["source_relationships"].as_array().into_iter().flatten().filter(|r| r["kind"] == "source-media-declaration")
        {
            let source_record =
                relationship["source_record"].as_u64().and_then(|v| usize::try_from(v).ok()).and_then(|i| graph["records"].get(i));
            let Some(source_record) = source_record else {
                unresolved += 1;
                continue;
            };
            let targets = relationship["target_records"].as_array();
            if relationship["declaration_namespace_complete"] != true
                || relationship["targets_truncated"] != false
                || targets.is_none_or(Vec::is_empty)
            {
                unresolved += 1;
                continue;
            }
            for target_record in targets.into_iter().flatten() {
                if attempts_left == 0 || bytes_left == 0 {
                    truncated = true;
                    break;
                }
                attempts_left -= 1;
                let media = target_record.as_u64().and_then(|v| usize::try_from(v).ok()).and_then(|i| graph["records"].get(i));
                let Some(media) = media else {
                    unresolved += 1;
                    continue;
                };
                let provenance = entry(source, source_record).is_some()
                    && entry(source, media).and_then(|e| e.get("fields")).and_then(Value::as_array).is_some_and(|v| v.len() <= 6);
                let relative = if provenance {
                    relative(&source_record["details"], &media["details"])
                } else {
                    Err("source-or-media-provenance-outside-profile")
                };
                let resolved = relative
                    .as_ref()
                    .map_err(|reason| *reason)
                    .and_then(|relative| index.resolve_distribution(source, &root.root, relative));
                let (target, reason) = match resolved {
                    Ok(target) => (Some(target), None),
                    Err(reason) => {
                        unresolved += 1;
                        (None, Some(reason))
                    }
                };
                let declared_size = source_record["details"]["declared_size"].as_str().unwrap_or("");
                let size_value = (!declared_size.is_empty() && declared_size.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| declared_size.parse::<u64>().ok())
                    .flatten();
                if !declared_size.is_empty() && size_value.is_none() {
                    unresolved += 1;
                }
                let size_check = if declared_size.is_empty() {
                    "not-declared"
                } else if size_value.is_none() {
                    "unsupported-size-declaration"
                } else if target.is_none() {
                    "target-unresolved"
                } else if target.is_some_and(|t| size_value == Some(t.size)) {
                    "agreement"
                } else {
                    "disagreement"
                };
                let value = json!({"source_record":relationship["source_record"],"media_record":target_record,"relative_path":relative.as_ref().ok(),
                    "status":if target.is_some(){"associated-supplied-artifact"}else if reason==Some("target-not-supplied-in-same-container"){"not-supplied-at-candidate-path"}else{"unresolved"},
                    "reason":reason,"target":target.map(|t|t.path.as_str()),"target_sha256":target.and_then(|t|t.digests.as_ref().map(|d|d.sha256.as_str())),
                    "declared_size":declared_size,"size_check":size_check,"size_agreement":target.and_then(|t|size_value.map(|size|size==t.size)),"platform_selected":false,
                    "payload_path_resolved":target.is_some()});
                let size = serde_json::to_vec(&value).map_or(bytes_left.saturating_add(1), |v| v.len());
                if size > bytes_left {
                    truncated = true;
                    break;
                }
                bytes_left -= size;
                records.push(value);
                if let Some(target) = target {
                    associated += 1;
                    if examples < 3 {
                        finding=finding.evidence(Evidence::field(source,format!("INF source line {}; media line {}",source_record["line"],media["line"]),
                            json!({"filename_literal":entry(source,source_record).and_then(|e|e.get("key")),
                                "source_fields_literal":entry(source,source_record).and_then(|e|e.get("fields")).and_then(Value::as_array).map(|v|v.iter().take(2).collect::<Vec<_>>()),
                                "media_path_literal":entry(source,media).and_then(|e|e.get("fields")).and_then(|v|v.get(3)),
                                "source_subdirectory_projection":source_record["details"]["subdirectory"],"media_path_projection":media["details"]["path"]})))
                            .evidence(Evidence::whole(target,target.digests.as_ref().map(|d|d.sha256.as_str())));
                        examples += 1;
                    }
                }
            }
            if truncated {
                break;
            }
        }
        if associated > 0 {
            out.finding(finding.param("count", associated));
        }
        if unresolved > 0 || records.is_empty() {
            out.limitation(
                "windows.source-files-unresolved",
                Some(source),
                Some("some source/media declarations or candidate paths were not resolved".into()),
            );
        }
        if truncated {
            out.limitation(
                "windows.source-files-limit",
                Some(source),
                Some("source mapping reached its attempt or output budget; remaining assignments may be unchecked".into()),
            );
        }
        out.fact(
            source,
            "windows.source-files",
            json!({"root":root.root,"basis":"caller-declared-logical-distribution-root","records":records,"truncated":truncated,
            "unresolved":unresolved,"platform_selected":false,"windows_installation_checked":false}),
        );
        if truncated {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_notation_is_root_relative_without_host_or_parent_resolution() {
        let source = json!({"filename_literal":"a.sys","subdirectory":"\\amd64\\.","extra_fields":[]});
        let media = json!({"path":"\\distribution\\","flags":"0x00","tag_or_cab":"","tag_file":""});
        assert_eq!(relative(&source, &media).expect("INF root-relative notation"), "distribution/amd64/a.sys");
        for path in ["\\\\server\\share", "C:\\data", "\\?\\device", "../outside", "data/../outside", "%12%", "[redacted]", "/host"] {
            let mut bad = media.clone();
            bad["path"] = json!(path);
            assert!(relative(&source, &bad).is_err(), "{path}");
        }
        for (key, value) in [("flags", "0x10"), ("tag_or_cab", "source.cab"), ("tag_file", "disk.tag")] {
            let mut bad = media.clone();
            bad[key] = json!(value);
            assert!(relative(&source, &bad).is_err());
        }
    }
}
