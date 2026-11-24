//! The same bounded queries serve the CLI, optional interpretation and read-only MCP.

use super::*;
use aa_core::{Artifact, Evidence};

const PAGE_BYTES: usize = 192 * 1024;

pub fn specs() -> Vec<Spec> {
    let mut specs = base_specs();
    let common = json!({
        "query": {"type":"string"}, "offset":{"type":"integer","minimum":0},
        "limit":{"type":"integer","minimum":1,"maximum":50},
        "artifact":{"type":"string","description":"Exact logical artifact path"},
        "under":{"type":"string","description":"Logical artifact path or its descendants"}
    });
    for (index, spec) in specs.iter_mut().enumerate() {
        for (key, value) in common.as_object().expect("fixed schema object") {
            if index != 1 || matches!(key.as_str(), "offset" | "limit") {
                spec.schema["properties"][key] = value.clone();
            }
        }
    }
    specs[0].description = "List findings, most severe first and then in report order. Filter original text, rule, confidence or evidence artifacts. Pages have next_offset; clipped text is marked.";
    specs[0].schema["properties"]["confidence"] = json!({"type":"string","enum":["verified","derived","heuristic"]});
    specs[0].schema["properties"]["rule"] = json!({"type":"string"});
    specs[0].schema["properties"]["evidence_query"] =
        json!({"type":"string","description":"Words in the original evidence, including values"});
    specs[1].description = "Get one finding and a page of its evidence. Use offset/limit to retrieve additional evidence; params and preview truncation are explicit.";
    specs[1].schema["properties"]["limit"]["maximum"] = json!(MAX_EVIDENCE);
    specs[2].schema["properties"]["limit"]["maximum"] = json!(MAX_FILES);
    specs[2].schema["properties"]["kind"] = json!({"type":"string"});
    specs[2].schema["properties"]["parent"] = json!({"type":"string"});
    specs[2].schema["properties"]["coverage"] =
        json!({"type":"string", "enum":["limited","without_recorded_limitations","unread","incomplete_container"]});
    specs[2].schema["properties"]["has_findings"] = json!({"type":"boolean"});
    for (name, description, extra, required) in [
        (
            "list_evidence",
            "List evidence with finding IDs, source ordinals, structured locations and bounded observed values. Filter artifacts, words, finding ID, location type, field or a byte position. Use next_offset for more.",
            json!({"id":{"type":"string"},"location":{"type":"string","enum":["bytes","field","whole"]},"field":{"type":"string"},"byte_offset":{"type":"integer","minimum":0}}),
            json!([]),
        ),
        (
            "list_limitations",
            "List recorded limitations, including run-wide gaps. An absence of limitations is not proof of semantic completeness. Filter code, artifact, descendants or words.",
            json!({"code":{"type":"string"},"run_wide":{"type":"boolean"}}),
            json!([]),
        ),
        (
            "get_file",
            "Get one captured artifact's metadata and a bounded page of its facts. No source file is opened. Fact previews identify clipping explicitly.",
            json!({"path":{"type":"string"},"fact":{"type":"string","description":"Exact fact key"}}),
            json!(["path"]),
        ),
        (
            "get_coverage",
            "Read overall coverage and counts for the selected logical artifacts and limitations. Limits and unread bytes are separate; no semantic-completeness percentage is inferred.",
            json!({}),
            json!([]),
        ),
    ] {
        let mut properties = common.clone();
        properties.as_object_mut().expect("fixed schema object").extend(extra.as_object().expect("fixed extra object").clone());
        if name == "get_file" {
            for key in ["artifact", "under", "query"] {
                properties.as_object_mut().expect("fixed schema").remove(key);
            }
        } else if name == "get_coverage" {
            for key in ["offset", "limit", "query"] {
                properties.as_object_mut().expect("fixed schema").remove(key);
            }
        }
        specs.push(Spec {
            name,
            description,
            schema: json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
        });
    }
    for spec in &mut specs {
        if let Some(properties) = spec.schema["properties"].as_object_mut() {
            for value in properties.values_mut().filter(|value| value["type"] == "string") {
                value["maxLength"] = json!(4096);
            }
        }
    }
    specs
}

fn string<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

fn matches_words(query: Option<&str>, value: &str) -> bool {
    query.is_none_or(|query| {
        let value = value.to_lowercase();
        query.split_whitespace().all(|word| value.contains(&word.to_lowercase()))
    })
}

fn path_matches(input: &Value, path: &str) -> bool {
    string(input, "artifact").is_none_or(|wanted| wanted == path)
        && string(input, "under").is_none_or(|root| {
            let root = root.trim_end_matches('/');
            root.is_empty() || path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))
        })
}

fn validate(spec: &Spec, input: &Value) -> Result<(), String> {
    let object = input.as_object().ok_or("query arguments must be an object")?;
    for key in spec.schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if !object.contains_key(key) {
            return Err(format!("{} needs `{key}`", spec.name));
        }
    }
    for (key, value) in object {
        let rule = &spec.schema["properties"][key];
        if rule.is_null() {
            return Err(format!("unknown {} argument `{key}`", spec.name));
        }
        let valid = match rule["type"].as_str() {
            Some("string") => value.as_str().is_some_and(|text| text.chars().count() <= 4096),
            Some("integer") => value.as_u64().is_some_and(|number| {
                rule["minimum"].as_u64().is_none_or(|minimum| number >= minimum)
                    && rule["maximum"].as_u64().is_none_or(|maximum| number <= maximum)
            }),
            Some("boolean") => value.is_boolean(),
            _ => false,
        };
        if !valid || rule["enum"].as_array().is_some_and(|values| !values.contains(value)) {
            return Err(format!("invalid {} argument `{key}`", spec.name));
        }
    }
    Ok(())
}

/// Count every match, but materialize only the requested page and a fixed byte budget.
fn page<T>(items: impl Iterator<Item = T>, input: &Value, default: usize, most: usize, key: &str, project: impl Fn(T) -> Value) -> Value {
    let offset = number(input, "offset", 0);
    let limit = number(input, "limit", default).min(most);
    let mut matching = 0usize;
    let mut rows = Vec::new();
    let mut used = 0usize;
    let mut budget_full = false;
    for item in items {
        let position = matching;
        matching += 1;
        if position < offset || rows.len() >= limit || budget_full {
            continue;
        }
        let row = project(item);
        let size = row.to_string().len();
        if used + size > PAGE_BYTES {
            budget_full = true;
            continue;
        }
        used += size;
        rows.push(row);
    }
    let returned = rows.len();
    let next = offset.saturating_add(returned);
    let mut result = json!({"matching":matching,"offset":offset,"limit":limit,"returned":returned,
        "next_offset": if next < matching { Some(next) } else { None },"has_more":next < matching,"page_byte_limit":PAGE_BYTES});
    result[key] = json!(rows);
    result
}

fn value_preview(value: &Value) -> Value {
    let text = match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    json!({"value":clip(&text, MAX_VALUE),"value_truncated":text.chars().count() > MAX_VALUE,
        "observed":if value.to_string().len() <= 4096 { Some(value) } else { None }})
}

fn evidence_row(evidence: &Evidence) -> Value {
    let (place, location, clipped) = match &evidence.location {
        Location::Bytes { offset, length } => {
            (format!("bytes {offset}..{}", offset.saturating_add(*length)), json!({"bytes":{"offset":offset,"length":length}}), false)
        }
        Location::Field(field) => {
            (format!("field {}", clip(field, MAX_VALUE)), json!({"field":clip(field, MAX_VALUE)}), field.chars().count() > MAX_VALUE)
        }
        Location::Whole => ("the whole file".into(), json!("whole"), false),
    };
    let mut result = value_preview(&evidence.value);
    result["file"] = json!(clip(&evidence.artifact, MAX_PATH));
    result["path_truncated"] = json!(evidence.artifact.chars().count() > MAX_PATH);
    result["sha256"] = evidence.sha256.as_ref().map(|value| json!(clip(value, MAX_VALUE))).unwrap_or(Value::Null);
    result["where"] = json!(place);
    result["location"] = location;
    result["location_truncated"] = json!(clipped);
    result
}

impl Tools<'_> {
    /// Queries read the report only. Source paths and all observed text remain untrusted data.
    pub fn call(&self, name: &str, input: &Value) -> Result<Value, String> {
        let spec = specs().into_iter().find(|spec| spec.name == name).ok_or_else(|| format!("there is no tool named {name}"))?;
        validate(&spec, input)?;
        match name {
            "list_findings" => Ok(self.list_findings(input)),
            "get_finding" => self.get_finding(input),
            "list_files" => Ok(self.list_files(input)),
            "list_evidence" => self.list_evidence(input),
            "list_limitations" => Ok(self.list_limitations(input)),
            "get_file" => self.get_file(input),
            "get_coverage" => Ok(self.get_coverage(input)),
            _ => Err("query is unavailable".into()),
        }
    }

    fn list_findings(&self, input: &Value) -> Value {
        let matching = self.order.iter().map(|index| &self.report.findings[*index]).filter(|finding| {
            string(input, "section").is_none_or(|value| word(&finding.section) == value)
                && string(input, "severity").is_none_or(|value| word(&finding.severity) == value)
                && string(input, "confidence").is_none_or(|value| word(&finding.confidence) == value)
                && string(input, "rule").is_none_or(|value| finding.rule == value)
                && (string(input, "artifact").is_none() && string(input, "under").is_none()
                    || finding.evidence.iter().any(|evidence| path_matches(input, &evidence.artifact)))
                && string(input, "evidence_query")
                    .is_none_or(|query| finding.evidence.iter().any(|evidence| matches_words(Some(query), &evidence.value.to_string())))
                && string(input, "query").is_none_or(|query| {
                    let (title, text) = self.words(&finding.rule, &finding.params);
                    let searchable = format!(
                        "{} {} {} {} {}",
                        finding.rule,
                        title,
                        text,
                        json!(finding.params),
                        finding.evidence.iter().map(|evidence| evidence.artifact.as_str()).collect::<Vec<_>>().join(" ")
                    );
                    matches_words(Some(query), &searchable)
                })
        });
        page(matching, input, 30, MAX_LIST, "findings", |finding| self.row(finding))
    }

    fn get_finding(&self, input: &Value) -> Result<Value, String> {
        let id = string(input, "id").ok_or("get_finding needs `id`")?;
        let finding = self.find(id).ok_or_else(|| format!("no unique finding has id {id}; take ids from list_findings"))?;
        let mut result = self.row(finding);
        let evidence = page(finding.evidence.iter(), input, MAX_EVIDENCE, MAX_EVIDENCE, "evidence", evidence_row);
        result["evidence"] = evidence["evidence"].clone();
        result["evidence_page"] = evidence;
        let mut params = BTreeMap::new();
        for (ordinal, (key, value)) in finding.params.iter().take(20).enumerate() {
            let mut key = clip(key, 100);
            if params.contains_key(&key) {
                key.push_str(&format!("#{ordinal}"));
            }
            params.insert(key, clip(&value.to_string(), MAX_VALUE));
        }
        result["values"] = json!(params);
        result["values_total"] = json!(finding.params.len());
        result["values_truncated"] = json!(
            finding.params.len() > 20
                || finding.params.iter().any(|(key, value)| key.chars().count() > 100 || value.to_string().chars().count() > MAX_VALUE)
        );
        result["references"] = json!(finding.references.iter().take(20).map(|value| clip(value, MAX_VALUE)).collect::<Vec<_>>());
        result["references_total"] = json!(finding.references.len());
        result["references_truncated"] =
            json!(finding.references.len() > 20 || finding.references.iter().any(|value| value.chars().count() > MAX_VALUE));
        Ok(result)
    }

    fn file_matches(&self, input: &Value, file: &Artifact) -> bool {
        path_matches(input, &file.path)
            && matches_words(string(input, "query"), &file.path)
            && string(input, "kind").is_none_or(|kind| file.kind.as_deref() == Some(kind))
            && string(input, "parent").is_none_or(|parent| file.parent.as_deref() == Some(parent))
            && input
                .get("has_findings")
                .and_then(Value::as_bool)
                .is_none_or(|wanted| self.with_findings.contains(file.path.as_str()) == wanted)
            && string(input, "coverage").is_none_or(|scope| match scope {
                "limited" => self.limited.contains(file.path.as_str()),
                "without_recorded_limitations" => !self.limited.contains(file.path.as_str()),
                "unread" => file.digests.is_none(),
                "incomplete_container" => file.facts.get("engine.container-listing").is_some_and(|value| value["complete"] == false),
                _ => false,
            })
    }

    fn file_row(&self, file: &Artifact) -> Value {
        json!({"path":clip(&file.path,MAX_PATH),"path_truncated":file.path.chars().count()>MAX_PATH,"size":file.size,
            "type":clip(file.kind.as_deref().unwrap_or(file.mime()),MAX_VALUE),"parent":file.parent.as_ref().map(|value|clip(value,MAX_PATH)),
            "parent_truncated":file.parent.as_ref().is_some_and(|value|value.chars().count()>MAX_PATH),
            "sha256":file.digests.as_ref().map(|digest|clip(&digest.sha256,MAX_VALUE)),"bytes_read":file.digests.is_some(),
            "has_limitations":self.limited.contains(file.path.as_str()),"has_findings":self.with_findings.contains(file.path.as_str()),
            "container_listing_complete":file.facts.get("engine.container-listing").and_then(|value|value.get("complete"))})
    }

    fn list_files(&self, input: &Value) -> Value {
        page(
            self.files.iter().map(|index| &self.report.artifacts[*index]).filter(|file| self.file_matches(input, file)),
            input,
            50,
            MAX_FILES,
            "files",
            |file| self.file_row(file),
        )
    }

    fn list_evidence(&self, input: &Value) -> Result<Value, String> {
        let finding = string(input, "id").map(|id| self.find(id).ok_or("no unique finding has this id")).transpose()?;
        let rows = self.order.iter().map(|index|&self.report.findings[*index]).filter(|candidate|finding.is_none_or(|finding|finding.id==candidate.id))
            .flat_map(|finding|finding.evidence.iter().enumerate().map(move |(index,evidence)|(finding,index,evidence)))
            .filter(|(_,_,evidence)| {
                path_matches(input,&evidence.artifact) && matches_words(string(input,"query"),&format!("{} {:?} {}",evidence.artifact,evidence.location,evidence.value))
                && string(input,"location").is_none_or(|kind| matches!((kind,&evidence.location),("bytes",Location::Bytes{..})|("field",Location::Field(_))|("whole",Location::Whole)))
                && string(input,"field").is_none_or(|name|matches!(&evidence.location,Location::Field(field) if field==name))
                && input.get("byte_offset").and_then(Value::as_u64).is_none_or(|position|matches!(&evidence.location,Location::Bytes{offset,length} if position.checked_sub(*offset).is_some_and(|delta|delta<*length)))
            });
        Ok(page(rows, input, 30, MAX_LIST, "evidence", |(finding, index, evidence)| {
            let mut row = evidence_row(evidence);
            row["finding_id"] = json!(finding.id);
            row["evidence_index"] = json!(index);
            row
        }))
    }

    fn list_limitations(&self, input: &Value) -> Value {
        let none = BTreeMap::new();
        page(
            self.report.limitations.iter().filter(|limit| {
                string(input, "code").is_none_or(|code| limit.code == code)
                    && input.get("run_wide").and_then(Value::as_bool).is_none_or(|wanted| limit.artifact.is_none() == wanted)
                    && limit
                        .artifact
                        .as_deref()
                        .map_or(string(input, "artifact").is_none() && string(input, "under").is_none(), |path| path_matches(input, path))
                    && matches_words(string(input, "query"), &format!("{} {:?} {:?}", limit.code, limit.artifact, limit.detail))
            }),
            input,
            30,
            MAX_LIST,
            "limitations",
            |limit| {
                let (title, text) = self.words(&limit.code, &none);
                json!({"code":clip(&limit.code,MAX_VALUE),"artifact":limit.artifact.as_ref().map(|path|clip(path,MAX_VALUE)),
                "title":clip(&title,MAX_TEXT),"text":clip(&text,MAX_TEXT),"detail":limit.detail.as_ref().map(|text|clip(text,MAX_TEXT)),
                "detail_truncated":limit.detail.as_ref().is_some_and(|text|text.chars().count()>MAX_TEXT)})
            },
        )
    }

    fn get_file(&self, input: &Value) -> Result<Value, String> {
        let path = string(input, "path").ok_or("get_file needs `path`")?;
        let mut matches = self.report.artifacts.iter().filter(|file| file.path == path);
        let file = matches.next().ok_or("no artifact has this path")?;
        if matches.next().is_some() {
            return Err("artifact path is ambiguous".into());
        }
        let mut result = self.file_row(file);
        result["facts"] = page(
            file.facts.iter().filter(|(key, _)| string(input, "fact").is_none_or(|wanted| *key == wanted)),
            input,
            20,
            MAX_LIST,
            "entries",
            |(key, value)| {
                let mut row = value_preview(value);
                row["key"] = json!(clip(key, MAX_VALUE));
                row["key_truncated"] = json!(key.chars().count() > MAX_VALUE);
                row
            },
        );
        Ok(result)
    }

    fn get_coverage(&self, input: &Value) -> Value {
        let files: Vec<_> = self.report.artifacts.iter().filter(|file| path_matches(input, &file.path)).collect();
        json!({"coverage":self.report.coverage,"selected_artifacts":files.len(),
        "selected_bytes_read":files.iter().filter(|file|file.digests.is_some()).count(),
        "selected_with_limitations":files.iter().filter(|file|self.limited.contains(file.path.as_str())).count(),
        "selected_limitations":self.report.limitations.iter().filter(|limit|limit.artifact.as_deref().is_some_and(|path|path_matches(input,path))).count(),
        "run_wide_limitations":self.report.limitations.iter().filter(|limit|limit.artifact.is_none()).count(),
        "limitations_total":self.report.limitations.len(),"note":match self.language {
            Language::En=>"No recorded limitation does not establish complete semantic understanding.",
            Language::Zh=>"没有记录局限，不代表已经完整理解全部语义。",
        }})
    }
}
