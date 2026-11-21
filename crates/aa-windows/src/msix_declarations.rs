//! Bounded declaration projections. These compare input metadata, never host applicability.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn resource_dimensions(rows: &[Value], supported: &str) -> Result<Value, &'static str> {
    if rows.len() > 200 {
        return Err("resource declaration count budget");
    }
    let mut languages = BTreeSet::new();
    let mut scales = BTreeSet::new();
    let mut levels = BTreeSet::new();
    let mut default_rows = 0;
    for row in rows {
        if row[supported] != true {
            return Err("resource row has unread, redacted or ambiguous structure");
        }
        if ["language", "scale", "dx_feature_level"].iter().any(|k| !row[k].is_null() && !row[k].is_string()) {
            return Err("resource field has an unsupported value type");
        }
        let mut fields = 0;
        if let Some(language) = row["language"].as_str() {
            fields += 1;
            if language.len() > 255
                || !language.is_ascii()
                || language.eq_ignore_ascii_case("x-generate")
                || language.split('-').any(|p| p.is_empty() || p.len() > 8 || !p.bytes().all(|b| b.is_ascii_alphanumeric()))
                || !language.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            {
                return Err("resource language is outside literal ASCII tag profile or is a build placeholder");
            }
            if !languages.insert(language.to_ascii_lowercase()) {
                return Err("resource language is repeated; no declaration selected");
            }
        }
        if let Some(scale) = row["scale"].as_str() {
            fields += 1;
            let scale = scale
                .parse::<u16>()
                .ok()
                .filter(|_| !scale.is_empty() && scale.bytes().all(|b| b.is_ascii_digit()))
                .filter(|n| [100, 120, 125, 140, 150, 160, 180, 200, 220, 225, 240, 250, 300, 400, 500].contains(n))
                .ok_or("resource scale is outside qualified SDK enumeration")?;
            if !scales.insert(scale) {
                return Err("resource scale is repeated; no declaration selected");
            }
        }
        if let Some(level) = row["dx_feature_level"].as_str() {
            fields += 1;
            if !matches!(level, "dx9" | "dx10" | "dx11") {
                return Err("resource DirectX feature level is unsupported");
            }
            if !levels.insert(level.to_string()) {
                return Err("resource DirectX feature level is repeated; no declaration selected");
            }
        }
        if fields > 1 {
            return Err("multiple qualifiers on one resource row are outside checked native profile");
        }
        if fields == 0 {
            default_rows += 1;
        }
    }
    if default_rows > 1 {
        return Err("default resource row is repeated");
    }
    Ok(json!({"languages":languages,"scales":scales,"dx_feature_levels":levels,"default_rows":default_rows}))
}

fn quad(value: &str) -> Option<Vec<u16>> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    parts
        .iter()
        .map(|p| if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) { None } else { p.parse().ok() })
        .collect()
}

pub(super) fn family_constraints(rows: &[Value]) -> Result<Value, &'static str> {
    if rows.len() > 128 {
        return Err("target-device-family count budget");
    }
    let mut names = BTreeSet::new();
    let mut families = BTreeMap::new();
    for row in rows {
        if row["projection_supported"] != true {
            return Err("target-device-family declaration is unread or ambiguous");
        }
        let fields = &row["attributes"];
        let name = fields["Name"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 255 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
            .ok_or("target-device-family name outside literal ASCII profile")?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err("target-device-family name or ASCII case alias is repeated");
        }
        let minimum =
            fields["MinVersion"].as_str().and_then(quad).filter(|v| v[0] > 0).ok_or("target-device minimum version unsupported")?;
        let tested =
            fields["MaxVersionTested"].as_str().and_then(quad).filter(|v| v[0] > 0).ok_or("target-device tested version unsupported")?;
        let display = |v: &[u16]| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
        families.insert(name, json!({"minimum":display(&minimum),"maximum_tested":display(&tested)}));
    }
    Ok(json!(families))
}

fn paired(profile: &str, declared: Result<Value, &str>, observed: Result<Value, &str>) -> Value {
    match (declared, observed) {
        (Ok(declared), Ok(observed)) => {
            json!({"profile":profile,"status":if declared==observed {"agrees"}else{"differs"},"declared":declared,"observed":observed})
        }
        (declared, observed) => {
            json!({"profile":profile,"status":"unresolved","declared":declared.as_ref().ok(),"observed":observed.as_ref().ok(),
            "declared_reason":declared.err(),"observed_reason":observed.err()})
        }
    }
}

pub(super) fn compare_resources(bundle: &Value, inner: &Value) -> Value {
    let rows = |model: &Value, key: &str| -> Result<Value, &'static str> {
        if model["resources_projection_established"] != true {
            return Err("resource projection is incomplete, unread or ambiguous");
        }
        resource_dimensions(model["resources"].as_array().ok_or("resource declarations absent")?, key)
    };
    let mut result =
        paired("resource-dimension-declarations-v1", rows(bundle, "projection_established"), rows(inner, "projection_supported"));
    result["language_aliases_and_fallbacks_resolved"] = json!(false);
    result["default_language_order_compared"] = json!(false);
    result["host_resource_selection_performed"] = json!(false);
    result
}

pub(super) fn compare_families(bundle: &Value, inner: &Value) -> Value {
    let mut result = if bundle["target_device_families_state"] == "not-declared" {
        json!({"profile":"target-device-declarations-v1","status":"not-declared","reason":"this bundle package has no target-device-family declaration; no inner absence inferred"})
    } else {
        let rows = |model: &Value| -> Result<Value, &'static str> {
            if model["target_device_families_projection_established"] != true {
                return Err("target-device-family projection is absent, unread or ambiguous");
            }
            family_constraints(model["target_device_families"].as_array().ok_or("target-device-family rows absent")?)
        };
        paired("target-device-declarations-v1", rows(bundle), rows(inner))
    };
    result["maximum_tested_is_compatibility_ceiling"] = json!(false);
    result["host_compatibility_checked"] = json!(false);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resource(field: &str, value: Value) -> Value {
        let mut row = json!({"projection_supported":true,"projection_established":true});
        row[field] = value;
        row
    }
    fn family(name: &str, min: &str, max: &str) -> Value {
        json!({"attributes":{"Name":name,"MinVersion":min,"MaxVersionTested":max},"projection_supported":true})
    }

    #[test]
    fn resource_dimension_sets_keep_case_rules_duplicates_and_unknowns_explicit() {
        let rows =
            vec![resource("language", json!("EN-us")), resource("scale", json!("0200")), resource("dx_feature_level", json!("dx11"))];
        let projection = resource_dimensions(&rows, "projection_supported").expect("qualified dimensions");
        assert_eq!(projection, json!({"languages":["en-us"],"scales":[200],"dx_feature_levels":["dx11"],"default_rows":0}));
        let mut reversed = rows.clone();
        reversed.reverse();
        assert_eq!(resource_dimensions(&reversed, "projection_supported").expect("order-independent sets"), projection);
        let mut duplicate = rows.clone();
        duplicate.push(resource("language", json!("en-US")));
        assert!(resource_dimensions(&duplicate, "projection_supported").is_err());
        for row in [
            resource("language", json!("x-generate")),
            resource("language", json!("en--US")),
            resource("language", json!("中文")),
            resource("scale", json!("65536")),
            resource("scale", json!("80")),
            resource("scale", json!(200)),
            resource("dx_feature_level", json!("dx12")),
            json!({"language":"en-US","scale":"200","projection_supported":true}),
        ] {
            assert!(resource_dimensions(&[row], "projection_supported").is_err());
        }
        assert!(resource_dimensions(&vec![rows[0].clone(); 201], "projection_supported").is_err());
        let outer = json!({"resources":rows,"resources_projection_established":true});
        let inner = json!({"resources":reversed,"resources_projection_established":true});
        assert_eq!(compare_resources(&outer, &inner)["status"], "agrees");
        let mut inner = inner;
        inner["resources_projection_established"] = json!(false);
        assert_eq!(compare_resources(&outer, &inner)["status"], "unresolved");
    }

    #[test]
    fn device_family_versions_are_declarations_and_absence_is_not_an_inner_constraint() {
        let row = family("Windows.Desktop", "010.0.17763.0", "10.0.26100.0");
        let projection = family_constraints(std::slice::from_ref(&row)).expect("canonical numeric quads");
        assert_eq!(projection["Windows.Desktop"]["minimum"], "10.0.17763.0");
        assert!(family_constraints(&[row.clone(), family("windows.desktop", "10.0.17763.0", "10.0.26100.0")]).is_err());
        for minimum in ["0.0.0.0", "10.0.65536.0", "10.1", "10.-1.0.0"] {
            assert!(family_constraints(&[family("Windows.Desktop", minimum, "10.0.26100.0")]).is_err());
        }
        assert!(family_constraints(&vec![row.clone(); 129]).is_err());
        let model = json!({"target_device_families":[row],"target_device_families_projection_established":true,"target_device_families_state":"projected"});
        let result = compare_families(&model, &model);
        assert_eq!(result["status"], "agrees");
        assert_eq!(result["maximum_tested_is_compatibility_ceiling"], false);
        let mut old = model.clone();
        old["target_device_families_state"] = json!("not-declared");
        assert_eq!(compare_families(&old, &model)["status"], "not-declared");
        let mut changed = model.clone();
        changed["target_device_families"][0]["attributes"]["MaxVersionTested"] = json!("10.0.22621.0");
        assert_eq!(compare_families(&model, &changed)["status"], "differs");
    }
}
