//! Captured package identities, kept separate from unresolved dependency declarations.

use aa_core::plugin::Tree;

use super::{Component, text};

pub(super) fn collect(tree: &dyn Tree, found: &mut Vec<Component>) {
    for artifact in tree.artifacts() {
        for (key, ecosystem) in [("wheel.package", "pypi"), ("npm.package", "npm")] {
            let Some(package) = artifact.facts.get(key) else { continue };
            let (Some(name), Some(version), Some(source)) =
                (text(package, "name"), text(package, "version"), text(package, "source_metadata"))
            else {
                continue;
            };
            if tree.get(source).is_some() {
                found.push(Component {
                    ecosystem,
                    name: name.into(),
                    version: Some(version.into()),
                    kind: "library",
                    declared_range: None,
                    source: source.into(),
                });
            }
        }
        let Some(package) = artifact.facts.get("java.jar") else { continue };
        let mut maven = false;
        for coordinate in package["maven"].as_array().into_iter().flatten() {
            if coordinate["path_identity_agrees"] != true {
                continue;
            }
            let (Some(group), Some(name), Some(version), Some(source)) =
                (text(coordinate, "group_id"), text(coordinate, "artifact_id"), text(coordinate, "version"), text(coordinate, "source"))
            else {
                continue;
            };
            if tree.get(source).is_some() {
                found.push(Component {
                    ecosystem: "maven",
                    name: format!("{group}/{name}"),
                    version: Some(version.into()),
                    kind: "library",
                    declared_range: None,
                    source: source.into(),
                });
                maven = true;
            }
        }
        // A manifest title is a literal software identity, never a Maven coordinate.
        if !maven
            && let (Some(name), Some(version), Some(source)) =
                (text(package, "name"), text(package, "version"), text(package, "source_manifest"))
            && tree.get(source).is_some()
        {
            found.push(Component {
                ecosystem: "java",
                name: name.into(),
                version: Some(version.into()),
                kind: "library",
                declared_range: None,
                source: source.into(),
            });
        }
    }
}

fn encoded(value: &str) -> String {
    let mut result = String::new();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(byte as char);
        } else {
            result.push('%');
            result.push(HEX[(byte >> 4) as usize] as char);
            result.push(HEX[(byte & 15) as usize] as char);
        }
    }
    result
}

pub(super) fn purl(ecosystem: &str, name: &str, version: &str) -> Option<String> {
    // Follow the ecosystem definitions in package-url/purl-spec/types: PyPI
    // normalizes names; npm scopes and Maven group IDs remain namespace parts.
    let name = match ecosystem {
        "pypi" => {
            if !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) {
                return None;
            }
            let mut normalized = String::new();
            for byte in name.bytes() {
                if matches!(byte, b'-' | b'_' | b'.') {
                    if !normalized.ends_with('-') {
                        normalized.push('-');
                    }
                } else {
                    normalized.push(byte.to_ascii_lowercase() as char);
                }
            }
            normalized
        }
        "npm" if name.starts_with('@') => {
            let (scope, name) = name.split_once('/')?;
            if scope.len() < 2 || name.is_empty() || name.contains('/') || scope[1..].contains('@') || name.contains('@') {
                return None;
            }
            format!("{}/{}", encoded(scope), encoded(name))
        }
        "npm" => {
            if name.is_empty() || name.contains(['/', '@']) {
                return None;
            }
            encoded(name)
        }
        "maven" => {
            let (group, name) = name.split_once('/')?;
            if group.is_empty() || name.is_empty() || name.contains('/') {
                return None;
            }
            format!("{}/{}", encoded(group), encoded(name))
        }
        _ => return None,
    };
    let version = if ecosystem == "pypi" { version.to_ascii_lowercase() } else { version.to_string() };
    Some(format!("pkg:{ecosystem}/{name}@{}", encoded(&version)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_urls_normalize_only_the_ecosystem_defined_name_and_encode_reserved_values() {
        assert_eq!(purl("pypi", "Example__Pkg.Name", "1.0+LOCAL"), Some("pkg:pypi/example-pkg-name@1.0%2Blocal".into()));
        assert_eq!(purl("npm", "@Example/name", "1.0.0+build"), Some("pkg:npm/%40Example/name@1.0.0%2Bbuild".into()));
        assert_eq!(purl("maven", "org.example/demo", "1.0+build"), Some("pkg:maven/org.example/demo@1.0%2Bbuild".into()));
        assert!(purl("npm", "scope/too/many", "1").is_none());
        assert!(purl("maven", "title", "1").is_none());
    }
}
