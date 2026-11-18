//! PE resources: the version block (VS_VERSIONINFO) and the application manifest.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::pe::{u16_at, u32_at};

/// The version resource of a PE file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VersionInfo {
    /// From the fixed block, as `a.b.c.d`.
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    /// The strings of the first string table (CompanyName, ProductName, …).
    pub strings: BTreeMap<String, String>,
    /// `(language id, code page)` pairs of the Translation value.
    pub translations: Vec<(u16, u16)>,
}

impl VersionInfo {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings.get(key).map(String::as_str).filter(|v| !v.is_empty())
    }

    pub fn json(&self) -> Value {
        json!({
            "file_version": self.file_version,
            "product_version": self.product_version,
            "strings": self.strings,
            "translations": self.translations.iter().map(|(l, c)| json!({ "language": l, "code_page": c })).collect::<Vec<_>>(),
        })
    }
}

struct Node<'a> {
    key: String,
    value: &'a [u8],
    /// Offset, inside the resource, of the first child.
    children: usize,
    end: usize,
}

fn align4(offset: usize) -> usize {
    offset.saturating_add(3) & !3
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Reads the node header at `at`. `text_value` says the value is a string, whose length field
/// is unreliable (words in some files, bytes in others), so the value runs to the node's end.
fn node(data: &[u8], at: usize, limit: usize, text_value: bool) -> Option<Node<'_>> {
    let length = u16_at(data, at)? as usize;
    let value_length = u16_at(data, at + 2)? as usize;
    let end = at.checked_add(length)?;
    if length < 6 || end > limit {
        return None;
    }
    let key_bytes = data.get(at + 6..end)?;
    let key_units = key_bytes.chunks_exact(2).position(|c| c == [0, 0])?;
    let key = utf16(&key_bytes[..key_units * 2]);
    let value_start = align4(at + 6 + key_units * 2 + 2).min(end);
    let value_end = if text_value { end } else { value_start.saturating_add(value_length).min(end) };
    Some(Node { key, value: data.get(value_start..value_end)?, children: align4(value_end), end })
}

/// The children of a node: every node between `start` and `end`.
fn children(data: &[u8], start: usize, end: usize, text_value: bool) -> Vec<Node<'_>> {
    let mut list = Vec::new();
    let mut at = start;
    while at + 6 <= end && list.len() < 256 {
        let Some(child) = node(data, at, end, text_value) else { break };
        at = align4(child.end);
        list.push(child);
    }
    list
}

fn dotted(high: u32, low: u32) -> String {
    format!("{}.{}.{}.{}", high >> 16, high & 0xffff, low >> 16, low & 0xffff)
}

/// Parses a `VS_VERSIONINFO` resource.
pub fn parse_version(data: &[u8]) -> Option<VersionInfo> {
    let root = node(data, 0, data.len(), false)?;
    if root.key != "VS_VERSION_INFO" {
        return None;
    }
    let mut info = VersionInfo::default();
    if root.value.len() >= 52 && u32_at(root.value, 0) == Some(0xfeef_04bd) {
        info.file_version = Some(dotted(u32_at(root.value, 8)?, u32_at(root.value, 12)?));
        info.product_version = Some(dotted(u32_at(root.value, 16)?, u32_at(root.value, 20)?));
    }
    for block in children(data, root.children, root.end, false) {
        match block.key.as_str() {
            "StringFileInfo" => {
                // Each table is one language; the first is the one Windows shows by default.
                for (index, table) in children(data, block.children, block.end, false).iter().enumerate() {
                    for string in children(data, table.children, table.end, true) {
                        let value = utf16(string.value).trim_end().to_string();
                        if index == 0 {
                            info.strings.insert(string.key, value);
                        } else {
                            info.strings.entry(string.key).or_insert(value);
                        }
                    }
                }
            }
            "VarFileInfo" => {
                for var in children(data, block.children, block.end, false) {
                    if var.key == "Translation" {
                        info.translations.extend(
                            var.value
                                .chunks_exact(4)
                                .take(64)
                                .map(|pair| (u16::from_le_bytes([pair[0], pair[1]]), u16::from_le_bytes([pair[2], pair[3]]))),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    Some(info)
}

/// What an application manifest declares.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub identity_name: Option<String>,
    pub identity_version: Option<String>,
    pub architecture: Option<String>,
    /// `asInvoker`, `highestAvailable` or `requireAdministrator`.
    pub execution_level: Option<String>,
    pub ui_access: Option<bool>,
    pub auto_elevate: Option<bool>,
    pub dpi_aware: Option<String>,
    pub dpi_awareness: Option<String>,
    pub long_path_aware: Option<bool>,
    pub supported_os: Vec<String>,
    /// `name version` of each dependent assembly.
    pub dependencies: Vec<String>,
}

impl Manifest {
    pub fn json(&self) -> Value {
        json!({
            "assembly_identity": { "name": self.identity_name, "version": self.identity_version, "architecture": self.architecture },
            "requested_execution_level": self.execution_level,
            "ui_access": self.ui_access,
            "auto_elevate": self.auto_elevate,
            "dpi_aware": self.dpi_aware,
            "dpi_awareness": self.dpi_awareness,
            "long_path_aware": self.long_path_aware,
            "supported_os": self.supported_os,
            "dependencies": self.dependencies,
        })
    }
}

fn supported_os_name(id: &str) -> Option<&'static str> {
    Some(match id.to_ascii_lowercase().as_str() {
        "{e2011457-1546-43c5-a5fe-008deee3d3f0}" => "Windows Vista",
        "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}" => "Windows 7",
        "{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}" => "Windows 8",
        "{1f676c76-80e1-4239-95bb-83d0f6d0da78}" => "Windows 8.1",
        "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" => "Windows 10/11",
        _ => return None,
    })
}

fn truthy(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Decodes XML bytes that may be UTF-8 (with or without a BOM) or UTF-16.
pub fn decode_xml(data: &[u8]) -> String {
    if let Some(rest) = data.strip_prefix(&[0xff, 0xfe]) {
        utf16(rest)
    } else if let Some(rest) = data.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data)).trim_end_matches('\0').to_string()
    }
}

/// Parses an application manifest (the RT_MANIFEST resource).
pub fn parse_manifest(data: &[u8]) -> Result<Manifest, String> {
    if data.len() > 4 * 1024 * 1024 {
        return Err("manifest larger than 4 MiB".into());
    }
    let text = decode_xml(data);
    let options = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let document = roxmltree::Document::parse_with_options(&text, options).map_err(|e| e.to_string())?;
    let mut manifest = Manifest::default();
    for element in document.descendants().filter(roxmltree::Node::is_element) {
        let text = || element.text().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
        match element.tag_name().name() {
            "assemblyIdentity" => {
                let name = element.attribute("name").unwrap_or_default();
                let version = element.attribute("version").unwrap_or_default();
                let dependent = element.ancestors().any(|a| a.tag_name().name() == "dependentAssembly");
                if dependent {
                    if manifest.dependencies.len() < 64 {
                        manifest.dependencies.push(format!("{name} {version}").trim().to_string());
                    }
                } else if manifest.identity_name.is_none() {
                    manifest.identity_name = Some(name.to_string()).filter(|n| !n.is_empty());
                    manifest.identity_version = Some(version.to_string()).filter(|v| !v.is_empty());
                    manifest.architecture = element.attribute("processorArchitecture").map(str::to_string);
                }
            }
            "requestedExecutionLevel" => {
                manifest.execution_level = element.attribute("level").map(str::to_string);
                manifest.ui_access = element.attribute("uiAccess").and_then(truthy);
            }
            "supportedOS" => {
                if let Some(id) = element.attribute("Id")
                    && manifest.supported_os.len() < 16
                {
                    manifest.supported_os.push(supported_os_name(id).map(str::to_string).unwrap_or_else(|| id.to_string()));
                }
            }
            "autoElevate" => manifest.auto_elevate = text().as_deref().and_then(truthy),
            "dpiAware" => manifest.dpi_aware = text(),
            "dpiAwareness" => manifest.dpi_awareness = text(),
            "longPathAware" => manifest.long_path_aware = text().as_deref().and_then(truthy),
            _ => {}
        }
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_fields_are_read() {
        let xml = include_bytes!("../tests/data/src/hello.manifest");
        let manifest = parse_manifest(xml).expect("manifest");
        assert_eq!(manifest.identity_name.as_deref(), Some("FixtureWorks.Hello"));
        assert_eq!(manifest.identity_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(manifest.execution_level.as_deref(), Some("requireAdministrator"));
        assert_eq!(manifest.ui_access, Some(false));
        assert_eq!(manifest.supported_os, ["Windows 10/11", "Windows 7"]);
        assert_eq!(manifest.dpi_awareness.as_deref(), Some("PerMonitorV2"));
        assert_eq!(manifest.dependencies, ["Microsoft.Windows.Common-Controls 6.0.0.0"]);
    }

    #[test]
    fn broken_manifest_is_an_error() {
        assert!(parse_manifest(b"<assembly><unclosed>").is_err());
        assert!(parse_manifest(b"").is_err());
        assert!(parse_manifest(&[0xff, 0xfe, 0x3c]).is_err());
    }

    #[test]
    fn version_parser_survives_garbage() {
        assert_eq!(parse_version(&[]), None);
        assert_eq!(parse_version(&[0xff; 64]), None);
        // A plausible header whose lengths point past the end.
        let mut data = vec![0u8; 40];
        data[0] = 0xff;
        data[1] = 0x7f;
        assert_eq!(parse_version(&data), None);
    }
}
