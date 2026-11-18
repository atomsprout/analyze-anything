//! The network security configuration (`res/xml/network_security_config.xml`).

use serde_json::{Value as Json, json};

use crate::xml::{Document, Element};

const MAX_CONFIGS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DomainConfig {
    /// `(domain, includeSubdomains)`.
    pub domains: Vec<(String, bool)>,
    pub cleartext_permitted: Option<bool>,
    pub trusts_user_cas: bool,
    pub pins: usize,
    pub pin_expiration: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkSecurityConfig {
    pub has_base_config: bool,
    pub base_cleartext_permitted: Option<bool>,
    pub base_trusts_user_cas: bool,
    /// Certificate sources other than `system` and `user` in the base config, e.g. `@raw/my_ca`.
    pub base_custom_anchors: Vec<String>,
    pub domain_configs: Vec<DomainConfig>,
    pub has_debug_overrides: bool,
    pub debug_trusts_user_cas: bool,
    pub truncated: bool,
}

fn attr<'a>(element: &'a Element, name: &str) -> Option<&'a crate::xml::Value> {
    element.attrs.iter().find(|a| a.name == name || a.raw_name == name).map(|a| &a.value)
}

fn anchors(element: &Element) -> (bool, Vec<String>) {
    let mut user = false;
    let mut custom = Vec::new();
    for anchors in element.children_named("trust-anchors") {
        for certificates in anchors.children_named("certificates").take(64) {
            match attr(certificates, "src").map(crate::xml::Value::display).as_deref() {
                Some("user") => user = true,
                Some("system") | None => {}
                Some(other) => custom.push(other.to_string()),
            }
        }
    }
    (user, custom)
}

/// Reads a decoded configuration. `None` when the root is not `<network-security-config>`.
pub fn parse(doc: &Document) -> Option<NetworkSecurityConfig> {
    let root = doc.root.as_ref().filter(|r| r.name == "network-security-config")?;
    let mut config = NetworkSecurityConfig { truncated: doc.truncated, ..NetworkSecurityConfig::default() };
    if let Some(base) = root.child("base-config") {
        config.has_base_config = true;
        config.base_cleartext_permitted = attr(base, "cleartextTrafficPermitted").and_then(crate::xml::Value::as_bool);
        let (user, custom) = anchors(base);
        config.base_trusts_user_cas = user;
        config.base_custom_anchors = custom;
    }
    if let Some(debug) = root.child("debug-overrides") {
        config.has_debug_overrides = true;
        config.debug_trusts_user_cas = anchors(debug).0;
    }
    // Domain configs nest; walk them with an explicit stack. A nested config inherits what it
    // does not set from its parent.
    let mut stack: Vec<(&Element, Option<bool>)> =
        root.children_named("domain-config").map(|e| (e, config.base_cleartext_permitted)).collect();
    stack.reverse();
    while let Some((element, inherited)) = stack.pop() {
        if config.domain_configs.len() >= MAX_CONFIGS {
            config.truncated = true;
            break;
        }
        let cleartext = attr(element, "cleartextTrafficPermitted").and_then(crate::xml::Value::as_bool).or(inherited);
        let mut entry = DomainConfig { cleartext_permitted: cleartext, trusts_user_cas: anchors(element).0, ..DomainConfig::default() };
        for domain in element.children_named("domain").take(1000) {
            let name = domain.text.trim();
            if !name.is_empty() {
                entry
                    .domains
                    .push((name.to_string(), attr(domain, "includeSubdomains").and_then(crate::xml::Value::as_bool).unwrap_or(false)));
            }
        }
        for pin_set in element.children_named("pin-set") {
            entry.pins += pin_set.children_named("pin").count();
            entry.pin_expiration = attr(pin_set, "expiration").map(crate::xml::Value::display);
        }
        config.domain_configs.push(entry);
        for nested in element.children_named("domain-config") {
            stack.push((nested, cleartext));
        }
    }
    Some(config)
}

impl NetworkSecurityConfig {
    pub fn cleartext_domains(&self) -> Vec<&str> {
        self.domain_configs
            .iter()
            .filter(|c| c.cleartext_permitted == Some(true))
            .flat_map(|c| c.domains.iter().map(|(d, _)| d.as_str()))
            .collect()
    }

    pub fn pinned_domains(&self) -> Vec<&str> {
        self.domain_configs.iter().filter(|c| c.pins > 0).flat_map(|c| c.domains.iter().map(|(d, _)| d.as_str())).collect()
    }

    pub fn to_json(&self) -> Json {
        json!({
            "base_config": self.has_base_config.then(|| json!({
                "cleartext_permitted": self.base_cleartext_permitted,
                "trusts_user_cas": self.base_trusts_user_cas,
                "custom_anchors": self.base_custom_anchors,
            })),
            "domain_configs": self.domain_configs.iter().take(200).map(|c| json!({
                "domains": c.domains.iter().map(|(d, sub)| json!({ "domain": d, "include_subdomains": sub })).collect::<Vec<_>>(),
                "cleartext_permitted": c.cleartext_permitted,
                "trusts_user_cas": c.trusts_user_cas,
                "pins": c.pins,
                "pin_expiration": c.pin_expiration,
            })).collect::<Vec<_>>(),
            "debug_overrides": self.has_debug_overrides.then(|| json!({ "trusts_user_cas": self.debug_trusts_user_cas })),
            "truncated": self.truncated || self.domain_configs.len() > 200,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{Attr, Value};

    fn a(name: &str, value: Value) -> Attr {
        Attr { ns: None, name: name.into(), raw_name: name.into(), res_id: None, value, raw: None }
    }

    fn el(name: &str, attrs: Vec<Attr>, children: Vec<Element>, text: &str) -> Element {
        Element { name: name.into(), attrs, children, text: text.into(), ..Element::default() }
    }

    #[test]
    fn reads_base_domain_pins_and_debug() {
        let user = || el("trust-anchors", vec![], vec![el("certificates", vec![a("src", Value::Str("user".into()))], vec![], "")], "");
        let root = el(
            "network-security-config",
            vec![],
            vec![
                el("base-config", vec![a("cleartextTrafficPermitted", Value::Bool(false))], vec![user()], ""),
                el(
                    "domain-config",
                    vec![a("cleartextTrafficPermitted", Value::Bool(true))],
                    vec![
                        el("domain", vec![a("includeSubdomains", Value::Bool(true))], vec![], "example.com"),
                        el("domain-config", vec![], vec![el("domain", vec![], vec![], "inner.example.com")], ""),
                    ],
                    "",
                ),
                el(
                    "domain-config",
                    vec![],
                    vec![
                        el("domain", vec![], vec![], "pinned.example"),
                        el(
                            "pin-set",
                            vec![a("expiration", Value::Str("2030-01-01".into()))],
                            vec![el("pin", vec![], vec![], "x"), el("pin", vec![], vec![], "y")],
                            "",
                        ),
                    ],
                    "",
                ),
                el("debug-overrides", vec![], vec![user()], ""),
            ],
            "",
        );
        let config = parse(&Document { root: Some(root), ..Document::default() }).expect("config");
        assert_eq!(config.base_cleartext_permitted, Some(false));
        assert!(config.base_trusts_user_cas);
        assert!(config.has_debug_overrides && config.debug_trusts_user_cas);
        assert_eq!(config.cleartext_domains(), vec!["example.com", "inner.example.com"]);
        assert_eq!(config.pinned_domains(), vec!["pinned.example"]);
        assert_eq!(config.domain_configs[2].pin_expiration.as_deref(), Some("2030-01-01"));
    }

    #[test]
    fn other_documents_are_not_configs() {
        assert!(parse(&Document::default()).is_none());
        assert!(parse(&Document { root: Some(el("manifest", vec![], vec![], "")), ..Document::default() }).is_none());
    }
}
