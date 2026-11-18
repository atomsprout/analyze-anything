//! Reads the app's declarations out of a decoded `AndroidManifest.xml`.

use serde_json::{Value as Json, json};

use crate::arsc::Resolved;
use crate::xml::{Attr, Document, Element, Value};

pub const TOOLS_NS: &str = "http://schemas.android.com/tools";
const MAX_COMPONENTS: usize = 20_000;
const MAX_LIST: usize = 5_000;

/// Turns resource ids into names and values. Implemented by the resource table of the package.
pub trait Resolver {
    fn resolve(&self, id: u32) -> Option<Resolved>;
}

/// A resolver for a package without a readable resource table.
pub struct NoResources;

impl Resolver for NoResources {
    fn resolve(&self, _id: u32) -> Option<Resolved> {
        None
    }
}

/// An attribute value after following a resource reference.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Text {
    /// The literal or resolved value. `None` when a reference could not be resolved.
    pub value: Option<String>,
    /// `@type/name` (or `@0x…` when the name is not known) when the attribute was a reference.
    pub reference: Option<String>,
}

impl Text {
    pub fn to_json(&self) -> Json {
        match &self.reference {
            Some(reference) => json!({ "value": self.value, "resource": reference }),
            None => json!(self.value),
        }
    }

    /// The value, or the reference when the value is unknown.
    pub fn shown(&self) -> Option<String> {
        self.value.clone().or_else(|| self.reference.clone())
    }
}

fn resolve_value(value: &Value, resolver: &dyn Resolver) -> (Value, Option<String>) {
    match value {
        Value::Ref(id) => match resolver.resolve(*id) {
            Some(resolved) => {
                let reference = resolved.name.map(|n| format!("@{n}")).unwrap_or_else(|| format!("@0x{id:08x}"));
                (resolved.value.unwrap_or(Value::Null), Some(reference))
            }
            None => (Value::Null, Some(format!("@0x{id:08x}"))),
        },
        other => (other.clone(), None),
    }
}

fn text(attr: Option<&Attr>, resolver: &dyn Resolver) -> Option<Text> {
    let attr = attr?;
    let (value, reference) = resolve_value(&attr.value, resolver);
    let value = match value {
        Value::Null => None,
        // A reference that still points at a resource after following the chain.
        Value::Ref(_) => None,
        other => Some(other.display()),
    };
    Some(Text { value, reference })
}

fn string(attr: Option<&Attr>, resolver: &dyn Resolver) -> Option<String> {
    text(attr, resolver).and_then(|t| t.value)
}

fn boolean(attr: Option<&Attr>, resolver: &dyn Resolver) -> Option<bool> {
    resolve_value(&attr?.value, resolver).0.as_bool()
}

fn integer(attr: Option<&Attr>, resolver: &dyn Resolver) -> Option<i64> {
    resolve_value(&attr?.value, resolver).0.as_i64()
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UsesPermission {
    pub name: String,
    pub max_sdk: Option<i64>,
    /// `uses-permission-sdk-23`: requested on Android 6 and later only.
    pub sdk23: bool,
    /// `usesPermissionFlags` has `neverForLocation`.
    pub never_for_location: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeclaredPermission {
    pub name: String,
    pub protection_level: Option<i64>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DataSpec {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub path_prefix: Option<String>,
    pub path_pattern: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<DataSpec>,
    pub auto_verify: Option<bool>,
    pub priority: Option<i64>,
}

impl IntentFilter {
    pub fn is_launcher(&self) -> bool {
        self.actions.iter().any(|a| a == "android.intent.action.MAIN")
            && self.categories.iter().any(|c| c == "android.intent.category.LAUNCHER" || c == "android.intent.category.LEANBACK_LAUNCHER")
    }

    pub fn is_browsable(&self) -> bool {
        self.categories.iter().any(|c| c == "android.intent.category.BROWSABLE")
    }

    fn to_json(&self) -> Json {
        let data: Vec<Json> = self
            .data
            .iter()
            .map(|d| {
                json!({
                    "scheme": d.scheme, "host": d.host, "port": d.port, "path": d.path,
                    "path_prefix": d.path_prefix, "path_pattern": d.path_pattern, "mime_type": d.mime_type,
                })
            })
            .collect();
        json!({ "actions": self.actions, "categories": self.categories, "data": data, "auto_verify": self.auto_verify, "priority": self.priority })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentKind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ComponentKind::Activity => "activity",
            ComponentKind::ActivityAlias => "activity-alias",
            ComponentKind::Service => "service",
            ComponentKind::Receiver => "receiver",
            ComponentKind::Provider => "provider",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetaData {
    pub name: String,
    pub value: Option<Text>,
    pub resource: Option<Text>,
}

/// How a component's `exported` state was arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportedBy {
    /// `android:exported` is set.
    Attribute,
    /// Not set; the component has an intent filter, which exports it on Android 11 and older.
    /// Android 12 and later refuse to install such a manifest when it targets API 31+.
    IntentFilter,
    /// Not set; the default for this kind of component and target SDK.
    Default,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub kind: ComponentKind,
    /// Fully qualified class name.
    pub name: String,
    pub enabled: Option<bool>,
    pub exported_attr: Option<bool>,
    pub exported: bool,
    pub exported_by: ExportedBy,
    pub permission: Option<String>,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
    pub authorities: Vec<String>,
    pub grant_uri_permissions: Option<bool>,
    pub process: Option<String>,
    pub launch_mode: Option<i64>,
    pub task_affinity: Option<String>,
    pub target_activity: Option<String>,
    pub foreground_service_type: Option<i64>,
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<MetaData>,
    pub offset: Option<u64>,
}

impl Component {
    pub fn is_launcher(&self) -> bool {
        self.intent_filters.iter().any(IntentFilter::is_launcher)
    }

    /// The permission a caller must hold: the component's own, else the application's.
    pub fn guard<'a>(&'a self, application_permission: Option<&'a str>) -> Option<&'a str> {
        self.permission.as_deref().or(application_permission)
    }

    pub fn to_json(&self) -> Json {
        json!({
            "kind": self.kind.as_str(),
            "name": self.name,
            "enabled": self.enabled,
            "exported_attribute": self.exported_attr,
            "exported": self.exported,
            "exported_by": match self.exported_by {
                ExportedBy::Attribute => "attribute",
                ExportedBy::IntentFilter => "intent-filter",
                ExportedBy::Default => "default",
            },
            "permission": self.permission,
            "read_permission": self.read_permission,
            "write_permission": self.write_permission,
            "authorities": self.authorities,
            "grant_uri_permissions": self.grant_uri_permissions,
            "process": self.process,
            "launch_mode": self.launch_mode.map(launch_mode_name),
            "task_affinity": self.task_affinity,
            "target_activity": self.target_activity,
            "foreground_service_type": self.foreground_service_type,
            "intent_filters": self.intent_filters.iter().map(IntentFilter::to_json).collect::<Vec<_>>(),
            "meta_data": self.meta_data.iter().map(|m| json!({ "name": m.name })).collect::<Vec<_>>(),
        })
    }
}

pub fn launch_mode_name(mode: i64) -> String {
    match mode {
        0 => "standard".into(),
        1 => "singleTop".into(),
        2 => "singleTask".into(),
        3 => "singleInstance".into(),
        4 => "singleInstancePerTask".into(),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Application {
    pub name: Option<String>,
    pub label: Option<Text>,
    pub icon: Option<Text>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<Text>,
    pub extract_native_libs: Option<bool>,
    pub test_only: Option<bool>,
    pub has_code: Option<bool>,
    pub large_heap: Option<bool>,
    pub full_backup_content: Option<Text>,
    pub data_extraction_rules: Option<Text>,
    pub backup_agent: Option<String>,
    pub request_legacy_external_storage: Option<bool>,
    pub app_component_factory: Option<String>,
    pub permission: Option<String>,
    pub process: Option<String>,
    pub task_affinity: Option<String>,
    pub meta_data: Vec<MetaData>,
    pub uses_libraries: Vec<(String, Option<bool>)>,
    pub uses_native_libraries: Vec<(String, Option<bool>)>,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Manifest {
    pub package: Option<String>,
    pub version_code: Option<i64>,
    pub version_name: Option<String>,
    pub min_sdk: Option<i64>,
    pub target_sdk: Option<i64>,
    pub max_sdk: Option<i64>,
    pub compile_sdk: Option<i64>,
    pub compile_sdk_codename: Option<String>,
    pub platform_build_version_name: Option<String>,
    pub shared_user_id: Option<String>,
    /// Name of the split when this is a split APK.
    pub split: Option<String>,
    pub config_for_split: Option<String>,
    pub is_feature_split: Option<bool>,
    pub install_location: Option<i64>,
    /// True when the manifest has a `<uses-sdk>` element.
    pub has_uses_sdk: bool,
    pub application: Option<Application>,
    pub uses_permissions: Vec<UsesPermission>,
    pub permissions: Vec<DeclaredPermission>,
    pub components: Vec<Component>,
    pub queries_packages: Vec<String>,
    pub queries_intents: Vec<String>,
    pub queries_providers: Vec<String>,
    pub uses_features: Vec<(String, Option<bool>)>,
    pub gl_es_version: Option<i64>,
    pub instrumentation: Vec<String>,
    /// `tools:` attributes left in the compiled manifest, as `element@attribute`.
    pub tools_leftovers: Vec<String>,
    pub truncated: bool,
}

impl Manifest {
    /// The target SDK the platform assumes: the declared one, else the minimum, else 1.
    pub fn effective_target_sdk(&self) -> i64 {
        self.target_sdk.or(self.min_sdk).unwrap_or(1)
    }

    pub fn launcher_activities(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.is_launcher() && c.enabled != Some(false)).collect()
    }
}

/// The Android version an API level belongs to.
pub fn android_version(api: i64) -> Option<&'static str> {
    Some(match api {
        1 => "1.0",
        2 => "1.1",
        3 => "1.5",
        4 => "1.6",
        5 => "2.0",
        6 => "2.0.1",
        7 => "2.1",
        8 => "2.2",
        9 => "2.3",
        10 => "2.3.3",
        11 => "3.0",
        12 => "3.1",
        13 => "3.2",
        14 => "4.0",
        15 => "4.0.3",
        16 => "4.1",
        17 => "4.2",
        18 => "4.3",
        19 => "4.4",
        20 => "4.4W",
        21 => "5.0",
        22 => "5.1",
        23 => "6.0",
        24 => "7.0",
        25 => "7.1",
        26 => "8.0",
        27 => "8.1",
        28 => "9",
        29 => "10",
        30 => "11",
        31 => "12",
        32 => "12L",
        33 => "13",
        34 => "14",
        35 => "15",
        36 => "16",
        _ => return None,
    })
}

/// `API 34 (Android 14)`, or just `API 99` for a level without a release name.
pub fn sdk_label(api: i64) -> String {
    match android_version(api) {
        Some(version) => format!("API {api} (Android {version})"),
        None => format!("API {api}"),
    }
}

fn qualify(package: Option<&str>, name: &str) -> String {
    match package {
        Some(package) if name.starts_with('.') => format!("{package}{name}"),
        Some(package) if !name.contains('.') && !name.is_empty() => format!("{package}.{name}"),
        _ => name.to_string(),
    }
}

fn meta_data(element: &Element, resolver: &dyn Resolver) -> Vec<MetaData> {
    element
        .children_named("meta-data")
        .take(MAX_LIST)
        .filter_map(|m| {
            Some(MetaData {
                name: string(m.android("name"), resolver)?,
                value: text(m.android("value"), resolver),
                resource: text(m.android("resource"), resolver),
            })
        })
        .collect()
}

fn intent_filter(element: &Element, resolver: &dyn Resolver) -> IntentFilter {
    let names = |tag: &str| -> Vec<String> {
        element.children_named(tag).take(MAX_LIST).filter_map(|c| string(c.android("name"), resolver)).collect()
    };
    let data = element
        .children_named("data")
        .take(MAX_LIST)
        .map(|d| DataSpec {
            scheme: string(d.android("scheme"), resolver),
            host: string(d.android("host"), resolver),
            port: string(d.android("port"), resolver),
            path: string(d.android("path"), resolver),
            path_prefix: string(d.android("pathPrefix"), resolver),
            path_pattern: string(d.android("pathPattern"), resolver),
            mime_type: string(d.android("mimeType"), resolver),
        })
        .collect();
    IntentFilter {
        actions: names("action"),
        categories: names("category"),
        data,
        auto_verify: boolean(element.android("autoVerify"), resolver),
        priority: integer(element.android("priority"), resolver),
    }
}

fn component(kind: ComponentKind, element: &Element, package: Option<&str>, target_sdk: i64, resolver: &dyn Resolver) -> Option<Component> {
    let name = qualify(package, &string(element.android("name"), resolver)?);
    let intent_filters: Vec<IntentFilter> = element.children_named("intent-filter").take(MAX_LIST).map(|f| intent_filter(f, resolver)).collect();
    let exported_attr = boolean(element.android("exported"), resolver);
    let (exported, exported_by) = match exported_attr {
        Some(value) => (value, ExportedBy::Attribute),
        None if kind == ComponentKind::Provider => (target_sdk < 17, ExportedBy::Default),
        None if !intent_filters.is_empty() => (true, ExportedBy::IntentFilter),
        None => (false, ExportedBy::Default),
    };
    let authorities = string(element.android("authorities"), resolver)
        .map(|a| a.split(';').filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    Some(Component {
        kind,
        name,
        enabled: boolean(element.android("enabled"), resolver),
        exported_attr,
        exported,
        exported_by,
        permission: string(element.android("permission"), resolver),
        read_permission: string(element.android("readPermission"), resolver),
        write_permission: string(element.android("writePermission"), resolver),
        authorities,
        grant_uri_permissions: boolean(element.android("grantUriPermissions"), resolver),
        process: string(element.android("process"), resolver),
        launch_mode: integer(element.android("launchMode"), resolver),
        task_affinity: string(element.android("taskAffinity"), resolver),
        target_activity: string(element.android("targetActivity"), resolver).map(|t| qualify(package, &t)),
        foreground_service_type: integer(element.android("foregroundServiceType"), resolver),
        intent_filters,
        meta_data: meta_data(element, resolver),
        offset: element.offset,
    })
}

fn collect_tools(element: &Element, out: &mut Vec<String>, budget: &mut usize) {
    // Iterative walk: the tree's depth is bounded by the decoder, its size by `budget`.
    let mut stack = vec![element];
    while let Some(current) = stack.pop() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        for attr in &current.attrs {
            if attr.ns.as_deref() == Some(TOOLS_NS) && out.len() < 100 {
                out.push(format!("{}@tools:{}", current.name, attr.name));
            }
        }
        stack.extend(current.children.iter());
    }
}

/// Reads a manifest. `None` when the document's root is not `<manifest>`.
pub fn extract(doc: &Document, resolver: &dyn Resolver) -> Option<Manifest> {
    let root = doc.root.as_ref().filter(|r| r.name == "manifest")?;
    let mut m = Manifest { truncated: doc.truncated, ..Manifest::default() };
    m.package = root.plain("package").and_then(|a| a.value.as_str()).map(str::to_string);
    let package = m.package.clone();
    let package = package.as_deref();
    let code = integer(root.android("versionCode"), resolver);
    let major = integer(root.android("versionCodeMajor"), resolver);
    m.version_code = match (code, major) {
        (Some(code), Some(major)) => Some((major << 32) | (code & 0xffff_ffff)),
        (code, _) => code,
    };
    m.version_name = string(root.android("versionName"), resolver);
    m.compile_sdk = integer(root.android("compileSdkVersion"), resolver);
    m.compile_sdk_codename = string(root.android("compileSdkVersionCodename"), resolver);
    m.platform_build_version_name = root.plain("platformBuildVersionName").map(|a| a.value.display());
    m.shared_user_id = string(root.android("sharedUserId"), resolver);
    m.split = root.plain("split").and_then(|a| a.value.as_str()).map(str::to_string);
    m.config_for_split = root.plain("configForSplit").and_then(|a| a.value.as_str()).map(str::to_string);
    m.is_feature_split = boolean(root.android("isFeatureSplit"), resolver);
    m.install_location = integer(root.android("installLocation"), resolver);

    if let Some(sdk) = root.child("uses-sdk") {
        m.has_uses_sdk = true;
        m.min_sdk = integer(sdk.android("minSdkVersion"), resolver);
        m.target_sdk = integer(sdk.android("targetSdkVersion"), resolver);
        m.max_sdk = integer(sdk.android("maxSdkVersion"), resolver);
    }
    let target_sdk = m.effective_target_sdk();

    for child in root.children.iter().take(MAX_COMPONENTS) {
        match child.name.as_str() {
            "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                if let Some(name) = string(child.android("name"), resolver)
                    && m.uses_permissions.len() < MAX_LIST
                {
                    m.uses_permissions.push(UsesPermission {
                        name,
                        max_sdk: integer(child.android("maxSdkVersion"), resolver),
                        sdk23: child.name != "uses-permission",
                        never_for_location: integer(child.android("usesPermissionFlags"), resolver).is_some_and(|f| f & 0x10000 != 0),
                    });
                }
            }
            "permission" => {
                if let Some(name) = string(child.android("name"), resolver)
                    && m.permissions.len() < MAX_LIST
                {
                    m.permissions.push(DeclaredPermission {
                        name,
                        protection_level: integer(child.android("protectionLevel"), resolver),
                        group: string(child.android("permissionGroup"), resolver),
                    });
                }
            }
            "uses-feature" => {
                if let Some(version) = integer(child.android("glEsVersion"), resolver) {
                    m.gl_es_version = Some(version);
                }
                if let Some(name) = string(child.android("name"), resolver)
                    && m.uses_features.len() < MAX_LIST
                {
                    m.uses_features.push((name, boolean(child.android("required"), resolver)));
                }
            }
            "queries" => {
                for query in child.children.iter().take(MAX_LIST) {
                    match query.name.as_str() {
                        "package" => m.queries_packages.extend(string(query.android("name"), resolver)),
                        "provider" => m.queries_providers.extend(string(query.android("authorities"), resolver)),
                        "intent" => {
                            let filter = intent_filter(query, resolver);
                            let schemes: Vec<&str> = filter.data.iter().filter_map(|d| d.scheme.as_deref()).collect();
                            let mut shown = filter.actions.join(",");
                            if !schemes.is_empty() {
                                shown.push_str(&format!(" [{}]", schemes.join(",")));
                            }
                            m.queries_intents.push(shown);
                        }
                        _ => {}
                    }
                }
            }
            "instrumentation" => m.instrumentation.extend(string(child.android("name"), resolver).map(|n| qualify(package, &n))),
            _ => {}
        }
    }

    if let Some(app) = root.child("application") {
        let mut application = Application {
            name: string(app.android("name"), resolver).map(|n| qualify(package, &n)),
            label: text(app.android("label"), resolver),
            icon: text(app.android("icon"), resolver),
            debuggable: boolean(app.android("debuggable"), resolver),
            allow_backup: boolean(app.android("allowBackup"), resolver),
            uses_cleartext_traffic: boolean(app.android("usesCleartextTraffic"), resolver),
            network_security_config: text(app.android("networkSecurityConfig"), resolver),
            extract_native_libs: boolean(app.android("extractNativeLibs"), resolver),
            test_only: boolean(app.android("testOnly"), resolver),
            has_code: boolean(app.android("hasCode"), resolver),
            large_heap: boolean(app.android("largeHeap"), resolver),
            full_backup_content: text(app.android("fullBackupContent"), resolver),
            data_extraction_rules: text(app.android("dataExtractionRules"), resolver),
            backup_agent: string(app.android("backupAgent"), resolver).map(|n| qualify(package, &n)),
            request_legacy_external_storage: boolean(app.android("requestLegacyExternalStorage"), resolver),
            app_component_factory: string(app.android("appComponentFactory"), resolver),
            permission: string(app.android("permission"), resolver),
            process: string(app.android("process"), resolver),
            task_affinity: string(app.android("taskAffinity"), resolver),
            meta_data: meta_data(app, resolver),
            uses_libraries: Vec::new(),
            uses_native_libraries: Vec::new(),
            offset: app.offset,
        };
        for child in app.children.iter() {
            let kind = match child.name.as_str() {
                "activity" => ComponentKind::Activity,
                "activity-alias" => ComponentKind::ActivityAlias,
                "service" => ComponentKind::Service,
                "receiver" => ComponentKind::Receiver,
                "provider" => ComponentKind::Provider,
                "uses-library" => {
                    if let Some(name) = string(child.android("name"), resolver) {
                        application.uses_libraries.push((name, boolean(child.android("required"), resolver)));
                    }
                    continue;
                }
                "uses-native-library" => {
                    if let Some(name) = string(child.android("name"), resolver) {
                        application.uses_native_libraries.push((name, boolean(child.android("required"), resolver)));
                    }
                    continue;
                }
                _ => continue,
            };
            if m.components.len() >= MAX_COMPONENTS {
                m.truncated = true;
                break;
            }
            m.components.extend(component(kind, child, package, target_sdk, resolver));
        }
        m.application = Some(application);
    }
    // `testOnly` is an application attribute; older tools also wrote it on the root.
    let mut budget = 500_000usize;
    collect_tools(root, &mut m.tools_leftovers, &mut budget);
    m.tools_leftovers.sort();
    m.tools_leftovers.dedup();
    Some(m)
}

impl Manifest {
    /// The manifest as a fact. Components are capped; the cap is visible in `truncated`.
    pub fn to_json(&self, component_cap: usize) -> Json {
        let app = self.application.as_ref();
        let meta = |list: &[MetaData]| -> Vec<Json> {
            list.iter()
                .take(500)
                .map(|m| {
                    let secret = crate::metadata::classify(&m.name).is_some_and(|k| k.secret);
                    let value = m.value.as_ref().map(|v| if secret { json!(v.value.as_deref().map(crate::redact)) } else { v.to_json() });
                    json!({ "name": m.name, "value": value, "resource": m.resource.as_ref().map(Text::to_json) })
                })
                .collect()
        };
        json!({
            "package": self.package,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "max_sdk": self.max_sdk,
            "compile_sdk": self.compile_sdk,
            "compile_sdk_codename": self.compile_sdk_codename,
            "platform_build_version_name": self.platform_build_version_name,
            "shared_user_id": self.shared_user_id,
            "split": self.split,
            "config_for_split": self.config_for_split,
            "is_feature_split": self.is_feature_split,
            "install_location": self.install_location,
            "application": app.map(|a| json!({
                "name": a.name,
                "label": a.label.as_ref().map(Text::to_json),
                "icon": a.icon.as_ref().map(Text::to_json),
                "debuggable": a.debuggable,
                "allow_backup": a.allow_backup,
                "uses_cleartext_traffic": a.uses_cleartext_traffic,
                "network_security_config": a.network_security_config.as_ref().map(Text::to_json),
                "extract_native_libs": a.extract_native_libs,
                "test_only": a.test_only,
                "has_code": a.has_code,
                "large_heap": a.large_heap,
                "full_backup_content": a.full_backup_content.as_ref().map(Text::to_json),
                "data_extraction_rules": a.data_extraction_rules.as_ref().map(Text::to_json),
                "backup_agent": a.backup_agent,
                "request_legacy_external_storage": a.request_legacy_external_storage,
                "app_component_factory": a.app_component_factory,
                "permission": a.permission,
                "process": a.process,
                "task_affinity": a.task_affinity,
                "meta_data": meta(&a.meta_data),
                "uses_libraries": a.uses_libraries.iter().map(|(n, r)| json!({ "name": n, "required": r })).collect::<Vec<_>>(),
                "uses_native_libraries": a.uses_native_libraries.iter().map(|(n, r)| json!({ "name": n, "required": r })).collect::<Vec<_>>(),
            })),
            "uses_features": self.uses_features.iter().map(|(n, r)| json!({ "name": n, "required": r })).collect::<Vec<_>>(),
            "gl_es_version": self.gl_es_version,
            "queries": { "packages": self.queries_packages, "intents": self.queries_intents, "providers": self.queries_providers },
            "instrumentation": self.instrumentation,
            "components": self.components.iter().take(component_cap).map(Component::to_json).collect::<Vec<_>>(),
            "component_count": self.components.len(),
            "tools_leftovers": self.tools_leftovers,
            "truncated": self.truncated || self.components.len() > component_cap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::ANDROID_NS;

    fn attr(name: &str, value: Value) -> Attr {
        Attr { ns: Some(ANDROID_NS.into()), name: name.into(), raw_name: name.into(), res_id: None, value, raw: None }
    }

    fn plain(name: &str, value: &str) -> Attr {
        Attr { ns: None, name: name.into(), raw_name: name.into(), res_id: None, value: Value::Str(value.into()), raw: None }
    }

    fn el(name: &str, attrs: Vec<Attr>, children: Vec<Element>) -> Element {
        Element { name: name.into(), attrs, children, ..Element::default() }
    }

    fn named(tag: &str, name: &str) -> Element {
        el(tag, vec![attr("name", Value::Str(name.into()))], vec![])
    }

    fn filter(actions: &[&str]) -> Element {
        el("intent-filter", vec![], actions.iter().map(|a| named("action", a)).collect())
    }

    fn manifest(target: i32, app_children: Vec<Element>) -> Document {
        let root = el(
            "manifest",
            vec![plain("package", "com.example"), attr("versionCode", Value::Int(7))],
            vec![
                el("uses-sdk", vec![attr("minSdkVersion", Value::Int(21)), attr("targetSdkVersion", Value::Int(target))], vec![]),
                named("uses-permission", "android.permission.CAMERA"),
                el("application", vec![attr("label", Value::Ref(0x7f01_0000))], app_children),
            ],
        );
        Document { root: Some(root), ..Document::default() }
    }

    struct OneString;
    impl Resolver for OneString {
        fn resolve(&self, id: u32) -> Option<Resolved> {
            (id == 0x7f01_0000).then(|| Resolved {
                name: Some("string/app_name".into()),
                value: Some(Value::Str("Example".into())),
                config: Some("default".into()),
                configs: 1,
            })
        }
    }

    #[test]
    fn exported_follows_the_platform_rules() {
        let children = vec![
            el("activity", vec![attr("name", Value::Str(".Main".into()))], vec![filter(&["android.intent.action.VIEW"])]),
            el("service", vec![attr("name", Value::Str("Svc".into()))], vec![]),
            el("receiver", vec![attr("name", Value::Str("a.b.R".into())), attr("exported", Value::Bool(false))], vec![filter(&["x"])]),
            el("provider", vec![attr("name", Value::Str(".P".into())), attr("authorities", Value::Str("a;b".into()))], vec![]),
        ];
        let m = extract(&manifest(30, children.clone()), &OneString).expect("manifest");
        assert_eq!(m.package.as_deref(), Some("com.example"));
        assert_eq!(m.version_code, Some(7));
        assert_eq!(m.application.as_ref().and_then(|a| a.label.as_ref()).and_then(|l| l.value.as_deref()), Some("Example"));
        assert_eq!(m.application.as_ref().and_then(|a| a.label.as_ref()).and_then(|l| l.reference.as_deref()), Some("@string/app_name"));
        let by_name = |m: &Manifest, n: &str| m.components.iter().find(|c| c.name == n).cloned().expect("component");
        let main = by_name(&m, "com.example.Main");
        assert!(main.exported);
        assert_eq!(main.exported_by, ExportedBy::IntentFilter);
        assert!(!by_name(&m, "com.example.Svc").exported);
        assert!(!by_name(&m, "a.b.R").exported);
        let provider = by_name(&m, "com.example.P");
        assert!(!provider.exported);
        assert_eq!(provider.authorities, vec!["a", "b"]);
        // Providers were exported by default before API 17.
        let old = extract(&manifest(16, children), &OneString).expect("manifest");
        assert!(by_name(&old, "com.example.P").exported);
    }

    #[test]
    fn unresolved_reference_is_unknown_not_empty() {
        let m = extract(&manifest(34, vec![]), &NoResources).expect("manifest");
        let label = m.application.and_then(|a| a.label).expect("label");
        assert_eq!(label.value, None);
        assert_eq!(label.reference.as_deref(), Some("@0x7f010000"));
    }

    #[test]
    fn other_roots_are_not_manifests() {
        let doc = Document { root: Some(el("resources", vec![], vec![])), ..Document::default() };
        assert!(extract(&doc, &NoResources).is_none());
        assert!(extract(&Document::default(), &NoResources).is_none());
    }

    #[test]
    fn sdk_labels() {
        assert_eq!(sdk_label(34), "API 34 (Android 14)");
        assert_eq!(sdk_label(99), "API 99");
    }
}
