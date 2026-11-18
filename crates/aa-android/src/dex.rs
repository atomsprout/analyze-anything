//! DEX files: header, identifier tables and class definitions. Nothing is decompiled; code is
//! looked at only through the tables that name what it refers to.

use std::collections::{BTreeMap, BTreeSet};

use crate::reader::{Reader, slice_at, u16_at, u32_at};
use crate::strpool::decode_mutf8;

const MAX_STRING: usize = 64 * 1024;
const MAX_LISTED: usize = 50;
const ACC_NATIVE: u32 = 0x100;
const NO_INDEX: u32 = 0xffff_ffff;

/// A platform API whose mere presence in the method table is worth reporting.
pub struct Api {
    pub group: &'static str,
    pub class: &'static str,
    /// Method name, or `*` for any method of the class.
    pub method: &'static str,
}

const fn api(group: &'static str, class: &'static str, method: &'static str) -> Api {
    Api { group, class, method }
}

/// Grouped by what the report says about them.
pub const APIS: &[Api] = &[
    api("dynamic-code", "Ldalvik/system/DexClassLoader;", "<init>"),
    api("dynamic-code", "Ldalvik/system/PathClassLoader;", "<init>"),
    api("dynamic-code", "Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
    api("dynamic-code", "Ldalvik/system/DexFile;", "*"),
    api("command-exec", "Ljava/lang/Runtime;", "exec"),
    api("command-exec", "Ljava/lang/ProcessBuilder;", "start"),
    api("native-load", "Ljava/lang/System;", "loadLibrary"),
    api("native-load", "Ljava/lang/System;", "load"),
    api("native-load", "Ljava/lang/Runtime;", "loadLibrary"),
    api("native-load", "Ljava/lang/Runtime;", "load"),
    api("reflection", "Ljava/lang/reflect/Method;", "invoke"),
    api("reflection", "Ljava/lang/Class;", "forName"),
    api("webview-js-interface", "Landroid/webkit/WebView;", "addJavascriptInterface"),
    api("webview-js-enabled", "Landroid/webkit/WebSettings;", "setJavaScriptEnabled"),
    api("webview-file-access", "Landroid/webkit/WebSettings;", "setAllowUniversalAccessFromFileURLs"),
    api("webview-file-access", "Landroid/webkit/WebSettings;", "setAllowFileAccessFromFileURLs"),
    api("webview-debugging", "Landroid/webkit/WebView;", "setWebContentsDebuggingEnabled"),
    api("cipher", "Ljavax/crypto/Cipher;", "getInstance"),
    api("message-digest", "Ljava/security/MessageDigest;", "getInstance"),
    api("hostname-verifier-set", "Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier"),
    api("hostname-verifier-set", "Ljavax/net/ssl/HttpsURLConnection;", "setHostnameVerifier"),
    api("device-identifiers", "Landroid/telephony/TelephonyManager;", "getDeviceId"),
    api("device-identifiers", "Landroid/telephony/TelephonyManager;", "getImei"),
    api("device-identifiers", "Landroid/telephony/TelephonyManager;", "getMeid"),
    api("device-identifiers", "Landroid/telephony/TelephonyManager;", "getSubscriberId"),
    api("device-identifiers", "Landroid/telephony/TelephonyManager;", "getSimSerialNumber"),
    api("device-identifiers", "Landroid/telephony/TelephonyManager;", "getLine1Number"),
    api("device-identifiers", "Landroid/net/wifi/WifiInfo;", "getMacAddress"),
    api("location", "Landroid/location/LocationManager;", "requestLocationUpdates"),
    api("location", "Landroid/location/LocationManager;", "getLastKnownLocation"),
    api("location", "Landroid/location/LocationManager;", "getCurrentLocation"),
    api("sms-send", "Landroid/telephony/SmsManager;", "sendTextMessage"),
    api("sms-send", "Landroid/telephony/SmsManager;", "sendMultipartTextMessage"),
    api("sms-send", "Landroid/telephony/SmsManager;", "sendDataMessage"),
    api("audio-record", "Landroid/media/AudioRecord;", "startRecording"),
    api("audio-record", "Landroid/media/MediaRecorder;", "setAudioSource"),
    api("camera", "Landroid/hardware/Camera;", "open"),
    api("camera", "Landroid/hardware/camera2/CameraManager;", "openCamera"),
    api("installed-apps", "Landroid/content/pm/PackageManager;", "getInstalledPackages"),
    api("installed-apps", "Landroid/content/pm/PackageManager;", "getInstalledApplications"),
    api("clipboard-read", "Landroid/content/ClipboardManager;", "getPrimaryClip"),
    api("accounts", "Landroid/accounts/AccountManager;", "getAccounts"),
    api("screen-capture", "Landroid/media/projection/MediaProjectionManager;", "createScreenCaptureIntent"),
    api("accessibility-actions", "Landroid/accessibilityservice/AccessibilityService;", "dispatchGesture"),
    api("accessibility-actions", "Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction"),
    api("package-install", "Landroid/content/pm/PackageInstaller;", "createSession"),
];

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dex {
    /// The three digits after `dex\n`, e.g. `035`.
    pub version: String,
    pub file_size: u32,
    pub strings: u32,
    pub types: u32,
    pub protos: u32,
    pub fields: u32,
    pub methods: u32,
    pub classes: u32,
    /// Descriptors of the classes this file defines, e.g. `Lcom/example/Main;`.
    pub class_names: Vec<String>,
    pub native_methods: u32,
    /// `(index into APIS, method_ids index, "Lclass;->method")`.
    pub api_hits: Vec<(usize, u32, String)>,
    /// Defined classes that implement `javax.net.ssl.X509TrustManager`.
    pub trust_managers: Vec<String>,
    /// Defined classes that implement `javax.net.ssl.HostnameVerifier`.
    pub hostname_verifiers: Vec<String>,
    /// Defined classes with a method named `onReceivedSslError`.
    pub ssl_error_handlers: Vec<String>,
    /// String constants shaped like `Cipher.getInstance` transformations.
    pub cipher_strings: BTreeSet<String>,
    /// String constants naming weak message digests (`MD5`, `SHA-1`, `SHA1`).
    pub weak_digest_strings: BTreeSet<String>,
    /// Structural problems met while reading; the tables read before them are kept.
    pub problems: Vec<String>,
}

pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= 0x70 && data.starts_with(b"dex\n") && data[7] == 0 && data[4..7].iter().all(u8::is_ascii_digit)
}

struct Tables<'a> {
    data: &'a [u8],
    string_ids: (usize, usize),
    type_ids: (usize, usize),
}

impl<'a> Tables<'a> {
    fn string_bytes(&self, index: u32) -> Option<&'a [u8]> {
        let index = index as usize;
        if index >= self.string_ids.1 {
            return None;
        }
        let offset = u32_at(self.data, self.string_ids.0 + index * 4)? as usize;
        let mut reader = Reader::new(self.data.get(offset..)?);
        reader.uleb128()?;
        let rest = &reader.data[reader.pos..];
        let limit = rest.len().min(MAX_STRING);
        let end = rest[..limit].iter().position(|b| *b == 0).unwrap_or(limit);
        Some(&rest[..end])
    }

    fn string(&self, index: u32) -> Option<String> {
        self.string_bytes(index).map(decode_mutf8)
    }

    fn type_bytes(&self, index: u32) -> Option<&'a [u8]> {
        let index = index as usize;
        if index >= self.type_ids.1 {
            return None;
        }
        self.string_bytes(u32_at(self.data, self.type_ids.0 + index * 4)?)
    }

    fn type_name(&self, index: u32) -> Option<String> {
        self.type_bytes(index).map(decode_mutf8)
    }
}

/// A table's `(offset, count)` if it lies inside the file; the count is cut to what fits.
fn table(data: &[u8], count: u32, offset: u32, item: usize, what: &str, problems: &mut Vec<String>) -> (usize, usize) {
    let (count, offset) = (count as usize, offset as usize);
    if count == 0 {
        return (0, 0);
    }
    let fits = data.len().saturating_sub(offset) / item;
    if offset > data.len() || fits < count {
        problems.push(format!("the {what} table runs past the file"));
    }
    (offset, count.min(fits))
}

fn is_cipher_transformation(text: &[u8]) -> bool {
    const ALGORITHMS: [&[u8]; 9] = [b"AES", b"DESede", b"DES", b"RSA", b"Blowfish", b"RC4", b"ARCFOUR", b"ChaCha20", b"SM4"];
    if text.len() > 64 {
        return false;
    }
    let Some(algorithm) = ALGORITHMS.iter().find(|a| text.starts_with(a)) else { return false };
    let rest = &text[algorithm.len()..];
    // `AES` alone, `AES_256`, or `AES/CBC/PKCS5Padding`; anything else is some other word.
    rest.is_empty()
        || (rest[0] == b'/' && rest.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_')) && rest.len() > 1)
        || (rest[0] == b'_' && rest[1..].iter().all(u8::is_ascii_digit) && rest.len() > 1)
}

/// Reads one DEX file. `None` when the bytes do not start with a DEX header.
pub fn parse(data: &[u8]) -> Option<Dex> {
    if !is_dex(data) {
        return None;
    }
    let mut dex = Dex { version: String::from_utf8_lossy(&data[4..7]).into_owned(), ..Dex::default() };
    let field = |offset: usize| u32_at(data, offset).unwrap_or(0);
    dex.file_size = field(32);
    if dex.file_size as usize != data.len() {
        dex.problems.push(format!("the header says {} bytes, the file has {}", dex.file_size, data.len()));
    }
    if field(40) != 0x1234_5678 {
        dex.problems.push("unexpected endian tag".into());
    }
    let mut problems = Vec::new();
    let string_ids = table(data, field(56), field(60), 4, "string", &mut problems);
    let type_ids = table(data, field(64), field(68), 4, "type", &mut problems);
    let proto_ids = table(data, field(72), field(76), 12, "proto", &mut problems);
    let field_ids = table(data, field(80), field(84), 8, "field", &mut problems);
    let method_ids = table(data, field(88), field(92), 8, "method", &mut problems);
    let class_defs = table(data, field(96), field(100), 32, "class", &mut problems);
    dex.problems.extend(problems);
    dex.strings = string_ids.1 as u32;
    dex.types = type_ids.1 as u32;
    dex.protos = proto_ids.1 as u32;
    dex.fields = field_ids.1 as u32;
    dex.methods = method_ids.1 as u32;
    dex.classes = class_defs.1 as u32;
    let tables = Tables { data, string_ids, type_ids };

    // Which type indices are classes the API table cares about.
    let mut interesting: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let (mut trust_manager_type, mut hostname_verifier_type) = (None, None);
    for index in 0..type_ids.1 as u32 {
        let Some(name) = tables.type_bytes(index) else { continue };
        if !name.starts_with(b"L") {
            continue;
        }
        match name {
            b"Ljavax/net/ssl/X509TrustManager;" => trust_manager_type = Some(index),
            b"Ljavax/net/ssl/HostnameVerifier;" => hostname_verifier_type = Some(index),
            _ => {}
        }
        for (api_index, api) in APIS.iter().enumerate() {
            if api.class.as_bytes() == name {
                interesting.entry(index).or_default().push(api_index);
            }
        }
    }

    // Classes defined here, and the interfaces they implement.
    let mut defined: BTreeMap<u32, usize> = BTreeMap::new();
    let mut seen_class_data: BTreeSet<u32> = BTreeSet::new();
    for i in 0..class_defs.1 {
        let at = class_defs.0 + i * 32;
        let class_idx = field(at);
        let Some(name) = tables.type_name(class_idx) else {
            continue;
        };
        defined.insert(class_idx, dex.class_names.len());
        let interfaces_off = field(at + 12) as usize;
        if interfaces_off != 0
            && let Some(count) = u32_at(data, interfaces_off)
        {
            let count = (count as usize).min(data.len().saturating_sub(interfaces_off + 4) / 2).min(1024);
            for j in 0..count {
                let Some(interface) = u16_at(data, interfaces_off + 4 + j * 2).map(u32::from) else { break };
                if Some(interface) == trust_manager_type && dex.trust_managers.len() < MAX_LISTED {
                    dex.trust_managers.push(name.clone());
                }
                if Some(interface) == hostname_verifier_type && dex.hostname_verifiers.len() < MAX_LISTED {
                    dex.hostname_verifiers.push(name.clone());
                }
            }
        }
        // Native methods, from the class data. Several classes may share one item; count it once.
        let class_data_off = field(at + 24);
        if class_data_off != 0 && seen_class_data.insert(class_data_off) {
            if let Some(native) = count_native(data, class_data_off as usize) {
                dex.native_methods += native;
            } else if dex.problems.len() < 8 {
                dex.problems.push("a class data item is malformed".into());
            }
        }
        dex.class_names.push(name);
    }

    // Method references.
    let mut hits: BTreeSet<(usize, String)> = BTreeSet::new();
    for i in 0..method_ids.1 {
        let at = method_ids.0 + i * 8;
        let (Some(class_idx), Some(name_idx)) = (u16_at(data, at).map(u32::from), u32_at(data, at + 4)) else { break };
        if let Some(candidates) = interesting.get(&class_idx) {
            let Some(name) = tables.string_bytes(name_idx) else { continue };
            for api_index in candidates {
                let api = &APIS[*api_index];
                if (api.method == "*" || api.method.as_bytes() == name) && hits.insert((*api_index, String::from_utf8_lossy(name).into_owned())) {
                    dex.api_hits.push((*api_index, i as u32, format!("{}->{}", api.class, String::from_utf8_lossy(name))));
                }
            }
        }
        if let Some(class_position) = defined.get(&class_idx)
            && tables.string_bytes(name_idx) == Some(b"onReceivedSslError")
            && dex.ssl_error_handlers.len() < MAX_LISTED
            && let Some(name) = dex.class_names.get(*class_position)
            && !dex.ssl_error_handlers.contains(name)
        {
            dex.ssl_error_handlers.push(name.clone());
        }
    }

    // String constants.
    let uses_cipher = dex.api_hits.iter().any(|(i, _, _)| APIS[*i].group == "cipher");
    let uses_digest = dex.api_hits.iter().any(|(i, _, _)| APIS[*i].group == "message-digest");
    if uses_cipher || uses_digest {
        for index in 0..string_ids.1 as u32 {
            let Some(text) = tables.string_bytes(index) else { continue };
            if uses_cipher && is_cipher_transformation(text) && dex.cipher_strings.len() < 200 {
                dex.cipher_strings.insert(String::from_utf8_lossy(text).into_owned());
            }
            if uses_digest && matches!(text, b"MD5" | b"SHA-1" | b"SHA1" | b"MD4" | b"MD2") {
                dex.weak_digest_strings.insert(String::from_utf8_lossy(text).into_owned());
            }
        }
    }
    let _ = NO_INDEX;
    Some(dex)
}

fn count_native(data: &[u8], offset: usize) -> Option<u32> {
    let mut reader = Reader::new(slice_at(data, offset, data.len().checked_sub(offset)?)?);
    let static_fields = reader.uleb128()? as usize;
    let instance_fields = reader.uleb128()? as usize;
    let direct_methods = reader.uleb128()? as usize;
    let virtual_methods = reader.uleb128()? as usize;
    // Every item takes at least two bytes, which bounds the loops by the file size.
    let total = static_fields.checked_add(instance_fields)?.checked_add(direct_methods)?.checked_add(virtual_methods)?;
    if total > reader.remaining() / 2 {
        return None;
    }
    for _ in 0..static_fields + instance_fields {
        reader.uleb128()?;
        reader.uleb128()?;
    }
    let mut native = 0;
    for _ in 0..direct_methods + virtual_methods {
        reader.uleb128()?;
        let access = reader.uleb128()?;
        reader.uleb128()?;
        if access & ACC_NATIVE != 0 {
            native += 1;
        }
    }
    Some(native)
}

/// `com.example` for `Lcom/example/Main;`: the package of a class descriptor, dotted.
pub fn package_of(descriptor: &str) -> &str {
    let inner = descriptor.strip_prefix('L').unwrap_or(descriptor);
    match inner.rfind('/') {
        Some(slash) => &inner[..slash],
        None => "",
    }
}

/// The class name without its package and without the trailing `;`.
pub fn simple_name(descriptor: &str) -> &str {
    let inner = descriptor.strip_prefix('L').unwrap_or(descriptor).trim_end_matches(';');
    inner.rsplit('/').next().unwrap_or(inner)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn uleb(mut v: u32, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// A DEX with class `Lcom/example/Main;` implementing X509TrustManager, one native method,
    /// and references to `DexClassLoader.<init>` and `Cipher.getInstance`.
    pub fn sample() -> Vec<u8> {
        // Strings must be sorted in a real file; the reader does not rely on it.
        let strings: [&str; 10] = [
            "<init>",                           // 0
            "AES/ECB/PKCS5Padding",             // 1
            "Lcom/example/Main;",               // 2
            "Ldalvik/system/DexClassLoader;",   // 3
            "Ljavax/crypto/Cipher;",            // 4
            "Ljavax/net/ssl/X509TrustManager;", // 5
            "V",                                // 6
            "getInstance",                      // 7
            "nativeCall",                       // 8
            "Ljava/lang/Object;",               // 9
        ];
        let types: [u32; 6] = [2, 3, 4, 5, 6, 9];
        // (class type, proto, name string)
        let methods: [(u16, u16, u32); 3] = [(1, 0, 0), (2, 0, 7), (0, 0, 8)];
        let header = 0x70usize;
        let string_ids_off = header;
        let type_ids_off = string_ids_off + strings.len() * 4;
        let proto_ids_off = type_ids_off + types.len() * 4;
        let method_ids_off = proto_ids_off + 12;
        let class_defs_off = method_ids_off + methods.len() * 8;
        let data_off = class_defs_off + 32;
        let mut data_section = Vec::new();
        let mut string_offsets = Vec::new();
        for s in strings {
            string_offsets.push((data_off + data_section.len()) as u32);
            uleb(s.len() as u32, &mut data_section);
            data_section.extend_from_slice(s.as_bytes());
            data_section.push(0);
        }
        while data_section.len() % 4 != 0 {
            data_section.push(0);
        }
        let interfaces_off = data_off + data_section.len();
        data_section.extend_from_slice(&1u32.to_le_bytes());
        data_section.extend_from_slice(&3u16.to_le_bytes());
        data_section.extend_from_slice(&[0, 0]);
        let class_data_off = data_off + data_section.len();
        for v in [0u32, 0, 1, 0] {
            uleb(v, &mut data_section);
        }
        uleb(2, &mut data_section); // method index diff
        uleb(ACC_NATIVE | 1, &mut data_section);
        uleb(0, &mut data_section);

        let mut out = vec![0u8; header];
        out[..8].copy_from_slice(b"dex\n035\0");
        let mut put = |at: usize, v: u32| out[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(36, header as u32);
        put(40, 0x1234_5678);
        put(56, strings.len() as u32);
        put(60, string_ids_off as u32);
        put(64, types.len() as u32);
        put(68, type_ids_off as u32);
        put(72, 1);
        put(76, proto_ids_off as u32);
        put(88, methods.len() as u32);
        put(92, method_ids_off as u32);
        put(96, 1);
        put(100, class_defs_off as u32);
        for o in &string_offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        for t in types {
            out.extend_from_slice(&t.to_le_bytes());
        }
        out.extend_from_slice(&[6, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]); // proto: shorty, return type, no params
        for (class, proto, name) in methods {
            out.extend_from_slice(&class.to_le_bytes());
            out.extend_from_slice(&proto.to_le_bytes());
            out.extend_from_slice(&name.to_le_bytes());
        }
        let mut class_def = Vec::new();
        for v in [0u32, 1, 5, interfaces_off as u32, NO_INDEX, 0, class_data_off as u32, 0] {
            class_def.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&class_def);
        out.extend_from_slice(&data_section);
        let size = out.len() as u32;
        out[32..36].copy_from_slice(&size.to_le_bytes());
        out
    }

    #[test]
    fn reads_tables_and_references() {
        let data = sample();
        let dex = parse(&data).expect("dex");
        assert!(dex.problems.is_empty(), "{:?}", dex.problems);
        assert_eq!(dex.version, "035");
        assert_eq!((dex.strings, dex.types, dex.protos, dex.methods, dex.classes), (10, 6, 1, 3, 1));
        assert_eq!(dex.class_names, vec!["Lcom/example/Main;"]);
        assert_eq!(dex.native_methods, 1);
        assert_eq!(dex.trust_managers, vec!["Lcom/example/Main;"]);
        let groups: Vec<&str> = dex.api_hits.iter().map(|(i, _, _)| APIS[*i].group).collect();
        assert_eq!(groups, vec!["dynamic-code", "cipher"]);
        assert_eq!(dex.api_hits[0].2, "Ldalvik/system/DexClassLoader;-><init>");
        assert!(dex.cipher_strings.contains("AES/ECB/PKCS5Padding"));
    }

    #[test]
    fn truncations_and_corruption_do_not_panic() {
        let data = sample();
        for cut in 0..data.len() {
            let _ = parse(&data[..cut]);
        }
        for i in 8..data.len() {
            for v in [0u8, 0xff, 0x80] {
                let mut bad = data.clone();
                bad[i] = v;
                let _ = parse(&bad);
            }
        }
    }

    #[test]
    fn huge_counts_are_cut_to_the_file() {
        let mut data = sample();
        for at in [56, 64, 72, 80, 88, 96] {
            data[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        }
        let dex = parse(&data).expect("dex");
        assert!(!dex.problems.is_empty());
        assert!((dex.methods as usize) < data.len());
    }

    #[test]
    fn names() {
        assert_eq!(package_of("Lcom/example/a/Main;"), "com/example/a");
        assert_eq!(package_of("LMain;"), "");
        assert_eq!(simple_name("Lcom/example/a/Main$1;"), "Main$1");
        assert!(is_cipher_transformation(b"AES/GCM/NoPadding"));
        assert!(is_cipher_transformation(b"DES"));
        assert!(!is_cipher_transformation(b"DESCRIPTION"));
        assert!(!is_cipher_transformation(b"AES/"));
    }
}
