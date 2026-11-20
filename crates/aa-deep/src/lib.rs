//! The optional deep level: which code does what.
//!
//! The rest of the program reads a file's structure. It can say that a program imports
//! `dlopen` or holds an address, but not which of its functions use them: that takes
//! disassembling the code and following its references, which is what disassemblers are for.
//! With `--deep`, the program files of the input are handed to one that is installed on the
//! machine (Ghidra or Hopper), which is asked two things: which functions call the APIs of a
//! fixed list, and which functions use the addresses the content analyzer found in that file.
//!
//! This is the one place where the analysis starts another program, so it is off unless asked
//! for, and what it adds is kept apart: every finding names the tool and its version, is
//! `derived`, and is a neutral fact. The tool is given a copy of the file to read; nothing of
//! the input is run. Another version of the tool may read the code differently, so a report
//! made with this level is repeatable only with the same tool.

pub mod settings;
pub mod tool;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

pub use tool::{Asker, Facts, Format, Programs, Request, Tool, Use, User};

const ID: &str = "deep";
/// Most call sites or users shown as evidence of one finding.
const MAX_EVIDENCE: usize = 12;
/// Most functions named in a finding's sentence.
const MAX_NAMED: usize = 6;
/// Most addresses of one file the tool is asked about.
const MAX_STRINGS: usize = 40;
/// Most address findings written for one file.
const MAX_STRING_FINDINGS: usize = 20;

/// How the deep level runs.
#[derive(Clone)]
pub struct Settings {
    pub tool: Tool,
    /// Most program files of one input handed to the tool; the largest come first.
    pub max_files: usize,
    /// Longest the tool may spend on one program file.
    pub seconds: u64,
    /// Largest program file handed to the tool.
    pub max_bytes: u64,
}

impl Settings {
    pub fn new(tool: Tool) -> Self {
        Settings { tool, max_files: 4, seconds: 900, max_bytes: 256 * 1024 * 1024 }
    }
}

/// What a program does that a reader would want pointed at, and the functions that do it.
struct Category {
    rule: &'static str,
    apis: &'static [&'static str],
}

const CATEGORIES: &[Category] = &[
    Category {
        rule: "deep.calls-network",
        apis: &[
            "socket",
            "connect",
            "getaddrinfo",
            "gethostbyname",
            "sendto",
            "recvfrom",
            "NSURLSession",
            "NSURLConnection",
            "CFNetworkExecuteProxyAutoConfigurationURL",
            "curl_easy_perform",
            "WSAStartup",
            "WinHttpOpen",
            "WinHttpConnect",
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetConnectW",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
        ],
    },
    Category {
        rule: "deep.calls-process",
        apis: &[
            "system",
            "popen",
            "execve",
            "execv",
            "execvp",
            "execl",
            "posix_spawn",
            "posix_spawnp",
            "fork",
            "NSTask",
            "CreateProcessA",
            "CreateProcessW",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
            "WinExec",
        ],
    },
    Category {
        rule: "deep.calls-loading",
        apis: &[
            "dlopen",
            "dlsym",
            "NSCreateObjectFileImageFromMemory",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
        ],
    },
    Category {
        rule: "deep.calls-crypto",
        apis: &[
            "CCCrypt",
            "CCCryptorCreate",
            "CC_MD5",
            "CC_SHA1",
            "CC_SHA256",
            "CCHmac",
            "SecKeyCreateEncryptedData",
            "SecKeyEncrypt",
            "EVP_EncryptInit_ex",
            "EVP_DecryptInit_ex",
            "AES_encrypt",
            "AES_set_encrypt_key",
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "BCryptEncrypt",
            "BCryptDecrypt",
        ],
    },
    Category {
        rule: "deep.calls-debugger",
        apis: &[
            "ptrace",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringA",
            "OutputDebugStringW",
        ],
    },
    Category {
        rule: "deep.calls-other-processes",
        apis: &[
            "task_for_pid",
            "mach_vm_write",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "OpenProcess",
        ],
    },
    Category {
        rule: "deep.calls-secrets",
        apis: &[
            "SecItemCopyMatching",
            "SecItemAdd",
            "SecItemUpdate",
            "SecKeychainFindGenericPassword",
            "CryptUnprotectData",
            "CredReadA",
            "CredReadW",
        ],
    },
];

const RULES: &[Rule] = &[
    Rule {
        id: "deep.analyzed",
        title_zh: "由反汇编器深入分析",
        title_en: "Read in depth by a disassembler",
        text_zh: "{tool} {version} 反汇编了这个文件的 {arch} 代码，识别出 {functions} 个函数。下面注明出自该工具的结论依赖它的分析；换一个版本，读出的结果可能不同。",
        text_en: "{tool} {version} disassembled the {arch} code of this file and made out {functions} functions. The findings below that name the tool rest on its analysis; another version of it may read the code differently.",
    },
    Rule {
        id: "deep.calls-network",
        title_zh: "发起网络连接的代码",
        title_en: "Code that opens network connections",
        text_zh: "有 {count} 个函数使用了联网相关的接口（{apis}）：{users}。出自 {tool} {version}。",
        text_en: "{count} functions use networking APIs ({apis}): {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.calls-process",
        title_zh: "启动其他程序的代码",
        title_en: "Code that starts other programs",
        text_zh: "有 {count} 个函数使用了启动程序或执行命令的接口（{apis}）：{users}。出自 {tool} {version}。",
        text_en: "{count} functions use APIs that start a program or run a command ({apis}): {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.calls-loading",
        title_zh: "在运行时加载代码的代码",
        title_en: "Code that loads code at run time",
        text_zh: "有 {count} 个函数使用了运行时加载代码的接口（{apis}）：{users}。出自 {tool} {version}。",
        text_en: "{count} functions use APIs that load code while the program runs ({apis}): {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.calls-crypto",
        title_zh: "加密或计算摘要的代码",
        title_en: "Code that encrypts or hashes",
        text_zh: "有 {count} 个函数使用了加密或摘要接口（{apis}）：{users}。出自 {tool} {version}。",
        text_en: "{count} functions use encryption or digest APIs ({apis}): {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.calls-debugger",
        title_zh: "检查或使用调试器的代码",
        title_en: "Code that looks for or uses a debugger",
        text_zh: "有 {count} 个函数使用了与调试器相关的接口（{apis}）：{users}。调试工具和反调试检查都会用到它们。出自 {tool} {version}。",
        text_en: "{count} functions use debugger-related APIs ({apis}): {users}. Debugging tools and checks against being debugged both use them. From {tool} {version}.",
    },
    Rule {
        id: "deep.calls-other-processes",
        title_zh: "读写其他进程的代码",
        title_en: "Code that reaches into other processes",
        text_zh: "有 {count} 个函数使用了打开、读取或改写其他进程的接口（{apis}）：{users}。出自 {tool} {version}。",
        text_en: "{count} functions use APIs that open, read or write another process ({apis}): {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.calls-secrets",
        title_zh: "读写系统保管的密钥和凭据的代码",
        title_en: "Code that reads or writes secrets the system keeps",
        text_zh: "有 {count} 个函数使用了钥匙串或凭据存储的接口（{apis}）：{users}。出自 {tool} {version}。",
        text_en: "{count} functions use keychain or credential-store APIs ({apis}): {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.address-users",
        title_zh: "使用某个地址的代码",
        title_en: "Code that uses an address",
        text_zh: "地址 {address} 被 {count} 个函数引用：{users}。出自 {tool} {version}。",
        text_en: "The address {address} is referred to by {count} functions: {users}. From {tool} {version}.",
    },
    Rule {
        id: "deep.failed",
        title_zh: "反汇编器没有给出结果",
        title_en: "The disassembler gave no answer",
        text_zh: "深入分析没有完成，这个文件没有函数级的结论；其余分析不受影响。",
        text_en: "The deep level did not finish for this file, so there are no function-level findings about it; the rest of the analysis is unaffected.",
    },
    Rule {
        id: "deep.not-asked",
        title_zh: "没有交给反汇编器的程序文件",
        title_en: "Program files not given to the disassembler",
        text_zh: "深入分析一次只处理有限数量、有限大小的程序文件；这些文件没有函数级的结论。",
        text_en: "The deep level takes a limited number of program files of a limited size; there are no function-level findings about these.",
    },
];

/// The analyzer that asks `settings.tool`. Register it before the analyzers that summarise.
pub fn analyzer(settings: Settings) -> Arc<dyn Analyzer> {
    Arc::new(Deep { settings, asker: Arc::new(Programs) })
}

/// The same, asking through `asker`; for tests.
pub fn analyzer_with(settings: Settings, asker: Arc<dyn Asker>) -> Arc<dyn Analyzer> {
    Arc::new(Deep { settings, asker })
}

struct Deep {
    settings: Settings,
    asker: Arc<dyn Asker>,
}

/// A folder of this run's own, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Scratch> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let number = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("aa-deep-{}-{number}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        // The real path, not one through a link: Ghidra looks its script up by the real path
        // and does not find it when it was named through `/var` on a Mac.
        Ok(Scratch(std::fs::canonicalize(&path).unwrap_or(path)))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The part of a program file that is handed to the tool.
struct Slice {
    format: Format,
    /// Where the part starts in the artifact; 0 unless it was taken out of a universal binary.
    offset: u64,
    length: u64,
    /// The processor, in plain words, when it is known before the tool is asked.
    arch: Option<&'static str>,
}

/// The processor a program file is for, read from its header, in plain words.
fn arch(format: Format, bytes: &[u8]) -> Option<&'static str> {
    let at = |offset: usize, length: usize| bytes.get(offset..offset + length);
    match format {
        Format::MachO => {
            let magic = at(0, 4)?;
            let big = magic == [0xfe, 0xed, 0xfa, 0xce] || magic == [0xfe, 0xed, 0xfa, 0xcf];
            let cpu = at(4, 4)
                .map(|b| if big { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) })?;
            mach_cpu(cpu)
        }
        Format::Elf => {
            let big = at(5, 1)? == [2];
            let machine = at(18, 2).map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })?;
            match machine {
                3 => Some("x86"),
                40 => Some("arm"),
                62 => Some("x86_64"),
                183 => Some("arm64"),
                243 => Some("RISC-V"),
                _ => None,
            }
        }
        Format::Pe => {
            let header = at(0x3c, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)?;
            let machine = at(header.checked_add(4)?, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))?;
            match machine {
                0x014c => Some("x86"),
                0x8664 => Some("x86_64"),
                0x01c0 | 0x01c4 => Some("arm"),
                0xaa64 => Some("arm64"),
                _ => None,
            }
        }
    }
}

fn mach_cpu(cpu: u32) -> Option<&'static str> {
    match cpu {
        0x0100_000c => Some("arm64"),
        0x0100_0007 => Some("x86_64"),
        0x0000_000c => Some("arm"),
        0x0000_0007 => Some("x86"),
        _ => None,
    }
}

/// Picks what to hand over from `bytes`, which the binary analyzer named `kind`.
fn slice(kind: &str, bytes: &[u8]) -> Option<Slice> {
    let whole = |format| Some(Slice { format, offset: 0, length: bytes.len() as u64, arch: arch(format, bytes) });
    match kind {
        "elf" => whole(Format::Elf),
        "pe" => whole(Format::Pe),
        "macho" => whole(Format::MachO),
        "macho-fat" => {
            // A universal binary holds one program per processor; one of them is read, the
            // 64-bit ARM one when there is one, as that is what current Apple devices run.
            let word = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            let long = |at: usize| Some(((word(at)? as u64) << 32) | word(at + 4)? as u64);
            let wide = word(0)? == 0xcafe_babf;
            let count = word(4)?.min(32) as usize;
            let mut best: Option<Slice> = None;
            for index in 0..count {
                let at = 8 + index * if wide { 32 } else { 20 };
                let cpu = word(at)?;
                let (offset, length) = if wide { (long(at + 8)?, long(at + 16)?) } else { (word(at + 8)? as u64, word(at + 12)? as u64) };
                if offset.checked_add(length).is_none_or(|end| end > bytes.len() as u64) || length == 0 {
                    continue;
                }
                let arch = mach_cpu(cpu);
                let better = match &best {
                    None => true,
                    Some(current) => current.arch != Some("arm64") && arch == Some("arm64"),
                };
                if better {
                    best = Some(Slice { format: Format::MachO, offset, length, arch });
                }
            }
            best
        }
        _ => None,
    }
}

/// "name (0x1000), other (0x2000) and 3 more": the functions of `users`, for a sentence.
fn named(users: &[User], total: u64) -> String {
    let mut text: Vec<String> = users.iter().take(MAX_NAMED).map(|user| format!("{} (0x{:x})", user.function, user.address)).collect();
    let shown = text.len() as u64;
    if total > shown {
        text.push(format!("… +{}", total - shown));
    }
    text.join(", ")
}

/// Evidence for the places `users` point at inside `artifact`.
fn evidence(mut finding: Finding, artifact: &Artifact, part: &Slice, users: &[(Option<&str>, &User)]) -> Finding {
    for (what, user) in users.iter().take(MAX_EVIDENCE) {
        let mut value = json!({ "function": user.function, "function_address": format!("0x{:x}", user.address), "address": format!("0x{:x}", user.at) });
        if let Some(what) = what {
            value["uses"] = json!(what);
        }
        finding = finding.evidence(match user.offset {
            // One byte marks where the instruction starts; its length depends on the processor.
            Some(offset) if offset < part.length => Evidence::bytes(artifact, part.offset + offset, 1, value),
            _ => Evidence::field(artifact, format!("code at 0x{:x}", user.at), value),
        });
    }
    finding
}

impl Deep {
    fn one(&self, tree: &dyn Tree, artifact: &Artifact, out: &mut Output) -> Result<(), String> {
        let kind = artifact.kind.as_deref().unwrap_or_default();
        let bytes = tree.read(&artifact.path).map_err(|e| format!("cannot read the file: {e}"))?;
        let part = slice(kind, &bytes).ok_or("the file holds no program this level can hand over")?;
        let scratch = Scratch::new().map_err(|e| format!("cannot make a working folder: {e}"))?;
        let program = scratch.0.join("program");
        std::fs::write(&program, &bytes[part.offset as usize..(part.offset + part.length) as usize])
            .map_err(|e| format!("cannot write a copy of the file: {e}"))?;

        let mut strings: Vec<String> = artifact
            .facts
            .get("content.urls")
            .and_then(|fact| fact.get("urls"))
            .and_then(Value::as_array)
            .map(|urls| urls.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        strings.truncate(MAX_STRINGS);
        let request =
            Request { apis: CATEGORIES.iter().flat_map(|category| category.apis.iter().map(|api| api.to_string())).collect(), strings };
        let facts =
            self.asker.ask(&self.settings.tool, &program, part.format, &request, &scratch.0, Duration::from_secs(self.settings.seconds))?;

        let tool = self.settings.tool.name();
        let new = |rule: &str| {
            Finding::new(Section::Code, ID, rule, Confidence::Derived, Severity::Info)
                .param("tool", tool)
                .param("version", facts.version.as_str())
        };
        out.finding(
            new("deep.analyzed")
                .param("arch", part.arch.unwrap_or(facts.language.as_str()))
                .param("functions", facts.functions)
                .evidence(Evidence::whole(artifact, json!({ "tool": facts.tool, "version": facts.version, "language": facts.language }))),
        );
        for category in CATEGORIES {
            let used: Vec<&Use> = facts.apis.iter().filter(|api| category.apis.contains(&api.name.as_str()) && api.total > 0).collect();
            if used.is_empty() {
                continue;
            }
            // A function that uses two of the APIs is one function.
            let mut users: Vec<(Option<&str>, &User)> = Vec::new();
            for api in &used {
                for user in &api.users {
                    if !users.iter().any(|(_, known)| known.address == user.address) {
                        users.push((Some(api.name.as_str()), user));
                    }
                }
            }
            users.sort_by_key(|(_, user)| user.address);
            let listed: Vec<User> = users.iter().map(|(_, user)| (*user).clone()).collect();
            // When a list was cut by the tool, the count is at least what is listed.
            let count = (listed.len() as u64).max(used.iter().map(|api| api.total).max().unwrap_or(0));
            let finding = new(category.rule)
                .param("count", count)
                .param("apis", used.iter().map(|api| api.name.as_str()).collect::<Vec<_>>().join(", "))
                .param("users", named(&listed, count));
            out.finding(evidence(finding, artifact, &part, &users));
        }
        for string in facts.strings.iter().filter(|string| string.total > 0).take(MAX_STRING_FINDINGS) {
            let users: Vec<(Option<&str>, &User)> = string.users.iter().map(|user| (None, user)).collect();
            let finding = new("deep.address-users")
                .param("address", string.value.as_str())
                .param("count", string.total)
                .param("users", named(&string.users, string.total));
            out.finding(evidence(finding, artifact, &part, &users));
        }
        out.fact(
            artifact,
            "deep.facts",
            json!({
                "tool": facts.tool, "version": facts.version, "language": facts.language, "functions": facts.functions,
                "apis": facts.apis.iter().map(|api| json!({ "name": api.name, "functions": api.total })).collect::<Vec<_>>(),
            }),
        );
        Ok(())
    }
}

impl Analyzer for Deep {
    fn id(&self) -> &'static str {
        ID
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    /// The tool is slow next to everything else here: each file may take its whole time.
    fn tree_seconds(&self) -> Option<u64> {
        Some((self.settings.seconds + 180).saturating_mul(self.settings.max_files.max(1) as u64))
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let mut programs: Vec<&Artifact> = tree
            .artifacts()
            .iter()
            .filter(|artifact| matches!(artifact.kind.as_deref(), Some("macho" | "macho-fat" | "elf" | "pe")))
            .collect();
        // The largest first: the main program of an app is nearly always its largest.
        programs.sort_by(|a, b| b.size.cmp(&a.size).then(a.path.cmp(&b.path)));
        let (fitting, too_large): (Vec<&Artifact>, Vec<&Artifact>) =
            programs.into_iter().partition(|artifact| artifact.size <= self.settings.max_bytes);
        let asked = fitting.len().min(self.settings.max_files);
        for artifact in &fitting[..asked] {
            if let Err(problem) = self.one(tree, artifact, out) {
                out.limitation("deep.failed", Some(artifact), Some(format!("{}: {problem}", self.settings.tool.name())));
            }
        }
        let left = fitting.len() - asked + too_large.len();
        if left > 0 {
            let names: Vec<&str> = fitting[asked..].iter().chain(&too_large).take(5).map(|artifact| artifact.name()).collect();
            let more = if left > names.len() { format!(" and {} more", left - names.len()) } else { String::new() };
            out.limitation(
                "deep.not-asked",
                None,
                Some(format!(
                    "{left} program files (limit: {} files, {} bytes each): {}{more}",
                    self.settings.max_files,
                    self.settings.max_bytes,
                    names.join(", ")
                )),
            );
        }
    }
}

/// True when `path` is a file that can be started.
pub fn is_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use aa_core::plugin::Bytes;

    use super::*;

    struct Files(Vec<(Artifact, Vec<u8>)>, Vec<Artifact>);

    impl Files {
        fn new(files: Vec<(Artifact, Vec<u8>)>) -> Files {
            let mut artifacts: Vec<Artifact> = files.iter().map(|(artifact, _)| artifact.clone()).collect();
            artifacts.sort_by(|a, b| a.path.cmp(&b.path));
            Files(files, artifacts)
        }
    }

    impl Tree for Files {
        fn artifacts(&self) -> &[Artifact] {
            &self.1
        }

        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            let found = self.0.iter().find(|(artifact, _)| artifact.path == path).ok_or(std::io::ErrorKind::NotFound)?;
            Ok(Bytes::from_vec(found.1.clone()))
        }
    }

    fn file(path: &str, kind: &str, size: u64) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size,
            digests: None,
            detected: None,
            kind: Some(kind.into()),
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    /// Answers every question the same way and remembers what it was asked.
    struct Canned {
        answer: Result<Facts, String>,
        asked: Mutex<Vec<(Format, Request, Vec<u8>)>>,
    }

    impl Asker for Canned {
        fn ask(&self, _: &Tool, program: &Path, format: Format, request: &Request, _: &Path, _: Duration) -> Result<Facts, String> {
            let bytes = std::fs::read(program).expect("the copy is there");
            self.asked.lock().expect("lock").push((format, request.clone(), bytes));
            self.answer.clone()
        }
    }

    fn user(function: &str, address: u64, at: u64, offset: Option<u64>) -> User {
        User { function: function.into(), address, at, offset }
    }

    fn facts() -> Facts {
        Facts {
            tool: "ghidra".into(),
            version: "12.1".into(),
            language: "AARCH64:LE:64:v8A".into(),
            functions: 50,
            apis: vec![
                Use {
                    name: "dlopen".into(),
                    value: String::new(),
                    total: 2,
                    users: vec![user("load", 0x2000, 0x2010, Some(0x10)), user("main", 0x1000, 0x1020, Some(0x20))],
                },
                Use { name: "dlsym".into(), value: String::new(), total: 1, users: vec![user("load", 0x2000, 0x2030, Some(0x30))] },
                Use { name: "socket".into(), value: String::new(), total: 1, users: vec![user("dial", 0x3000, 0x3004, None)] },
            ],
            strings: vec![Use {
                name: String::new(),
                value: "https://example.com/a".into(),
                total: 1,
                users: vec![user("dial", 0x3000, 0x3008, Some(0x40))],
            }],
        }
    }

    fn run(
        settings: Settings,
        answer: Result<Facts, String>,
        files: Vec<(Artifact, Vec<u8>)>,
    ) -> (Output, Vec<(Format, Request, Vec<u8>)>) {
        let asker = Arc::new(Canned { answer, asked: Mutex::new(Vec::new()) });
        let mut out = Output::default();
        analyzer_with(settings, asker.clone()).analyze_tree(&Files::new(files), &mut out);
        let asked = asker.asked.lock().expect("lock").clone();
        (out, asked)
    }

    fn settings() -> Settings {
        Settings::new(Tool::Ghidra { headless: "/opt/ghidra/support/analyzeHeadless".into() })
    }

    /// A universal binary of two slices: x86_64 at 0x100 and arm64 at 0x200, 0x80 bytes each.
    fn universal() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x280];
        bytes[..8].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]);
        for (index, (cpu, offset)) in [(0x0100_0007u32, 0x100u32), (0x0100_000c, 0x200)].into_iter().enumerate() {
            let at = 8 + index * 20;
            bytes[at..at + 4].copy_from_slice(&cpu.to_be_bytes());
            bytes[at + 8..at + 12].copy_from_slice(&offset.to_be_bytes());
            bytes[at + 12..at + 16].copy_from_slice(&0x80u32.to_be_bytes());
        }
        bytes[0x200] = 0xaa;
        bytes
    }

    #[test]
    fn what_the_tool_says_becomes_findings_that_name_it_and_point_into_the_file() {
        let mut app = file("App/app", "macho-fat", 0x280);
        app.facts.insert("content.urls".into(), json!({ "urls": ["https://example.com/a"], "truncated": false }));
        let (out, asked) =
            run(settings(), Ok(facts()), vec![(app, universal()), (file("App/readme.txt", "text", 10), b"0123456789".to_vec())]);

        // Only the program was handed over, and of the universal binary only its arm64 part.
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, Format::MachO);
        assert_eq!((asked[0].2.len(), asked[0].2[0]), (0x80, 0xaa));
        assert!(asked[0].1.apis.iter().any(|api| api == "dlopen") && asked[0].1.strings == ["https://example.com/a"]);

        let rules: Vec<&str> = out.findings.iter().map(|finding| finding.rule.as_str()).collect();
        assert_eq!(rules, ["deep.analyzed", "deep.calls-network", "deep.calls-loading", "deep.address-users"]);
        for finding in &out.findings {
            assert_eq!((finding.confidence, finding.severity), (Confidence::Derived, Severity::Info));
            assert_eq!((finding.params["tool"].as_str(), finding.params["version"].as_str()), (Some("Ghidra"), Some("12.1")));
        }
        assert_eq!(out.findings[0].params["arch"], "arm64");

        // Two functions use the loading APIs between them, however many of the APIs each uses.
        let loading = &out.findings[2];
        assert_eq!(loading.params["count"], 2);
        assert_eq!(loading.params["apis"], "dlopen, dlsym");
        assert_eq!(loading.params["users"], "main (0x1000), load (0x2000)");
        // The place is given inside the artifact: the part's own offset plus where the part starts.
        assert_eq!(loading.evidence[0].location, aa_core::Location::Bytes { offset: 0x200 + 0x20, length: 1 });
        // Where the tool gave no place in the file, the address stands as it is.
        assert!(matches!(out.findings[1].evidence[0].location, aa_core::Location::Field(_)));
        assert_eq!(out.findings[3].params["address"], "https://example.com/a");
        assert!(out.limitations.is_empty());
    }

    #[test]
    fn a_tool_that_fails_and_files_beyond_the_limits_are_limitations_not_silence() {
        let files = vec![
            (file("a/big", "elf", 900), vec![0; 900]),
            (file("a/one", "elf", 300), vec![0x7f; 300]),
            (file("a/two", "pe", 200), vec![0; 200]),
            (file("a/three", "macho", 100), vec![0; 100]),
        ];
        let limits = Settings { max_files: 2, max_bytes: 500, ..settings() };
        let (out, asked) = run(limits, Err("no answer within 5 seconds".into()), files);
        // The two largest that fit were tried, in that order.
        assert_eq!(
            asked.iter().map(|(format, _, bytes)| (*format, bytes.len())).collect::<Vec<_>>(),
            [(Format::Elf, 300), (Format::Pe, 200)]
        );
        assert!(out.findings.is_empty());
        let codes: Vec<(&str, Option<&str>)> = out.limitations.iter().map(|l| (l.code.as_str(), l.artifact.as_deref())).collect();
        assert_eq!(codes, [("deep.failed", Some("a/one")), ("deep.failed", Some("a/two")), ("deep.not-asked", None)]);
        assert_eq!(out.limitations[0].detail.as_deref(), Some("Ghidra: no answer within 5 seconds"));
        let detail = out.limitations[2].detail.as_deref().expect("says which");
        assert!(detail.starts_with("2 program files") && detail.contains("three") && detail.contains("big"), "{detail}");
    }

    #[test]
    fn every_rule_it_can_emit_has_its_words_and_it_asks_for_time() {
        let known: Vec<&str> = RULES.iter().map(|rule| rule.id).collect();
        for category in CATEGORIES {
            assert!(known.contains(&category.rule), "{}", category.rule);
        }
        for rule in RULES {
            assert!(
                !rule.title_zh.is_empty() && !rule.text_zh.is_empty() && !rule.title_en.is_empty() && !rule.text_en.is_empty(),
                "{}",
                rule.id
            );
        }
        let deep = analyzer_with(Settings { max_files: 3, seconds: 100, ..settings() }, Arc::new(Programs));
        assert_eq!(deep.tree_seconds(), Some((100 + 180) * 3));
    }

    #[test]
    fn the_processor_is_read_from_each_kind_of_header() {
        let mut elf = vec![0u8; 64];
        elf[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        elf[18] = 183;
        assert_eq!(arch(Format::Elf, &elf), Some("arm64"));
        let mut pe = vec![0u8; 0x100];
        pe[0x3c] = 0x80;
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        assert_eq!(arch(Format::Pe, &pe), Some("x86_64"));
        assert_eq!(arch(Format::MachO, &[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]), Some("arm64"));
        assert_eq!(arch(Format::Elf, &[1, 2, 3]), None);
        assert!(slice("zip", &[0; 16]).is_none());
    }
}
