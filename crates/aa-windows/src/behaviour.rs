//! Groups imported Windows API functions into capability categories.
//!
//! An import says a program *can* call a function, not that it does, nor why. The categories
//! therefore describe capability, and the rule texts say so.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::pe::Imports;

pub struct Category {
    pub id: &'static str,
    /// Rule emitted for the category; `None` for categories nearly every program falls into.
    pub rule: Option<&'static str>,
    /// Function names without the `A`/`W` suffix.
    functions: &'static [&'static str],
    /// Libraries whose every import counts (they are often imported by ordinal).
    libraries: &'static [&'static str],
}

pub const CATEGORIES: &[Category] = &[
    Category {
        id: "network",
        rule: Some("windows.imports-network"),
        functions: &[
            "socket",
            "connect",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "bind",
            "listen",
            "accept",
            "WSAStartup",
            "WSASocket",
            "WSAConnect",
            "WSASend",
            "WSARecv",
            "getaddrinfo",
            "GetAddrInfo",
            "GetAddrInfoEx",
            "gethostbyname",
            "InternetOpen",
            "InternetOpenUrl",
            "InternetConnect",
            "InternetReadFile",
            "InternetWriteFile",
            "HttpOpenRequest",
            "HttpSendRequest",
            "HttpSendRequestEx",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReadData",
            "WinHttpWebSocketCompleteUpgrade",
            "URLDownloadToFile",
            "URLDownloadToCacheFile",
            "DnsQuery_A",
            "DnsQuery_W",
            "DnsQueryEx",
            "FtpPutFile",
            "FtpGetFile",
        ],
        libraries: &["ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "mswsock.dll"],
    },
    Category {
        id: "crypto",
        rule: Some("windows.imports-crypto"),
        functions: &[
            "CryptAcquireContext",
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptGenKey",
            "CryptDeriveKey",
            "CryptCreateHash",
            "CryptHashData",
            "CryptImportKey",
            "CryptExportKey",
            "CryptGenRandom",
            "CryptProtectData",
            "CryptUnprotectData",
            "CryptProtectMemory",
            "CryptStringToBinary",
            "CryptBinaryToString",
            "BCryptOpenAlgorithmProvider",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "BCryptGenerateSymmetricKey",
            "BCryptGenerateKeyPair",
            "BCryptImportKey",
            "BCryptImportKeyPair",
            "BCryptHashData",
            "BCryptCreateHash",
            "BCryptGenRandom",
            "BCryptDeriveKey",
            "BCryptSignHash",
            "BCryptVerifySignature",
            "NCryptOpenKey",
            "NCryptDecrypt",
            "NCryptEncrypt",
            "NCryptSignHash",
            "CertOpenStore",
            "CertOpenSystemStore",
            "CertAddCertificateContextToStore",
        ],
        libraries: &[],
    },
    Category {
        id: "injection",
        rule: Some("windows.imports-injection"),
        functions: &[
            "VirtualAllocEx",
            "VirtualAllocExNuma",
            "VirtualProtectEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "ZwCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtQueueApcThread",
            "SetThreadContext",
            "Wow64SetThreadContext",
            "NtSetContextThread",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "NtMapViewOfSection",
            "ZwMapViewOfSection",
            "NtWriteVirtualMemory",
            "ZwWriteVirtualMemory",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
        ],
        libraries: &[],
    },
    Category {
        id: "process",
        rule: None,
        functions: &[
            "CreateProcess",
            "CreateProcessAsUser",
            "CreateProcessWithLogonW",
            "CreateProcessWithTokenW",
            "CreateProcessInternalW",
            "ShellExecute",
            "ShellExecuteEx",
            "WinExec",
            "system",
            "_wsystem",
            "OpenProcess",
            "TerminateProcess",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32FirstW",
            "Process32Next",
            "Process32NextW",
            "EnumProcesses",
            "NtCreateUserProcess",
            "CreateThread",
        ],
        libraries: &[],
    },
    Category {
        id: "registry",
        rule: None,
        functions: &[
            "RegOpenKey",
            "RegOpenKeyEx",
            "RegCreateKey",
            "RegCreateKeyEx",
            "RegSetValue",
            "RegSetValueEx",
            "RegSetKeyValue",
            "RegDeleteKey",
            "RegDeleteKeyEx",
            "RegDeleteValue",
            "RegDeleteTree",
            "RegQueryValue",
            "RegQueryValueEx",
            "RegGetValue",
            "RegEnumKey",
            "RegEnumKeyEx",
            "RegEnumValue",
            "SHSetValue",
            "SHRegSetUSValue",
            "NtSetValueKey",
            "ZwSetValueKey",
            "RegSaveKey",
            "RegLoadKey",
        ],
        libraries: &[],
    },
    Category {
        id: "services",
        rule: Some("windows.imports-services"),
        functions: &[
            "OpenSCManager",
            "CreateService",
            "OpenService",
            "StartService",
            "ControlService",
            "DeleteService",
            "ChangeServiceConfig",
            "ChangeServiceConfig2",
            "StartServiceCtrlDispatcher",
            "RegisterServiceCtrlHandler",
            "RegisterServiceCtrlHandlerEx",
            "EnumServicesStatus",
            "EnumServicesStatusEx",
        ],
        libraries: &[],
    },
    Category {
        id: "persistence",
        rule: Some("windows.imports-persistence"),
        functions: &["CreateService", "NetScheduleJobAdd", "MoveFileEx", "MoveFileWithProgress", "RegisterApplicationRestart"],
        libraries: &["taskschd.dll", "mstask.dll"],
    },
    Category {
        id: "filesystem",
        rule: None,
        functions: &[
            "CreateFile",
            "CreateFile2",
            "WriteFile",
            "ReadFile",
            "DeleteFile",
            "MoveFile",
            "MoveFileEx",
            "CopyFile",
            "CopyFileEx",
            "FindFirstFile",
            "FindFirstFileEx",
            "FindNextFile",
            "GetTempPath",
            "GetTempFileName",
            "SetFileAttributes",
            "CreateDirectory",
            "RemoveDirectory",
            "SHFileOperation",
            "NtCreateFile",
            "NtWriteFile",
            "SetFileTime",
            "EncryptFile",
        ],
        libraries: &[],
    },
    Category {
        id: "anti-debug",
        rule: Some("windows.imports-anti-debug"),
        // IsDebuggerPresent and OutputDebugString are left out: the C runtime imports them in
        // almost every program.
        functions: &[
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "NtSetInformationThread",
            "ZwSetInformationThread",
            "DebugActiveProcess",
            "DebugActiveProcessStop",
            "NtQuerySystemInformation",
            "ZwQuerySystemInformation",
            "DbgBreakPoint",
            "DbgUiRemoteBreakin",
            "BlockInput",
        ],
        libraries: &[],
    },
    Category {
        id: "input-capture",
        rule: Some("windows.imports-input-capture"),
        functions: &[
            "GetAsyncKeyState",
            "GetKeyboardState",
            "SetWindowsHookEx",
            "RegisterRawInputDevices",
            "GetRawInputData",
            "keybd_event",
            "mouse_event",
            "SendInput",
            "PrintWindow",
            "GetClipboardData",
            "AttachThreadInput",
            "capCreateCaptureWindow",
        ],
        libraries: &[],
    },
    Category {
        id: "privilege",
        rule: Some("windows.imports-privilege"),
        functions: &[
            "AdjustTokenPrivileges",
            "LookupPrivilegeValue",
            "OpenProcessToken",
            "OpenThreadToken",
            "DuplicateToken",
            "DuplicateTokenEx",
            "ImpersonateLoggedOnUser",
            "ImpersonateNamedPipeClient",
            "SetThreadToken",
            "LogonUser",
            "CreateProcessAsUser",
            "CreateProcessWithTokenW",
            "RtlAdjustPrivilege",
            "SetTokenInformation",
            "LsaOpenPolicy",
            "LsaAddAccountRights",
        ],
        libraries: &[],
    },
    Category {
        id: "ipc",
        rule: None,
        functions: &[
            "CreateNamedPipe",
            "ConnectNamedPipe",
            "CallNamedPipe",
            "CreatePipe",
            "CreateMailslot",
            "CoCreateInstance",
            "CoCreateInstanceEx",
            "CoGetClassObject",
            "RpcStringBindingCompose",
            "RpcBindingFromStringBinding",
            "NdrClientCall2",
            "NdrClientCall3",
            "NdrAsyncClientCall",
            "RpcServerListen",
            "RpcServerUseProtseqEp",
            "CreateFileMapping",
            "OpenFileMapping",
            "DdeInitialize",
            "NtAlpcConnectPort",
        ],
        libraries: &["rpcrt4.dll"],
    },
    Category {
        id: "wmi",
        rule: Some("windows.imports-wmi"),
        functions: &[],
        libraries: &["wbemcomn.dll", "fastprox.dll", "wbemprox.dll", "wmiutils.dll"],
    },
    Category {
        id: "device-io",
        rule: Some("windows.imports-device-io"),
        functions: &[
            "DeviceIoControl",
            "NtDeviceIoControlFile",
            "ZwDeviceIoControlFile",
            "NtLoadDriver",
            "ZwLoadDriver",
            "FilterConnectCommunicationPort",
            "FilterSendMessage",
            "SetupDiGetClassDevs",
            "DefineDosDevice",
        ],
        libraries: &[],
    },
];

/// APIs kept per category.
const MAX_APIS: usize = 60;

/// `category id -> evidence names`, sorted. Evidence is `library!Function`, or `library (n
/// imports)` when a whole library counts.
pub fn classify(imports: &Imports, pinvokes: &[(String, String)]) -> BTreeMap<&'static str, Vec<String>> {
    let mut found: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let add = |library: &str, function: &str, found: &mut BTreeMap<&'static str, Vec<String>>| {
        let stem = function.strip_suffix(['A', 'W']).unwrap_or(function);
        for category in CATEGORIES {
            if category.functions.iter().any(|f| *f == function || *f == stem) {
                found.entry(category.id).or_default().push(format!("{library}!{function}"));
            }
        }
    };
    for dll in &imports.dlls {
        let library = dll.name.to_ascii_lowercase();
        for category in CATEGORIES {
            if category.libraries.contains(&library.as_str()) && !dll.functions.is_empty() {
                found.entry(category.id).or_default().push(format!("{library} ({} imports)", dll.functions.len()));
            }
        }
        for function in dll.functions.iter().filter_map(|f| f.name.as_deref()) {
            add(&library, function, &mut found);
        }
    }
    for (library, function) in pinvokes {
        add(&library.to_ascii_lowercase(), function, &mut found);
    }
    for list in found.values_mut() {
        list.sort();
        list.dedup();
        list.truncate(MAX_APIS);
    }
    found
}

pub fn json(found: &BTreeMap<&'static str, Vec<String>>) -> Value {
    json!(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{ImportDll, ImportFunction};

    #[test]
    fn suffixes_ordinals_and_pinvokes_are_classified() {
        let named = |n: &str| ImportFunction { name: Some(n.to_string()), ordinal: None };
        let imports = Imports {
            dlls: vec![
                ImportDll { name: "KERNEL32.dll".into(), functions: vec![named("WriteProcessMemory"), named("CreateFileW")] },
                ImportDll { name: "WS2_32.dll".into(), functions: vec![ImportFunction { name: None, ordinal: Some(3) }] },
            ],
            truncated: false,
        };
        let found = classify(&imports, &[("user32".into(), "SetWindowsHookExA".into())]);
        assert_eq!(found["injection"], ["kernel32.dll!WriteProcessMemory"]);
        assert_eq!(found["network"], ["ws2_32.dll (1 imports)"]);
        assert_eq!(found["filesystem"], ["kernel32.dll!CreateFileW"]);
        assert_eq!(found["input-capture"], ["user32!SetWindowsHookExA"]);
        assert!(!found.contains_key("crypto"));
    }
}
