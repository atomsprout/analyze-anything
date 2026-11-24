//! The opening chapter: what the input is, in a few sentences, drawn from the facts the format
//! analyzers attached. Each sentence is its own finding and appears only when its facts were read,
//! so the chapter never states something that was not established.

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::Value;

pub struct Overview;

const RULES: &[Rule] = &[
    Rule {
        id: "overview.kind-deb",
        title_en: "Kind of input",
        title_zh: "输入类型",
        text_en: "This is a Debian package. Control declarations and supported payload contents were read as data, without installation.",
        text_zh: "这是 Debian 软件包。控制声明与受支持的载荷内容作为数据读取，没有安装。",
    },
    Rule {
        id: "overview.kind-rpm",
        title_en: "Kind of input",
        title_zh: "输入类型",
        text_en: "This is an RPM package. Header declarations and supported payload contents were read as data, without installation.",
        text_zh: "这是 RPM 软件包。头部声明与受支持的载荷内容作为数据读取，没有安装。",
    },
    Rule {
        id: "overview.kind-dotnet-bundle",
        title_en: "Kind of input",
        title_zh: "输入类型",
        text_en: "This input declares a .NET single-file bundle. Supported embedded contents were opened as data; the host and assemblies were not run.",
        text_zh: "此输入声明了 .NET 单文件包。受支持的内嵌内容作为数据打开，没有运行宿主与程序集。",
    },
    Rule {
        id: "overview.kind-pyinstaller",
        title_en: "Kind of input",
        title_zh: "输入类型",
        text_en: "This input declares a PyInstaller CArchive. Supported contents were opened as data; the bootloader and Python code were not run.",
        text_zh: "此输入声明了 PyInstaller CArchive。受支持的内容作为数据打开，没有运行引导程序或 Python 代码。",
    },
    Rule {
        id: "overview.kind-batch-script",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 批处理脚本，报告记录可读取的字面命令段。",
        text_en: "This is a Windows batch script. The report records readable literal command segments.",
    },
    Rule {
        id: "overview.kind-powershell-script",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 PowerShell 脚本，报告记录可读取的命令语法与管理员声明。",
        text_en: "This PowerShell script contains readable command syntax and may declare administrator requirements.",
    },
    Rule {
        id: "overview.kind-msix-bundle",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 MSIX/APPX bundle，包含声明的应用或资源包。内部包的对应关系与外层签名字节覆盖分别记录，不判断本机安装资格。",
        text_en: "This is an MSIX/APPX bundle containing declared application or resource packages. Inner-package correspondence and outer signed-byte coverage are recorded separately; host installation eligibility is not judged.",
    },
    Rule {
        id: "overview.kind-msix-bundle-manifest",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 MSIX/APPX bundle 清单，声明内部应用包、资源包、架构与位置。清单声明、实际内容对应关系和签名覆盖分别记录。",
        text_en: "This is an MSIX/APPX bundle manifest declaring inner application/resource packages, architectures and locations. Declarations, content correspondence and signature coverage are recorded separately.",
    },
    Rule {
        id: "overview.kind-msix-signature",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 MSIX/APPX 的 P7X 签名文件，包含包摘要声明与 CMS 签名。数学检查、原始包对应关系与 Windows 信任分别记录。",
        text_en: "This is an MSIX/APPX P7X signature with package digest declarations and a CMS signature. Mathematical checks, original package correspondence and Windows trust are recorded separately.",
    },
    Rule {
        id: "overview.kind-msix-block-map",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 MSIX/APPX 分块映射，记录文件大小和内容摘要。内容与声明一致不等于确认软件包的认证状态。",
        text_en: "This is an MSIX/APPX block map of declared file sizes and content digests. Agreement with those declarations does not authenticate the package.",
    },
    Rule {
        id: "overview.kind-windows-catalog",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 目录文件，以 CTL 记录文件主体标识和摘要声明。目录自身的签名不等于确认所有载荷的覆盖情况或 Windows 信任。",
        text_en: "This is a Windows catalog with CTL subject identifiers and digest declarations. Its own signature does not establish coverage of every payload or Windows trust.",
    },
    Rule {
        id: "overview.kind-windows-inf",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows INF 声明文档。保留了文件中的节和条目，没有执行安装或验证驱动包。",
        text_en: "This is a Windows INF declaration document. Its sections and entries were retained; no installation was performed or driver package verified.",
    },
    Rule {
        id: "overview.kind-scheduled-task",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 任务计划 XML 文档。仅分析文件中的声明，没有注册或运行任务。",
        text_en: "This is a Windows Task Scheduler XML document. Only its declarations were analyzed; no task was registered or run.",
    },
    Rule {
        id: "overview.kind-registry-export",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 注册表导出文档，保存了键和值的写入或删除声明。没有导入注册表。",
        text_en: "This is a Windows registry export document containing key and value write or deletion declarations. No registry data was imported.",
    },
    Rule {
        id: "overview.kind-shell-link",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows Shell 快捷方式，保存了目标和启动属性的声明。目标没有运行或解析。",
        text_en: "This is a Windows Shell Link containing target and launch-property declarations. The target was not run or resolved.",
    },
    Rule {
        id: "overview.kind-internet-shortcut",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Internet 快捷方式，保存了网址及相关属性的声明。目标没有打开。",
        text_en: "This is an Internet shortcut containing a URL declaration and related properties. Its target was not opened.",
    },
    Rule {
        id: "overview.kind-ipa",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 iOS 应用包（IPA）。",
        text_en: "This is an iOS app package (IPA).",
    },
    Rule {
        id: "overview.kind-dmg",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 macOS 磁盘镜像（DMG），已读出其中的文件系统。",
        text_en: "This is a macOS disk image (DMG); the file system inside it was read.",
    },
    Rule {
        id: "overview.kind-pkg",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 macOS 安装包（pkg）。",
        text_en: "This is a macOS installer package (pkg).",
    },
    Rule {
        id: "overview.kind-apk",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Android 应用包（APK）。",
        text_en: "This is an Android app package (APK).",
    },
    Rule {
        id: "overview.kind-aab",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Android App Bundle（AAB）。",
        text_en: "This is an Android App Bundle (AAB).",
    },
    Rule {
        id: "overview.kind-apk-set",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个包含多个 APK 的 Android 分发包（{kind}）。",
        text_en: "This is an Android distribution archive holding several APKs ({kind}).",
    },
    Rule {
        id: "overview.kind-installer",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 安装程序，格式为 {format}。",
        text_en: "This is a Windows installer in {format} format.",
    },
    Rule {
        id: "overview.kind-sfx",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 自解压程序：可执行文件后面附带了一个压缩包，已解开。",
        text_en: "This is a Windows self-extracting program: an archive is attached after the executable, and it was opened.",
    },
    Rule {
        id: "overview.kind-pe",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Windows 可执行文件（PE）。",
        text_en: "This is a Windows executable (PE).",
    },
    Rule {
        id: "overview.kind-elf",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 ELF 可执行文件或库（Linux、Android 等系统使用）。",
        text_en: "This is an ELF executable or library (used by Linux, Android and similar systems).",
    },
    Rule {
        id: "overview.kind-macho",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 Mach-O 可执行文件或库（Apple 系统使用）。",
        text_en: "This is a Mach-O executable or library (used by Apple systems).",
    },
    Rule {
        id: "overview.kind-archive",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个 {format} 格式的归档，已解开，里面有 {files} 个文件。",
        text_en: "This is a {format} archive; it was opened and holds {files} files.",
    },
    Rule {
        id: "overview.kind-bundle",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个应用包（{name}）：一个按 Apple 的约定组织的文件夹，直接包含 {files} 个文件（不含解包得到的）。",
        text_en: "This is an application bundle ({name}): a folder laid out the way Apple's systems expect, holding {files} files (not counting unpacked ones).",
    },
    Rule {
        id: "overview.kind-folder",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是一个文件夹，直接包含 {files} 个文件（不含解包得到的）。",
        text_en: "This is a folder holding {files} files (not counting unpacked ones).",
    },
    Rule {
        id: "overview.kind-file",
        title_zh: "输入类型",
        title_en: "Kind of input",
        text_zh: "这是单个文件，内容类型识别为 {mime}。没有针对这种类型的专门分析，只做了通用检查。",
        text_en: "This is a single file whose content was recognised as {mime}. No format-specific analysis exists for this type; only the general checks ran.",
    },
    Rule {
        id: "overview.product", title_zh: "产品", title_en: "Product", text_zh: "产品名称：{name}。", text_en: "Product name: {name}."
    },
    Rule {
        id: "overview.version", title_zh: "版本", title_en: "Version", text_zh: "版本：{version}。", text_en: "Version: {version}."
    },
    Rule {
        id: "overview.identifier",
        title_zh: "标识符",
        title_en: "Identifier",
        text_zh: "应用标识符：{id}。",
        text_en: "Application identifier: {id}.",
    },
    Rule {
        id: "overview.publisher-claimed",
        title_zh: "自称的发布者",
        title_en: "Claimed publisher",
        text_zh: "文件中写的发布者是 {publisher}。这是文件自己的声明，任何人都可以填写，不等于签名者。",
        text_en: "The publisher written in the file is {publisher}. This is the file's own claim, which anyone can fill in; it is not the signer.",
    },
    Rule {
        id: "overview.architectures",
        title_zh: "处理器架构",
        title_en: "Architectures",
        text_zh: "主程序包含的处理器架构：{architectures}。",
        text_en: "The main program is built for: {architectures}.",
    },
    Rule {
        id: "overview.apple-bundles",
        title_zh: "包含的 Apple 组件",
        title_en: "Apple bundles inside",
        text_zh: "共识别出 {total} 个 bundle（应用、框架、扩展等），主应用位于 {path}。",
        text_en: "{total} bundles (apps, frameworks, extensions and the like) were recognised; the main app is at {path}.",
    },
    Rule {
        id: "overview.apple-developer-id",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "主程序使用 Developer ID 证书签名（团队 {team_id}），这是在 App Store 之外分发 macOS 软件的方式。校验了哪些内容见“来源与签名”一章。",
        text_en: "The main program is signed with a Developer ID certificate (team {team_id}), the way macOS software is distributed outside the App Store. The Provenance chapter says what was verified.",
    },
    Rule {
        id: "overview.apple-distribution",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "主程序使用 Apple 分发证书签名（团队 {team_id}）。校验了哪些内容见“来源与签名”一章。",
        text_en: "The main program is signed with an Apple distribution certificate (team {team_id}). The Provenance chapter says what was verified.",
    },
    Rule {
        id: "overview.apple-development",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "主程序使用开发证书签名（团队 {team_id}），这通常是开发或测试版本，不是正式发布的版本。",
        text_en: "The main program is signed with a development certificate (team {team_id}); this is normally a development or test build, not a release.",
    },
    Rule {
        id: "overview.apple-adhoc",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "主程序只有临时签名（ad-hoc）：没有证书，无法得知是谁构建的。",
        text_en: "The main program is only ad-hoc signed: there is no certificate, so who built it cannot be told.",
    },
    Rule {
        id: "overview.apple-other-signing",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "主程序带有签名，类型为 {signing_type}。详情见“来源与签名”一章。",
        text_en: "The main program is signed; the signing type is {signing_type}. See the Provenance chapter.",
    },
    Rule {
        id: "overview.apple-unsigned",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "没有读到主程序的代码签名。",
        text_en: "No code signature was read from the main program.",
    },
    Rule {
        id: "overview.win-signed",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "输入文件带有 Authenticode 签名，签名者是 {signer}；文件内容与签名一致，签名本身和内嵌证书链均校验通过。未检查根证书是否受信任以及证书是否被吊销。",
        text_en: "The input file carries an Authenticode signature by {signer}; the file matches the signature, and the signature and the embedded certificate chain verify. Whether the root is trusted or a certificate was revoked was not checked.",
    },
    Rule {
        id: "overview.win-signed-problem",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "输入文件带有 Authenticode 签名，签名者是 {signer}，但有校验项没有通过。详情见“来源与签名”一章。",
        text_en: "The input file carries an Authenticode signature by {signer}, but not every check passed. See the Provenance chapter.",
    },
    Rule {
        id: "overview.win-unsigned",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "输入文件本身没有内嵌的 Authenticode 签名。",
        text_en: "The input file itself has no embedded Authenticode signature.",
    },
    Rule {
        id: "overview.win-inner-signers",
        title_zh: "内部文件的签名情况",
        title_en: "Signing of the files inside",
        text_zh: "共有 {pe_files} 个 Windows 可执行文件，其中 {unsigned} 个没有签名，其余由 {signers} 个不同的签名者签名。",
        text_en: "There are {pe_files} Windows executables; {unsigned} are unsigned and the rest are signed by {signers} distinct signers.",
    },
    Rule {
        id: "overview.installer-contents",
        title_zh: "安装内容",
        title_en: "What it installs",
        text_zh: "安装程序会释放 {files} 个文件，共 {bytes} 字节。它写注册表、创建快捷方式、运行命令等行为见“权限与能力”一章。",
        text_en: "The installer lays down {files} files, {bytes} bytes in all. What it writes to the registry, the shortcuts it creates and the commands it runs are in the Capabilities chapter.",
    },
    Rule {
        id: "overview.install-dir",
        title_zh: "默认安装位置",
        title_en: "Default install location",
        text_zh: "默认安装到 {dir}。",
        text_en: "It installs to {dir} by default.",
    },
    Rule {
        id: "overview.android-sdk",
        title_zh: "系统版本要求",
        title_en: "Android versions",
        text_zh: "最低支持 API {min_sdk}，目标 API {target_sdk}。",
        text_en: "Minimum API level {min_sdk}, target API level {target_sdk}.",
    },
    Rule {
        id: "overview.android-signer",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "签名证书的 SHA-256 指纹为 {sha256}。Android 用这个指纹判断更新是否来自同一个发布者；各签名方案的校验结果见“来源与签名”一章。",
        text_en: "The signing certificate's SHA-256 fingerprint is {sha256}. Android uses it to decide whether an update comes from the same publisher; the Provenance chapter gives the result for each signature scheme.",
    },
    Rule {
        id: "overview.android-signature-problem",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "包内带有签名数据，但没有任何一个签名方案校验通过，因此无法确认签名者。详情见“来源与签名”一章。",
        text_en: "The package carries signature data, but no signature scheme verified, so the signer cannot be confirmed. See the Provenance chapter.",
    },
    Rule {
        id: "overview.android-unsigned",
        title_zh: "签名",
        title_en: "Signing",
        text_zh: "没有读到任何签名者证书。未签名的包无法安装到普通设备上。",
        text_en: "No signer certificate was read. An unsigned package cannot be installed on an ordinary device.",
    },
    Rule {
        id: "overview.electron",
        title_zh: "技术栈",
        title_en: "Technology",
        text_zh: "这是一个 Electron 应用（{name} {version}），内置 Electron {electron_version}。",
        text_en: "This is an Electron app ({name} {version}) bundling Electron {electron_version}.",
    },
    Rule {
        id: "overview.dotnet",
        title_zh: "技术栈",
        title_en: "Technology",
        text_zh: "包含 {assemblies} 个 .NET 程序集。",
        text_en: "It contains {assemblies} .NET assemblies.",
    },
];

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.trim().is_empty())
}

fn finding(rule: &str, confidence: Confidence) -> Finding {
    Finding::new(Section::Overview, "overview", rule, confidence, Severity::Info)
}

impl Analyzer for Overview {
    fn id(&self) -> &'static str {
        "overview"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let roots: Vec<&Artifact> = tree.artifacts().iter().filter(|a| a.parent.is_none()).collect();
        let Some(first) = roots.first() else { return };
        // A folder input has several top-level files, or one that sits inside a subfolder.
        let single = roots.len() == 1 && !first.path.contains('/');
        if single {
            kind_of_file(tree, first, out);
            windows_file(first, out);
        } else if let Some(plist) = bundle_plist(tree) {
            // The folder that was given is itself a bundle: say so, not just "a folder".
            out.finding(
                finding("overview.kind-bundle", Confidence::Verified)
                    .param("name", tree.input_name())
                    .param("files", roots.len())
                    .evidence(Evidence::whole(plist, "Info.plist")),
            );
        } else {
            out.finding(
                finding("overview.kind-folder", Confidence::Verified)
                    .param("files", roots.len())
                    .evidence(Evidence::whole(first, roots.len())),
            );
        }
        apple(tree, out);
        android(tree, out);
        windows_tree(tree, first, out);
    }
}

/// The Info.plist at the top of the input, when the input is a folder named like a bundle
/// (`Name.app`, `Name.framework`, …) that has one where a bundle keeps it.
fn bundle_plist(tree: &dyn Tree) -> Option<&Artifact> {
    let name = tree.input_name().trim_end_matches('/').to_ascii_lowercase();
    const KINDS: &[&str] = &[".app", ".framework", ".appex", ".bundle", ".plugin", ".kext", ".xpc"];
    if !KINDS.iter().any(|kind| name.ends_with(kind)) {
        return None;
    }
    ["Contents/Info.plist", "Info.plist", "Resources/Info.plist"].iter().find_map(|path| tree.get(path)).or_else(|| {
        // A framework keeps it under the version it holds: Versions/A/Resources/Info.plist.
        tree.artifacts().iter().find(|artifact| {
            artifact
                .path
                .strip_prefix("Versions/")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(_, rest)| rest == "Resources/Info.plist")
        })
    })
}

fn kind_of_file(tree: &dyn Tree, root: &Artifact, out: &mut Output) {
    let children = || tree.under(&root.path).len();
    let kind = root.kind.as_deref().unwrap_or("");
    let unpacker = root.unpacked_by.as_deref().unwrap_or("");
    let installer_format = root.facts.get("windows.installer").and_then(|f| text(f, "format").or_else(|| text(f, "kind")));
    let made = match (kind, unpacker) {
        (_, "deb") => finding("overview.kind-deb", Confidence::Verified),
        (_, "rpm") => finding("overview.kind-rpm", Confidence::Verified),
        (_, "dotnet-bundle") => finding("overview.kind-dotnet-bundle", Confidence::Verified),
        (_, "pyinstaller") => finding("overview.kind-pyinstaller", Confidence::Verified),
        ("ipa", _) => finding("overview.kind-ipa", Confidence::Derived),
        ("internet-shortcut", _) => finding("overview.kind-internet-shortcut", Confidence::Verified),
        ("shell-link", _) => finding("overview.kind-shell-link", Confidence::Verified),
        ("registry-export", _) => finding("overview.kind-registry-export", Confidence::Verified),
        ("scheduled-task", _) => finding("overview.kind-scheduled-task", Confidence::Verified),
        ("windows-inf", _) => finding("overview.kind-windows-inf", Confidence::Verified),
        ("windows-catalog", _) => finding("overview.kind-windows-catalog", Confidence::Verified),
        ("msix-block-map", _) => finding("overview.kind-msix-block-map", Confidence::Verified),
        ("msix-signature", _) => finding("overview.kind-msix-signature", Confidence::Verified),
        ("msix-bundle-manifest", _) => finding("overview.kind-msix-bundle-manifest", Confidence::Verified),
        ("msix-bundle", _) => finding("overview.kind-msix-bundle", Confidence::Verified),
        ("powershell-script", _) => finding("overview.kind-powershell-script", Confidence::Verified),
        ("batch-script", _) => finding("overview.kind-batch-script", Confidence::Verified),
        ("apk", _) => finding("overview.kind-apk", Confidence::Derived),
        ("aab", _) => finding("overview.kind-aab", Confidence::Derived),
        ("xapk" | "apks" | "apkm" | "apk-set", _) => finding("overview.kind-apk-set", Confidence::Derived).param("kind", kind),
        ("pkg", _) => finding("overview.kind-pkg", Confidence::Derived),
        ("dmg", _) | (_, "dmg") => finding("overview.kind-dmg", Confidence::Verified),
        (_, "nsis" | "inno" | "msi") => match installer_format {
            Some(format) => finding("overview.kind-installer", Confidence::Verified).param("format", format),
            None => finding("overview.kind-installer", Confidence::Verified).param("format", unpacker),
        },
        (_, "sfx") => finding("overview.kind-sfx", Confidence::Verified),
        ("pe", _) => finding("overview.kind-pe", Confidence::Verified),
        ("elf", _) => finding("overview.kind-elf", Confidence::Verified),
        ("macho" | "macho-fat", _) => finding("overview.kind-macho", Confidence::Verified),
        (_, unpacker) if !unpacker.is_empty() => finding("overview.kind-archive", Confidence::Verified)
            .param("format", if kind.is_empty() { unpacker } else { kind })
            .param("files", children()),
        _ => finding("overview.kind-file", Confidence::Verified).param("mime", root.mime()),
    };
    out.finding(made.evidence(Evidence::whole(root, if kind.is_empty() { root.mime() } else { kind })));
}

/// Identity and signing of a single Windows input file, from its own facts.
fn windows_file(root: &Artifact, out: &mut Output) {
    let installer = root.facts.get("windows.installer");
    let version = root.facts.get("windows.version");
    let strings = version.and_then(|v| v.get("strings"));
    let product = installer.and_then(|i| text(i, "product")).or_else(|| strings.and_then(|s| text(s, "ProductName")));
    if let Some(name) = product {
        let field = if installer.is_some_and(|i| text(i, "product").is_some()) { "installer product" } else { "ProductName" };
        out.finding(finding("overview.product", Confidence::Verified).param("name", name).evidence(Evidence::field(root, field, name)));
    }
    let number = installer
        .and_then(|i| text(i, "version"))
        .or_else(|| version.and_then(|v| text(v, "product_version").or_else(|| text(v, "file_version"))));
    if let Some(number) = number {
        out.finding(
            finding("overview.version", Confidence::Verified).param("version", number).evidence(Evidence::field(root, "version", number)),
        );
    }
    let publisher = installer.and_then(|i| text(i, "publisher")).or_else(|| strings.and_then(|s| text(s, "CompanyName")));
    if let Some(publisher) = publisher {
        out.finding(finding("overview.publisher-claimed", Confidence::Verified).param("publisher", publisher).evidence(Evidence::field(
            root,
            "publisher",
            publisher,
        )));
    }
    if let Some(installer) = installer {
        if let (Some(files), Some(bytes)) =
            (installer.get("files").and_then(Value::as_u64), installer.get("files_bytes").and_then(Value::as_u64))
        {
            out.finding(
                finding("overview.installer-contents", Confidence::Verified)
                    .param("files", files)
                    .param("bytes", bytes)
                    .evidence(Evidence::whole(root, files)),
            );
        }
        if let Some(dir) = text(installer, "install_dir") {
            out.finding(finding("overview.install-dir", Confidence::Verified).param("dir", dir).evidence(Evidence::field(
                root,
                "install_dir",
                dir,
            )));
        }
    }
    let Some(authenticode) = root.facts.get("windows.authenticode") else { return };
    let signatures = authenticode.get("signatures").and_then(Value::as_array);
    match signatures.and_then(|list| list.first()) {
        Some(signature) => {
            let signer = signature.get("signer").and_then(|s| text(s, "common_name").or_else(|| text(s, "subject"))).unwrap_or("?");
            let checks = signature.get("checks").and_then(Value::as_object);
            let all_passed = checks.is_some_and(|c| !c.is_empty() && c.values().all(|v| v == "passed"));
            let rule = if all_passed { "overview.win-signed" } else { "overview.win-signed-problem" };
            out.finding(finding(rule, Confidence::Verified).param("signer", signer).evidence(Evidence::field(
                root,
                "Authenticode signer",
                signer,
            )));
        }
        None if authenticode.get("signed") == Some(&Value::Bool(false)) => {
            out.finding(finding("overview.win-unsigned", Confidence::Verified).evidence(Evidence::field(
                root,
                "certificate table",
                "absent",
            )));
        }
        None => {}
    }
}

fn windows_tree(tree: &dyn Tree, anchor: &Artifact, out: &mut Output) {
    // Summary facts are not visible through the tree, so these are recomputed from the artifacts.
    let executables: Vec<&Artifact> = tree.artifacts().iter().filter(|a| a.facts.contains_key("windows.authenticode")).collect();
    if executables.len() > 1 {
        let mut signers = std::collections::BTreeSet::new();
        let mut unsigned = 0u64;
        for file in &executables {
            let first = file.facts["windows.authenticode"].get("signatures").and_then(Value::as_array).and_then(|l| l.first());
            match first.and_then(|s| s.get("signer")).and_then(|s| text(s, "sha256").or_else(|| text(s, "common_name"))) {
                Some(signer) => {
                    signers.insert(signer);
                }
                None => unsigned += 1,
            }
        }
        out.finding(
            finding("overview.win-inner-signers", Confidence::Derived)
                .param("pe_files", executables.len())
                .param("unsigned", unsigned)
                .param("signers", signers.len())
                .evidence(Evidence::whole(anchor, executables.len())),
        );
    }
    let assemblies = tree.artifacts().iter().filter(|a| a.facts.contains_key("windows.dotnet")).count();
    if assemblies > 0 {
        out.finding(
            finding("overview.dotnet", Confidence::Derived).param("assemblies", assemblies).evidence(Evidence::whole(anchor, assemblies)),
        );
    }
    for app in tree.summary().get("windows.electron").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(name), Some(version), Some(electron)) = (text(app, "name"), text(app, "version"), text(app, "electron_version")) {
            out.finding(
                finding("overview.electron", Confidence::Derived)
                    .param("name", name)
                    .param("version", version)
                    .param("electron_version", electron)
                    .evidence(Evidence::whole(anchor, text(app, "folder").unwrap_or(name))),
            );
        }
    }
}

/// The main Apple app: the first top-level app bundle the Apple analyzer listed.
fn apple(tree: &dyn Tree, out: &mut Output) {
    let Some(bundles) = tree.summary().get("apple.bundles").and_then(|f| f.get("bundles")).and_then(Value::as_array) else { return };
    let main = bundles.iter().find(|b| b.get("top_level") == Some(&Value::Bool(true)) && text(b, "kind") == Some("app"));
    let Some(bundle) = main.or(bundles.first()) else { return };
    let Some(path) = bundle.get("path").and_then(Value::as_str) else { return };
    // The bundle's Info.plist is the artifact its identity was read from.
    let join = |rest: &str| if path.is_empty() { rest.to_string() } else { format!("{path}/{rest}") };
    let Some(info) = tree.get(&join("Info.plist")).or_else(|| tree.get(&join("Contents/Info.plist"))) else { return };
    // An app given as the input folder itself has no path in the tree; its name is the input's.
    if let Some(name) = path.rsplit('/').next().filter(|name| !name.is_empty()).or(Some(tree.input_name()).filter(|name| !name.is_empty()))
    {
        out.finding(finding("overview.product", Confidence::Verified).param("name", name).evidence(Evidence::whole(info, name)));
    }
    if let Some(id) = text(bundle, "bundle_id") {
        out.finding(finding("overview.identifier", Confidence::Verified).param("id", id).evidence(Evidence::field(
            info,
            "CFBundleIdentifier",
            id,
        )));
    }
    if let Some(version) = text(bundle, "version") {
        let shown = match text(bundle, "build") {
            Some(build) if build != version => format!("{version} (build {build})"),
            _ => version.to_string(),
        };
        out.finding(finding("overview.version", Confidence::Verified).param("version", shown).evidence(Evidence::field(
            info,
            "CFBundleShortVersionString",
            version,
        )));
    }
    let architectures: Vec<&str> =
        bundle.get("architectures").and_then(Value::as_array).map(|l| l.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if !architectures.is_empty() {
        out.finding(
            finding("overview.architectures", Confidence::Verified)
                .param("architectures", architectures.join(", "))
                .evidence(Evidence::whole(info, architectures.join(", "))),
        );
    }
    if bundles.len() > 1 {
        out.finding(
            finding("overview.apple-bundles", Confidence::Derived)
                .param("total", bundles.len())
                .param("path", if path.is_empty() { tree.input_name() } else { path })
                .evidence(Evidence::whole(info, bundles.len())),
        );
    }
    // Only an executable that was read can be called signed or unsigned.
    if text(bundle, "executable").and_then(|path| tree.get(path)).is_none_or(|exe| exe.digests.is_none()) {
        return;
    }
    let team = text(bundle, "team_id").unwrap_or("?");
    let signing = match text(bundle, "signing_type") {
        Some("developer-id") => finding("overview.apple-developer-id", Confidence::Derived).param("team_id", team),
        Some("distribution" | "app-store") => finding("overview.apple-distribution", Confidence::Derived).param("team_id", team),
        Some("development") => finding("overview.apple-development", Confidence::Derived).param("team_id", team),
        Some("adhoc" | "adhoc-linker") => finding("overview.apple-adhoc", Confidence::Verified),
        Some(other) => finding("overview.apple-other-signing", Confidence::Derived).param("signing_type", other),
        None => finding("overview.apple-unsigned", Confidence::Derived),
    };
    out.finding(signing.evidence(Evidence::whole(info, text(bundle, "signing_type").unwrap_or("none"))));
}

/// The main Android package: the first one the Android analyzer listed that is not a split.
fn android(tree: &dyn Tree, out: &mut Output) {
    let Some(packages) = tree.summary().get("android.packages").and_then(|f| f.get("packages")).and_then(Value::as_array) else { return };
    let Some(package) = packages.iter().find(|p| p.get("split").is_none_or(Value::is_null)).or(packages.first()) else { return };
    let Some(file) = text(package, "path").and_then(|path| tree.get(path)) else { return };
    if let Some(label) = text(package, "label") {
        out.finding(finding("overview.product", Confidence::Verified).param("name", label).evidence(Evidence::field(
            file,
            "application label",
            label,
        )));
    }
    if let Some(id) = text(package, "package") {
        out.finding(finding("overview.identifier", Confidence::Verified).param("id", id).evidence(Evidence::field(
            file,
            "manifest package",
            id,
        )));
    }
    if let Some(version) = text(package, "version_name") {
        let shown = match package.get("version_code").and_then(Value::as_u64) {
            Some(code) => format!("{version} (versionCode {code})"),
            None => version.to_string(),
        };
        out.finding(finding("overview.version", Confidence::Verified).param("version", shown).evidence(Evidence::field(
            file,
            "versionName",
            version,
        )));
    }
    if let (Some(min), Some(target)) = (package.get("min_sdk").and_then(Value::as_u64), package.get("target_sdk").and_then(Value::as_u64)) {
        out.finding(
            finding("overview.android-sdk", Confidence::Verified)
                .param("min_sdk", min)
                .param("target_sdk", target)
                .evidence(Evidence::field(file, "uses-sdk", target)),
        );
    }
    // The signer list is present only when the signing data was read; an empty one means unsigned.
    if let Some(signers) = package.get("signer_sha256").and_then(Value::as_array) {
        match signers.first().and_then(Value::as_str) {
            Some(sha256) => {
                out.finding(finding("overview.android-signer", Confidence::Verified).param("sha256", sha256).evidence(Evidence::field(
                    file,
                    "signer certificate",
                    sha256,
                )))
            }
            None => {
                // No verified signer: either nothing is signed, or signatures exist and failed.
                let schemes = file.facts.get("android.signing").and_then(|f| f.get("schemes")).and_then(Value::as_array);
                let rule = if schemes.is_some_and(|list| !list.is_empty()) {
                    "overview.android-signature-problem"
                } else {
                    "overview.android-unsigned"
                };
                out.finding(finding(rule, Confidence::Verified).evidence(Evidence::field(file, "signer certificate", "none")));
            }
        }
    }
}
