//! The text of every rule and limitation code the analyzer emits.

use aa_core::plugin::Rule;

const fn rule(id: &'static str, title_zh: &'static str, title_en: &'static str, text_zh: &'static str, text_en: &'static str) -> Rule {
    Rule { id, title_zh, title_en, text_zh, text_en }
}

pub const RULES: &[Rule] = &[
    // Identity
    rule(
        "apple.bundle-id",
        "Bundle 标识符",
        "Bundle identifier",
        "{bundle} 是一个 {kind} 类型的 bundle，标识符为 {bundle_id}。",
        "{bundle} is a bundle of kind {kind} with the identifier {bundle_id}.",
    ),
    rule(
        "apple.bundle-id-missing",
        "缺少 Bundle 标识符",
        "No bundle identifier",
        "{bundle} 的 Info.plist 没有 CFBundleIdentifier。正常的应用和框架都有这个字段。",
        "The Info.plist of {bundle} has no CFBundleIdentifier. Regular apps and frameworks always carry one.",
    ),
    rule("apple.bundle-name", "名称", "Name", "{bundle}：显示名称为 {name}。", "{bundle}: The display name is {name}."),
    rule("apple.bundle-version", "版本", "Version", "{bundle}：版本为 {version}。", "{bundle}: The version is {version}."),
    rule(
        "apple.min-os",
        "最低系统版本",
        "Minimum OS version",
        "{bundle}：需要 {platform} {version} 或更高版本。",
        "{bundle}: Requires {platform} {version} or later.",
    ),
    rule(
        "apple.supported-platforms",
        "支持的平台",
        "Supported platforms",
        "{bundle}：声明支持的平台：{platforms}。",
        "{bundle}: Declares support for: {platforms}.",
    ),
    rule(
        "apple.device-families",
        "支持的设备",
        "Device families",
        "{bundle}：声明支持的设备类型：{families}。",
        "{bundle}: Declares these device families: {families}.",
    ),
    rule("apple.app-category", "应用分类", "App category", "{bundle}：应用分类为 {value}。", "{bundle}: The app category is {value}."),
    rule("apple.copyright", "版权声明", "Copyright", "{bundle}：版权声明：{value}", "{bundle}: Copyright notice: {value}"),
    rule(
        "apple.executable",
        "主可执行文件",
        "Main executable",
        "{bundle}：主可执行文件是 {executable}，包含的架构：{archs}。",
        "{bundle}: The main executable is {executable}, with these architectures: {archs}.",
    ),
    rule(
        "apple.executable-built-for",
        "主可执行文件",
        "Main executable",
        "{bundle}：主可执行文件是 {executable}，包含的架构：{archs}；按其加载命令，为 {target} 及以上版本构建。",
        "{bundle}: The main executable is {executable}, with these architectures: {archs}. Its load commands say it was built for {target} or later.",
    ),
    rule(
        "apple.app-icon",
        "应用图标",
        "App icon",
        "{bundle}：Info.plist 指定的图标为 {icon}。",
        "{bundle}: The Info.plist names the icon {icon}.",
    ),
    rule(
        "apple.ipa",
        "IPA 安装包",
        "IPA package",
        "这是一个 IPA 安装包，其中的应用是 {app}。",
        "This is an IPA package; the app inside is {app}.",
    ),
    rule(
        "apple.pkg-distribution",
        "安装包（产品）",
        "Installer product",
        "安装包标题为「{title}」，包含 {count} 个组件包：{components}。带有安装前检查脚本：{scripted}。",
        "The installer is titled “{title}” and holds {count} component packages: {components}. It carries installation-check scripts: {scripted}.",
    ),
    rule(
        "apple.pkg-component",
        "安装包组件",
        "Installer component",
        "组件包 {identifier}：{details}。",
        "Component package {identifier}: {details}.",
    ),
    // Composition
    rule(
        "apple.build-info",
        "构建环境",
        "Build environment",
        "{bundle}：Info.plist 记录的构建环境：{details}。这些字段由 Xcode 写入，可以被改写。",
        "{bundle}: Build environment recorded in the Info.plist: {details}. Xcode writes these fields; they can be edited.",
    ),
    rule(
        "apple.embedded-code",
        "内嵌的代码",
        "Embedded code",
        "{bundle} 内嵌了 {count} 个代码组件：{summary}。完整列表见 apple.embedded。",
        "{bundle} embeds {count} code components: {summary}. The apple.embedded fact lists them all.",
    ),
    rule(
        "apple.framework",
        "使用的开发框架",
        "Framework in use",
        "{bundle} 使用了 {framework}。这是根据包内文件布局推断的，依据见证据。",
        "{bundle} uses {framework}. This is inferred from the files in the bundle; the evidence names them.",
    ),
    // Structure
    rule(
        "apple.localizations",
        "本地化语言",
        "Localisations",
        "{bundle} 带有 {count} 种语言的本地化资源：{languages}。",
        "{bundle} carries localised resources for {count} languages: {languages}.",
    ),
    rule(
        "apple.asset-catalogs",
        "资源目录（Assets.car）",
        "Asset catalogs",
        "{bundle} 中有 {count} 个编译后的资源目录（Assets.car），共 {bytes} 字节。其中的图片没有逐一解出分析。",
        "{bundle} holds {count} compiled asset catalogs (Assets.car), {bytes} bytes in total. The images inside were not extracted.",
    ),
    rule(
        "apple.dmg",
        "磁盘映像",
        "Disk image",
        "UDIF 磁盘映像（版本 {version}），{partitions} 个分区表项，展开后约 {megabytes} MB，数据块压缩方式：{compression}。",
        "A UDIF disk image (version {version}) with {partitions} partition entries, about {megabytes} MB when expanded; chunk compression: {compression}.",
    ),
    rule(
        "apple.dmg-encrypted",
        "加密的磁盘映像",
        "Encrypted disk image",
        "这是加密的磁盘映像（加密格式版本 {version}）。没有密码无法读取其中的任何内容。",
        "This disk image is encrypted (encrypted-image format version {version}). Nothing inside can be read without the password.",
    ),
    // Capabilities
    rule(
        "apple.usage-description",
        "声明使用受保护的资源",
        "Declares use of a protected resource",
        "{bundle}：声明需要访问「{resource}」（{key}），向用户展示的理由是：「{purpose}」。这是声明，不代表程序一定会使用。",
        "{bundle}: Declares access to “{resource}” ({key}). The reason shown to the user is: “{purpose}”. This is a declaration; the program does not necessarily use it.",
    ),
    rule(
        "apple.usage-description-empty",
        "受保护资源的使用理由为空",
        "Empty reason for a protected resource",
        "{bundle}：声明需要访问「{resource}」（{key}），但没有填写向用户展示的理由。",
        "{bundle}: Declares access to “{resource}” ({key}) but gives the user no reason for it.",
    ),
    rule(
        "apple.url-schemes",
        "注册的 URL Scheme",
        "Registered URL schemes",
        "{bundle}：注册了 {count} 个 URL Scheme：{schemes}。其他应用和网页可以通过这些地址唤起本应用并传入数据。",
        "{bundle}: Registers {count} URL schemes: {schemes}. Other apps and web pages can open this app through them and pass data in.",
    ),
    rule(
        "apple.queried-schemes",
        "查询的其他应用",
        "Queried URL schemes",
        "{bundle}：声明会查询 {count} 个 URL Scheme 是否可用：{schemes}。这通常用于检测设备上是否安装了对应的应用。",
        "{bundle}: Declares {count} URL schemes it may probe: {schemes}. This is how an app checks whether other apps are installed.",
    ),
    rule(
        "apple.document-types",
        "可打开的文档类型",
        "Document types",
        "{bundle}：声明可以打开 {count} 类文档：{types}。",
        "{bundle}: Declares {count} document types it can open: {types}.",
    ),
    rule(
        "apple.exported-types",
        "导出的类型标识",
        "Exported type identifiers",
        "{bundle}：定义并导出了 {count} 个统一类型标识（UTI）：{types}。",
        "{bundle}: Defines and exports {count} uniform type identifiers: {types}.",
    ),
    rule(
        "apple.imported-types",
        "导入的类型标识",
        "Imported type identifiers",
        "{bundle}：引用了 {count} 个其他程序定义的统一类型标识（UTI）：{types}。",
        "{bundle}: Imports {count} uniform type identifiers defined elsewhere: {types}.",
    ),
    rule(
        "apple.background-modes",
        "后台运行模式",
        "Background modes",
        "{bundle}：声明的后台运行模式：{modes}。",
        "{bundle}: Declares these background modes: {modes}.",
    ),
    rule(
        "apple.required-capabilities",
        "要求的设备能力",
        "Required device capabilities",
        "{bundle}：要求设备具备：{capabilities}。",
        "{bundle}: Requires these device capabilities: {capabilities}.",
    ),
    rule(
        "apple.agent-app",
        "不显示在程序坞",
        "Agent app",
        "{bundle}：{key} 为真：程序运行时不在程序坞和切换器中显示。",
        "{bundle}: {key} is set: the app runs without a Dock icon or an entry in the app switcher.",
    ),
    rule(
        "apple.background-only",
        "仅后台运行",
        "Background only",
        "{bundle}：{key} 为真：程序只在后台运行，没有界面。",
        "{bundle}: {key} is set: the app runs in the background only, without a user interface.",
    ),
    rule(
        "apple.file-sharing",
        "文件共享",
        "File sharing",
        "{bundle}：{key} 为真：应用的 Documents 目录可以通过访达或 iTunes 读写。",
        "{bundle}: {key} is set: the app's Documents folder can be read and written through Finder or iTunes.",
    ),
    rule(
        "apple.open-in-place",
        "原位打开文档",
        "Opens documents in place",
        "{bundle}：{key} 为真：应用的文档在「文件」应用中可见，其他应用可以原位打开。",
        "{bundle}: {key} is set: the app's documents show in the Files app and other apps can open them in place.",
    ),
    rule(
        "apple.scriptable",
        "支持 AppleScript",
        "Scriptable",
        "{bundle}：{key} 为真：程序可以被 AppleScript 控制。",
        "{bundle}: {key} is set: the app can be driven by AppleScript.",
    ),
    rule(
        "apple.extension-point",
        "应用扩展",
        "App extension",
        "应用扩展 {bundle} 接入的扩展点是 {point}。",
        "The app extension {bundle} plugs into the extension point {point}.",
    ),
    rule(
        "apple.entitlements",
        "签名中的权利（entitlements）",
        "Entitlements",
        "{file} 的签名中带有 {count} 项权利：{keys}。每一项的取值见证据。",
        "The signature of {file} carries {count} entitlements: {keys}. The evidence gives each value.",
    ),
    rule(
        "apple.app-groups",
        "应用组",
        "App groups",
        "{file} 可以访问 {count} 个应用组共享容器：{values}。同一开发者的应用和扩展通过它共享数据。",
        "{file} may use {count} app-group containers: {values}. Apps and extensions of one developer share data through them.",
    ),
    rule(
        "apple.keychain-groups",
        "钥匙串访问组",
        "Keychain access groups",
        "{file} 可以访问 {count} 个钥匙串访问组：{values}。",
        "{file} may use {count} keychain access groups: {values}.",
    ),
    rule(
        "apple.associated-domains",
        "关联域名",
        "Associated domains",
        "{file} 声明了 {count} 个关联域名：{values}。用于通用链接、共享网站凭据等。",
        "{file} declares {count} associated domains: {values}. They serve universal links, shared web credentials and the like.",
    ),
    rule(
        "apple.icloud-containers",
        "iCloud 容器",
        "iCloud containers",
        "{file} 可以访问 {count} 个 iCloud 容器：{values}。",
        "{file} may use {count} iCloud containers: {values}.",
    ),
    rule(
        "apple.push-notifications",
        "推送通知",
        "Push notifications",
        "{file} 可以接收推送通知，环境为 {environment}。",
        "{file} may receive push notifications, in the {environment} environment.",
    ),
    rule(
        "apple.pkg-scripts",
        "安装时运行的脚本",
        "Scripts run during installation",
        "组件包 {identifier} 在安装过程中会运行脚本：{scripts}。安装脚本通常以 root 权限执行，可以对系统做任何改动。",
        "The component package {identifier} runs scripts during installation: {scripts}. Installer scripts usually run as root and can change anything on the system.",
    ),
    // Hardening
    rule(
        "apple.ats-arbitrary-loads",
        "关闭了传输安全（ATS）",
        "App Transport Security disabled",
        "{bundle}：NSAllowsArbitraryLoads 为真：对所有连接关闭了 App Transport Security，程序可以用明文 HTTP 或弱 TLS 配置联网。",
        "{bundle}: NSAllowsArbitraryLoads is set: App Transport Security is off for every connection, so the app may use plain HTTP or weak TLS settings.",
    ),
    rule(
        "apple.ats-arbitrary-loads-narrowed",
        "传输安全（ATS）全局开关被细分项取代",
        "ATS global switch superseded",
        "{bundle}：NSAllowsArbitraryLoads 为真，但同时存在 {narrowed_by}。在 iOS 10 / macOS 10.12 及以上，这些细分项存在时全局开关被忽略；更早的系统上 ATS 对所有连接关闭。",
        "{bundle}: NSAllowsArbitraryLoads is set, alongside {narrowed_by}. From iOS 10 / macOS 10.12 on, the global switch is ignored when these narrower keys are present; on older systems ATS is off for every connection.",
    ),
    rule(
        "apple.ats-relaxed",
        "部分放宽传输安全（ATS）",
        "ATS relaxed for a class of content",
        "{bundle}：{key} 为真：这一类内容的连接不受 App Transport Security 约束。",
        "{bundle}: {key} is set: connections for this class of content are exempt from App Transport Security.",
    ),
    rule(
        "apple.ats-local-networking",
        "允许本地网络明文连接",
        "Local networking exempt from ATS",
        "{bundle}：NSAllowsLocalNetworking 为真：对本地网络地址的连接不受 App Transport Security 约束。",
        "{bundle}: NSAllowsLocalNetworking is set: connections to local network addresses are exempt from App Transport Security.",
    ),
    rule(
        "apple.ats-insecure-domain",
        "允许对指定域名使用明文 HTTP",
        "Plain HTTP allowed for a domain",
        "{bundle}：允许对 {domain} 使用明文 HTTP（包含子域名：{subdomains}）。",
        "{bundle}: Plain HTTP is allowed for {domain} (subdomains included: {subdomains}).",
    ),
    rule(
        "apple.ats-weak-tls",
        "允许对指定域名使用旧版 TLS",
        "Old TLS allowed for a domain",
        "{bundle}：对 {domain} 允许的最低 TLS 版本降到了 {version}（包含子域名：{subdomains}）。",
        "{bundle}: The minimum TLS version for {domain} is lowered to {version} (subdomains included: {subdomains}).",
    ),
    rule(
        "apple.ats-no-forward-secrecy",
        "不要求前向保密",
        "Forward secrecy not required",
        "{bundle}：对 {domain} 不要求使用具备前向保密的加密套件（包含子域名：{subdomains}）。",
        "{bundle}: Forward-secret cipher suites are not required for {domain} (subdomains included: {subdomains}).",
    ),
    rule(
        "apple.hardened-runtime",
        "已启用加固运行时",
        "Hardened runtime enabled",
        "{file} 的签名启用了加固运行时（Hardened Runtime）。",
        "The signature of {file} enables the hardened runtime.",
    ),
    rule(
        "apple.hardened-runtime-missing",
        "未启用加固运行时",
        "Hardened runtime not enabled",
        "{file} 的签名没有启用加固运行时。没有它，代码注入、动态库劫持等防护不生效，也无法通过公证。",
        "The signature of {file} does not enable the hardened runtime. Without it the protections against code injection and library hijacking do not apply, and the code cannot be notarized.",
    ),
    rule(
        "apple.runtime-exception",
        "放宽加固运行时的权利",
        "Hardened-runtime exception",
        "{file} 带有权利 {key}，它放宽了加固运行时的一项保护。",
        "{file} carries the entitlement {key}, which relaxes one protection of the hardened runtime.",
    ),
    rule(
        "apple.sandbox-on",
        "已启用应用沙盒",
        "App Sandbox enabled",
        "{file} 启用了应用沙盒（com.apple.security.app-sandbox）。",
        "{file} enables the App Sandbox (com.apple.security.app-sandbox).",
    ),
    rule(
        "apple.sandbox-off",
        "未启用应用沙盒",
        "App Sandbox not enabled",
        "{file} 没有启用应用沙盒，程序以当前用户的全部权限运行。Mac App Store 之外分发的应用常见这种情况。",
        "{file} does not enable the App Sandbox; the program runs with the full rights of the user. This is common for apps distributed outside the Mac App Store.",
    ),
    rule(
        "apple.sandbox-exceptions",
        "沙盒临时例外",
        "Sandbox temporary exceptions",
        "{file} 带有沙盒临时例外权利：{keys}。它们让沙盒内的程序访问原本不允许的资源。",
        "{file} carries sandbox temporary-exception entitlements: {keys}. They let a sandboxed program reach resources the sandbox otherwise denies.",
    ),
    rule(
        "apple.debuggable",
        "允许被调试",
        "Debugging allowed",
        "{file} 带有 {key} 权利，其他进程可以附加调试它。开发版本中这是正常的。",
        "{file} carries {key}: other processes may attach to it as a debugger. This is normal in a development build.",
    ),
    rule(
        "apple.debuggable-release",
        "发行版本允许被调试",
        "Debugging allowed in a distribution build",
        "{file} 使用发行证书签名，却带有 {key} 权利，其他进程可以附加调试它并读取其内存。发行版本不应带有这项权利。",
        "{file} is signed for distribution yet carries {key}: other processes may attach to it and read its memory. A distribution build should not have this entitlement.",
    ),
    // Network
    rule(
        "apple.update-feed",
        "自动更新地址",
        "Update feed",
        "{bundle}：Sparkle 自动更新地址为 {url}（声明了更新签名公钥：{signed_updates}）。",
        "{bundle}: The Sparkle update feed is {url} (an update-signing public key is declared: {signed_updates}).",
    ),
    rule(
        "apple.update-feed-http",
        "自动更新地址使用明文 HTTP",
        "Update feed over plain HTTP",
        "{bundle}：Sparkle 自动更新地址 {url} 使用明文 HTTP，更新信息在传输中可以被篡改（声明了更新签名公钥：{signed_updates}）。",
        "{bundle}: The Sparkle update feed {url} uses plain HTTP, so update information can be altered in transit (an update-signing public key is declared: {signed_updates}).",
    ),
    // Provenance
    rule(
        "apple.signature",
        "代码签名",
        "Code signature",
        "{file} 带有代码签名：标识符 {identifier}，cdhash {cdhash}（{hash_type}，{arch}），标志 {flags}。cdhash 由本工具根据签名中的代码目录计算。",
        "{file} carries a code signature: identifier {identifier}, cdhash {cdhash} ({hash_type}, {arch}), flags {flags}. The cdhash was computed by this tool from the code directory.",
    ),
    rule(
        "apple.team-id",
        "开发者团队 ID",
        "Team identifier",
        "{file} 的签名记录的团队 ID 是 {team}。",
        "The signature of {file} records the team identifier {team}.",
    ),
    rule(
        "apple.unsigned",
        "没有代码签名",
        "No code signature",
        "{file}（{arch}）没有代码签名，无法确认它的来源，也无法发现它是否被改动过。",
        "{file} ({arch}) has no code signature. Where it comes from cannot be established, nor whether it was altered.",
    ),
    rule(
        "apple.signed-adhoc",
        "临时签名（ad-hoc）",
        "Ad-hoc signature",
        "{file} 是临时签名（ad-hoc）：签名中没有证书，不能说明是谁签的，只能用来检查文件是否被改动。",
        "{file} is ad-hoc signed: the signature holds no certificate. It says nothing about who signed, and only lets changes to the file be detected.",
    ),
    rule(
        "apple.signed-adhoc-linker",
        "链接器自动生成的临时签名",
        "Linker-generated ad-hoc signature",
        "{file} 的签名是链接器在构建时自动生成的临时签名，没有证书，不能说明是谁签的。",
        "The signature of {file} is the ad-hoc one the linker adds at build time. It holds no certificate and says nothing about who built it.",
    ),
    rule(
        "apple.signed-developer-id",
        "Developer ID 签名",
        "Developer ID signature",
        "{file} 由「{signer}」签名。这是 Developer ID 证书，用于在 Mac App Store 之外分发软件。类型根据签名者证书的名称判断。",
        "{file} is signed by “{signer}”, a Developer ID certificate, used to distribute software outside the Mac App Store. The type is read from the signer certificate's name.",
    ),
    rule(
        "apple.signed-development",
        "开发证书签名",
        "Development signature",
        "{file} 由「{signer}」签名。这是开发证书，用于在开发者自己登记的设备上运行，不用于正式分发。类型根据签名者证书的名称判断。",
        "{file} is signed by “{signer}”, a development certificate, meant for the developer's own registered devices and not for release. The type is read from the signer certificate's name.",
    ),
    rule(
        "apple.signed-distribution",
        "分发证书签名",
        "Distribution signature",
        "{file} 由「{signer}」签名。这是分发证书，用于提交 App Store、Ad Hoc 或企业内部分发；具体是哪一种要看描述文件。类型根据签名者证书的名称判断。",
        "{file} is signed by “{signer}”, a distribution certificate, used for App Store submission, ad-hoc or in-house distribution; which one depends on the provisioning profile. The type is read from the signer certificate's name.",
    ),
    rule(
        "apple.signed-app-store",
        "App Store 签名",
        "App Store signature",
        "{file} 由「{signer}」签名。这是 Apple 在应用上架 App Store 时使用的证书。类型根据签名者证书的名称判断。",
        "{file} is signed by “{signer}”, the certificate Apple uses for apps delivered through the App Store. The type is read from the signer certificate's name.",
    ),
    rule(
        "apple.signed-apple-system",
        "Apple 系统软件签名",
        "Apple system software signature",
        "{file} 由「{signer}」签名，这是 Apple 自家软件使用的证书名称。类型根据签名者证书的名称判断。",
        "{file} is signed by “{signer}”, the certificate name Apple uses for its own software. The type is read from the signer certificate's name.",
    ),
    rule(
        "apple.signed-other",
        "其他证书签名",
        "Signed with another kind of certificate",
        "{file} 由「{signer}」签名。证书名称不属于 Apple 颁发的常见代码签名类型，可能是自签名证书或其他机构的证书。",
        "{file} is signed by “{signer}”. The certificate's name is none of the usual Apple-issued code-signing types; it may be self-signed or from another authority.",
    ),
    rule(
        "apple.certificate-chain",
        "签名中的证书链",
        "Certificates in the signature",
        "{file} 的签名中有一条 {count} 张证书的链：{chain}。每张证书的主体、序列号和有效期见证据。",
        "The signature of {file} holds a chain of {count} certificates: {chain}. The evidence gives each one's subject, serial number and validity.",
    ),
    rule(
        "apple.cms-valid",
        "签名值验证通过",
        "Signature value verifies",
        "已验证：{file} 的 CMS 签名中的摘要（{digest}）与代码目录一致，签名值可以用「{signer}」证书的公钥验证通过。这说明代码目录确实由该证书对应的私钥签署。",
        "Verified: the digest ({digest}) in the CMS signature of {file} equals that of the code directory, and the signature value verifies with the public key of the certificate “{signer}”. The code directory was signed with that certificate's private key.",
    ),
    rule(
        "apple.cms-invalid",
        "签名值验证失败",
        "Signature value does not verify",
        "{file} 的 CMS 签名验证失败：签名中的摘要与代码目录不符，或签名值无法用签名者证书的公钥验证。签名或代码目录在签署后被改动过。",
        "The CMS signature of {file} does not verify: its digest differs from the code directory's, or the signature value fails against the signer's public key. The signature or the code directory was altered after signing.",
    ),
    rule(
        "apple.directory-unbound",
        "代码目录未被签名覆盖",
        "A code directory is not covered by the signature",
        "{file} 有多个代码目录，但其中有的哈希不在已签名的列表中，这个代码目录没有受到签名保护。",
        "{file} has several code directories, and the hash of at least one is missing from the signed list: that directory is not protected by the signature.",
    ),
    rule(
        "apple.chain-apple-root",
        "证书链逐级验证到 Apple 根证书",
        "Chain verifies up to an Apple root",
        "已验证：{file} 签名中的 {count} 张证书（{chain}）逐级签发关系成立，根证书的指纹与本工具内置的「{root}」一致。未检查证书是否被吊销、当前是否过期。每张证书的主体、序列号和有效期见证据。",
        "Verified: each of the {count} certificates in the signature of {file} ({chain}) is signed by the next, and the root's fingerprint equals that of “{root}” built into this tool. Revocation and expiry as of today were not checked. The evidence gives each certificate's subject, serial number and validity.",
    ),
    rule(
        "apple.chain-unknown-root",
        "证书链的根不是已知的 Apple 根证书",
        "Chain ends in an unknown root",
        "{file} 签名中的证书链以一张自签名证书结束，它不是本工具已知的 Apple 根证书。这样的签名任何人都可以制作，不能证明来源。",
        "The certificate chain in the signature of {file} ends in a self-signed certificate that is not an Apple root known to this tool. Anyone can make such a signature; it proves no origin.",
    ),
    rule(
        "apple.chain-incomplete",
        "证书链不完整",
        "Incomplete certificate chain",
        "{file} 的签名没有带上完整的证书链，无法在离线状态下追溯到根证书。",
        "The signature of {file} does not include the whole certificate chain, so it cannot be followed to a root offline.",
    ),
    rule(
        "apple.chain-broken",
        "证书链签发关系不成立",
        "Broken certificate chain",
        "{file} 签名中的证书链有一级验证失败：某张证书并不是由它声称的上级证书签发的。",
        "One link of the certificate chain in the signature of {file} does not verify: a certificate was not signed by the issuer it names.",
    ),
    rule(
        "apple.signing-time",
        "签名时间",
        "Signing time",
        "{file} 的签名者声明的签名时间是 {time}。这个时间由签名者自己填写，没有第三方时间戳佐证。",
        "The signer of {file} states the signing time {time}. The signer writes this value; no third-party timestamp backs it.",
    ),
    rule(
        "apple.signing-time-stamped",
        "签名时间（附有时间戳）",
        "Signing time, with a timestamp token",
        "{file} 的签名者声明的签名时间是 {time}，签名中附有时间戳机构的令牌。令牌本身的签名没有验证。",
        "The signer of {file} states the signing time {time}, and the signature carries a timestamp-authority token. The token's own signature was not checked.",
    ),
    rule(
        "apple.signed-outside-validity",
        "签名时间不在证书有效期内",
        "Signed outside the certificate's validity",
        "{file} 声明的签名时间 {time} 不在签名者证书的有效期内。",
        "The stated signing time of {file}, {time}, lies outside the validity period of the signer's certificate.",
    ),
    rule(
        "apple.code-intact",
        "代码与签名一致",
        "Code matches its signature",
        "已验证：{file} 的 {pages} 个代码页哈希与文件内容全部一致（架构：{archs}），签名覆盖的代码在签署后没有被改动。",
        "Verified: all {pages} code-page hashes of {file} match the file's content (architectures: {archs}). The signed code was not altered after signing.",
    ),
    rule(
        "apple.code-and-seal-intact",
        "代码及签名绑定的内容与签名一致",
        "Code and sealed items match the signature",
        "已验证：{file} 的 {pages} 个代码页哈希与文件内容全部一致（架构：{archs}），签名覆盖的代码在签署后没有被改动；签名绑定的这些内容也与记录的哈希一致：{slots}。",
        "Verified: all {pages} code-page hashes of {file} match the file's content (architectures: {archs}), so the signed code was not altered after signing; and these items bound into the signature match their recorded hashes: {slots}.",
    ),
    rule(
        "apple.code-modified",
        "代码在签名后被改动",
        "Code modified after signing",
        "{file} 有 {pages} 个代码页的哈希与签名记录不符：文件在签署之后被改动过，系统会拒绝运行或在运行中终止它。",
        "{pages} code pages of {file} do not match the hashes in its signature: the file was changed after signing. The system will refuse to run it or kill it while running.",
    ),
    rule(
        "apple.other-code-intact",
        "其他程序文件与签名一致",
        "Other code matches its signatures",
        "已验证：另有 {count} 个 Mach-O 文件（其他 bundle 的主程序，以及不属于任何 bundle 的程序文件），共 {pages} 个代码页哈希与文件内容全部一致，它们在签署后没有被改动。",
        "Verified: for {count} further Mach-O files (main executables of other bundles, and code that belongs to no bundle), all {pages} code-page hashes match the files' content. They were not altered after signing.",
    ),
    rule(
        "apple.seal-intact",
        "签名绑定的内容一致",
        "Sealed items match",
        "已验证：{file} 的签名绑定的这些内容与记录的哈希一致：{slots}。",
        "Verified: these items bound into the signature of {file} match their recorded hashes: {slots}.",
    ),
    rule(
        "apple.seal-broken",
        "签名绑定的内容被改动",
        "A sealed item was modified",
        "{file} 的签名绑定的「{slot}」与记录的哈希不符，它在签署之后被改动过。",
        "The item “{slot}” bound into the signature of {file} does not match its recorded hash: it was changed after signing.",
    ),
    rule(
        "apple.seal-data-missing",
        "签名绑定的内容缺失",
        "A sealed item is missing",
        "{file} 的签名记录了「{slot}」的哈希，但对应的内容不在分析范围内，无法核对。",
        "The signature of {file} records a hash for “{slot}”, but the item itself is not among the analyzed files, so it could not be compared.",
    ),
    rule(
        "apple.resources-intact",
        "包内资源与签名一致",
        "Bundle resources match the seal",
        "已验证：{bundle} 的 CodeResources 中列出的 {files} 个文件哈希全部一致，{nested} 个内嵌代码的 cdhash 一致。",
        "Verified: the {files} files listed in the CodeResources of {bundle} all match their hashes, and {nested} nested code items match their cdhash.",
    ),
    rule(
        "apple.nested-resources-intact",
        "内嵌组件的资源与签名一致",
        "Nested bundles match their seals",
        "已验证：{count} 个内嵌 bundle（框架、扩展等）各自 CodeResources 中列出的文件全部一致，没有多出或缺少的文件。",
        "Verified: in {count} nested bundles (frameworks, extensions, …) every file listed in the bundle's own CodeResources matches, with none added or missing.",
    ),
    rule(
        "apple.resources-modified",
        "包内文件在签名后被改动",
        "Bundle files modified after signing",
        "{bundle} 中有 {count} 个文件的内容与 CodeResources 记录的哈希不符，它们在签署之后被改动过。",
        "{count} files in {bundle} differ from the hashes recorded in CodeResources: they were changed after signing.",
    ),
    rule(
        "apple.nested-code-replaced",
        "内嵌代码与签名记录不符",
        "Nested code differs from the seal",
        "{bundle} 中有 {count} 个内嵌代码的 cdhash 与 CodeResources 记录的不符，它们在签署之后被替换或重新签名过：{paths}。",
        "{count} nested code items in {bundle} have a cdhash other than the one CodeResources records; they were replaced or re-signed after the bundle was signed: {paths}.",
    ),
    rule(
        "apple.resources-missing",
        "签名记录的文件缺失",
        "Sealed files are missing",
        "{bundle} 的 CodeResources 列出了 {count} 个不在包内的文件：{paths}。它们可能被删除，也可能没有被解包出来。",
        "The CodeResources of {bundle} lists {count} files that are not in the bundle: {paths}. They were removed, or were not unpacked.",
    ),
    rule(
        "apple.resources-added",
        "包内有签名未覆盖的文件",
        "Files not covered by the seal",
        "{bundle} 中有 {count} 个文件不在 CodeResources 的列表中，它们可能是签署之后加进去的。判断时只套用了标准的豁免规则，自定义规则可能使其中一些属于正常情况。",
        "{count} files in {bundle} are not listed in CodeResources; they may have been added after signing. Only the standard exemption rules were applied, so custom rules may make some of these legitimate.",
    ),
    rule(
        "apple.notarization-ticket",
        "附带公证票据",
        "Stapled notarization ticket",
        "{bundle} 附带了公证票据文件（{bytes} 字节）。本工具只确认票据文件存在，没有验证票据内容，也没有向 Apple 查询公证状态。",
        "{bundle} has a stapled notarization ticket ({bytes} bytes). This tool only notes that the ticket file is present; it did not validate the ticket or ask Apple about the notarization status.",
    ),
    rule(
        "apple.code-summary",
        "代码签名概览",
        "Code signing overview",
        "共有 {count} 个 Mach-O 文件，按签名类型：{summary}。出现的团队 ID：{teams}。",
        "{count} Mach-O files in all; by signature type: {summary}. Team identifiers seen: {teams}.",
    ),
    rule(
        "apple.nested-team-differs",
        "内嵌代码由其他团队签名",
        "Nested code signed by another team",
        "包内有 {count} 个 Mach-O 文件的签名团队 ID 是 {team}，与主程序的不同。第三方组件保留原签名时会出现这种情况。",
        "{count} Mach-O files in the bundle are signed with the team identifier {team}, not the main executable's. This happens when third-party components keep their own signature.",
    ),
    rule(
        "apple.profile",
        "描述文件",
        "Provisioning profile",
        "包内的描述文件名为「{name}」，属于团队 {team}，创建于 {created}，到期时间 {expires}。",
        "The embedded provisioning profile is named “{name}”, belongs to team {team}, was created {created} and expires {expires}.",
    ),
    rule(
        "apple.profile-development",
        "开发描述文件",
        "Development profile",
        "这是开发描述文件：只允许在登记的 {devices} 台设备上运行，并允许调试。",
        "A development profile: the app may run only on its {devices} registered devices, and debugging is allowed.",
    ),
    rule(
        "apple.profile-ad-hoc",
        "Ad Hoc 描述文件",
        "Ad-hoc profile",
        "这是 Ad Hoc 分发描述文件：只允许在登记的 {devices} 台设备上运行，不允许调试。",
        "An ad-hoc distribution profile: the app may run only on its {devices} registered devices, without debugging.",
    ),
    rule(
        "apple.profile-enterprise",
        "企业内部分发描述文件",
        "Enterprise (in-house) profile",
        "这是企业内部分发描述文件（ProvisionsAllDevices）：应用可以安装到任何设备上，不经过 App Store 审核。",
        "An enterprise in-house profile (ProvisionsAllDevices): the app can be installed on any device without App Store review.",
    ),
    rule(
        "apple.profile-app-store",
        "App Store 描述文件",
        "App Store profile",
        "这是 App Store 分发描述文件：没有设备列表，用于提交 App Store 或 TestFlight。",
        "An App Store distribution profile: it lists no devices and serves submission to the App Store or TestFlight.",
    ),
    rule(
        "apple.profile-developer-id",
        "Developer ID 描述文件",
        "Developer ID profile",
        "这是 macOS 的 Developer ID 描述文件：适用于所有设备，用于在 Mac App Store 之外分发并使用受限的系统能力。",
        "A macOS Developer ID profile: it applies to all devices and lets software distributed outside the Mac App Store use restricted capabilities.",
    ),
    rule(
        "apple.profile-signature-valid",
        "描述文件签名验证通过",
        "Profile signature verifies",
        "已验证：描述文件的 CMS 签名值可以用「{signer}」证书的公钥验证通过（证书链逐级验证到已知的 Apple 根证书：{anchored}）。",
        "Verified: the profile's CMS signature value verifies with the public key of the certificate “{signer}” (chain verified up to a known Apple root: {anchored}).",
    ),
    rule(
        "apple.profile-signature-invalid",
        "描述文件签名验证失败",
        "Profile signature does not verify",
        "描述文件的 CMS 签名验证失败，文件在签发后被改动过。",
        "The profile's CMS signature does not verify: the file was altered after it was issued.",
    ),
    rule(
        "apple.profile-covers-entitlements",
        "描述文件覆盖了程序的全部权利",
        "Profile covers the executable's entitlements",
        "主程序签名中的 {count} 项权利都在描述文件允许的范围内。",
        "All {count} entitlements in the main executable's signature are within what the profile grants.",
    ),
    rule(
        "apple.profile-lists-signer",
        "签名证书在描述文件中",
        "Signer is listed in the profile",
        "已验证：主程序的签名证书在描述文件的开发者证书列表中。",
        "Verified: the certificate that signed the main executable is among the developer certificates of the profile.",
    ),
    rule(
        "apple.store-metadata",
        "App Store 购买信息",
        "App Store purchase metadata",
        "安装包带有 iTunesMetadata.plist，说明它是从 App Store 下载的：商品「{item}」（编号 {item_id}）。其中是否带有购买者账号（账号本身已脱敏，不写入报告）：{account_present}。",
        "The package carries iTunesMetadata.plist, so it was downloaded from the App Store: item “{item}” (id {item_id}). Buyer account present (the account itself is redacted and not copied into the report): {account_present}.",
    ),
    rule(
        "apple.sc-info",
        "FairPlay 授权文件",
        "FairPlay key files",
        "应用包内有 SC_Info 目录（{count} 个文件），这是 App Store 版应用的 FairPlay 授权数据。",
        "The app holds an SC_Info folder ({count} files): FairPlay licensing data of an App Store copy.",
    ),
    rule(
        "apple.pkg-signed",
        "安装包签名",
        "Installer package signature",
        "{file} 由「{signer}」签名（签名形式：{styles}），证书链：{chain}。",
        "{file} is signed by “{signer}” (signature styles: {styles}); certificate chain: {chain}.",
    ),
    rule(
        "apple.pkg-signature-valid-apple-root",
        "安装包签名验证通过",
        "Package signature verifies",
        "已验证：{file} 的目录校验和正确，签名值可以用签名者证书的公钥验证通过，证书链逐级验证到 {anchor}。未检查证书是否被吊销、是否已公证。",
        "Verified: the table-of-contents checksum of {file} is correct, the signature value verifies with the signer's public key, and the chain verifies up to {anchor}. Revocation and notarization were not checked.",
    ),
    rule(
        "apple.pkg-signature-valid",
        "安装包签名值验证通过，但证书链未追溯到 Apple 根证书",
        "Package signature verifies, chain not anchored",
        "{file} 的目录校验和正确，签名值可以用签名者证书的公钥验证通过；但证书链没有追溯到已知的 Apple 根证书（{anchor}），不能证明来源。",
        "The table-of-contents checksum of {file} is correct and the signature value verifies with the signer's public key, but the chain does not reach a known Apple root ({anchor}), so it proves no origin.",
    ),
    rule(
        "apple.pkg-signature-invalid",
        "安装包签名验证失败",
        "Package signature does not verify",
        "{file} 的签名值无法用签名者证书的公钥验证，安装包在签署后被改动过。",
        "The signature value of {file} fails against the signer's public key: the package was altered after signing.",
    ),
    rule(
        "apple.pkg-unsigned",
        "安装包没有签名",
        "Unsigned installer package",
        "{file} 是没有签名的安装包，无法确认它的来源。安装包以管理员权限运行其中的脚本。",
        "{file} is an installer package without a signature; where it comes from cannot be established. Installer packages run their scripts with administrator rights.",
    ),
    // Privacy
    rule(
        "apple.privacy-manifest",
        "隐私清单",
        "Privacy manifest",
        "{owner} 带有隐私清单（PrivacyInfo.xcprivacy）：是否声明跟踪 {tracking}，声明收集 {collected} 类数据，声明使用 {apis} 类需说明理由的 API。这是开发者的自我声明。",
        "{owner} has a privacy manifest (PrivacyInfo.xcprivacy): tracking declared {tracking}, {collected} collected data types, {apis} required-reason API categories. This is the developer's own declaration.",
    ),
    rule(
        "apple.privacy-tracking",
        "声明进行跟踪",
        "Tracking declared",
        "{owner} 的隐私清单声明会跟踪用户，或列出了跟踪域名：{domains}。",
        "The privacy manifest of {owner} declares tracking, or lists tracking domains: {domains}.",
    ),
    rule(
        "apple.privacy-collected-data",
        "声明收集的数据",
        "Declared data collection",
        "{owner} 的隐私清单声明收集 {count} 类数据：{types}。",
        "The privacy manifest of {owner} declares {count} collected data types: {types}.",
    ),
    rule(
        "apple.privacy-required-reason-apis",
        "声明使用的受限 API",
        "Declared required-reason APIs",
        "{owner} 的隐私清单声明使用 {count} 类需说明理由的 API（方括号内为理由代码）：{apis}。",
        "The privacy manifest of {owner} declares {count} required-reason API categories (reason codes in brackets): {apis}.",
    ),
    // Code
    rule(
        "apple.fairplay",
        "代码被 FairPlay 加密",
        "Code encrypted with FairPlay",
        "{file}（{arch}）的代码段有 {bytes} 字节处于 FairPlay 加密状态（cryptid 不为 0）。这是 App Store 下载的应用的正常状态；加密部分的内容无法分析，字符串、符号等结论不包含这部分代码。",
        "{bytes} bytes of the code of {file} ({arch}) are FairPlay-encrypted (cryptid is not 0). This is the normal state of an app downloaded from the App Store. The encrypted part cannot be analyzed; findings about strings, symbols and the like do not cover it.",
    ),
    // Anomalies
    rule(
        "apple.executable-missing",
        "主可执行文件缺失",
        "Main executable missing",
        "{bundle} 的 Info.plist 指定主可执行文件为 {executable}，但包内没有这个文件。",
        "The Info.plist of {bundle} names {executable} as the main executable, but the bundle has no such file.",
    ),
    rule(
        "apple.executable-not-macho",
        "主可执行文件不是 Mach-O",
        "Main executable is not a Mach-O",
        "{bundle} 的主可执行文件 {executable} 不是 Mach-O 程序（类型：{mime}），可能是启动脚本。",
        "The main executable {executable} of {bundle} is not a Mach-O program (type: {mime}); it may be a launcher script.",
    ),
    rule(
        "apple.identifier-mismatch",
        "签名标识符与 Bundle 标识符不同",
        "Signature identifier differs from the bundle identifier",
        "{bundle}：Info.plist 中的标识符是 {bundle_id}，而主程序签名中的标识符是 {identifier}。",
        "{bundle}: The Info.plist says {bundle_id}, while the main executable's signature says {identifier}.",
    ),
    rule(
        "apple.slices-differ",
        "各架构的签名不一致",
        "Architectures are signed differently",
        "{file} 的各个架构（{archs}）签名的标识符、团队或类型不一致。同一次构建和签名不会出现这种情况。",
        "The architectures of {file} ({archs}) differ in signature identifier, team or type. One build signed once would not look like this.",
    ),
    rule(
        "apple.entitlements-differ",
        "两种格式的权利内容不一致",
        "XML and DER entitlements differ",
        "{file} 签名中 XML 格式与 DER 格式的权利列表不一致。系统的不同部分读取不同格式，不一致可能被用来骗过检查。",
        "The XML and DER forms of the entitlements in the signature of {file} list different keys. Different parts of the system read different forms; a mismatch can be used to deceive checks.",
    ),
    rule(
        "apple.private-entitlements",
        "带有 Apple 私有权利",
        "Apple-private entitlements",
        "{file} 带有 Apple 私有权利：{keys}。这类权利只对 Apple 自己签名的软件生效，出现在第三方软件中通常意味着面向越狱环境或经过改造。",
        "{file} carries Apple-private entitlements: {keys}. They take effect only for software Apple itself signs; in third-party software they usually point to a jailbreak target or a modified build.",
    ),
    rule(
        "apple.unsigned-nested",
        "包内有未签名的代码",
        "Unsigned code inside a bundle",
        "包内有 {count} 个 Mach-O 文件没有代码签名。",
        "{count} Mach-O files inside the bundle have no code signature.",
    ),
    rule(
        "apple.profile-entitlement-mismatch",
        "程序的权利超出描述文件范围",
        "Entitlements beyond the profile",
        "主程序签名中有 {count} 项权利不在描述文件允许的范围内：{keys}。系统安装或启动时会拒绝这样的应用，除非这些权利不需要描述文件授权。",
        "{count} entitlements in the main executable's signature are not within what the profile grants: {keys}. The system refuses such an app at install or launch, unless these entitlements need no profile.",
    ),
    rule(
        "apple.profile-signer-not-listed",
        "签名证书不在描述文件中",
        "Signer is not listed in the profile",
        "主程序的签名证书不在描述文件的开发者证书列表中，描述文件与签名不配套。",
        "The certificate that signed the main executable is not among the developer certificates of the profile: profile and signature do not belong together.",
    ),
    rule(
        "apple.xar-checksum-mismatch",
        "xar 目录校验和不符",
        "xar table-of-contents checksum mismatch",
        "{file} 的目录校验和与归档中记录的不一致，归档损坏或被改动过。",
        "The table-of-contents checksum of {file} differs from the one stored in the archive: the archive is damaged or was altered.",
    ),
    // Limitations
    rule(
        "apple.plist-unreadable",
        "属性列表无法解析",
        "Unreadable property list",
        "这些属性列表文件无法解析（损坏或格式不受支持），其中的信息没有进入报告。",
        "These property lists could not be parsed (damaged, or in an unsupported form). What they hold is not in the report.",
    ),
    rule(
        "apple.package-info-unreadable",
        "安装包描述文件无法解析",
        "Unreadable installer description",
        "安装包中的 PackageInfo 或 Distribution 不是有效的 XML，安装位置和安装脚本的信息没有进入报告。",
        "The PackageInfo or Distribution file of the package is not valid XML. Install location and script information are not in the report.",
    ),
    rule(
        "apple.macho-unreadable",
        "Mach-O 文件无法解析",
        "Unreadable Mach-O file",
        "这些文件有 Mach-O 的文件头，但加载命令无法解析，签名和加密状态没有检查。",
        "These files have a Mach-O header, but their load commands could not be parsed. Signature and encryption were not examined.",
    ),
    rule(
        "apple.signature-unreadable",
        "代码签名无法解析",
        "Unreadable code signature",
        "这些文件带有代码签名，但签名数据无法解析，签名的任何内容都没有检查。",
        "These files carry a code signature that could not be parsed. Nothing about the signature was checked.",
    ),
    rule(
        "apple.cms-unreadable",
        "签名中的证书数据无法解析",
        "Unreadable CMS signature",
        "这些文件的签名中的 CMS 数据无法解析，签名者证书和签名值没有检查；代码页哈希的核对不受影响。",
        "The CMS data in the signature of these files could not be parsed. Signer certificates and the signature value were not checked; the page-hash comparison is unaffected.",
    ),
    rule(
        "apple.cms-unchecked",
        "签名值未能验证",
        "Signature value not checked",
        "这些文件的签名值没有验证（算法不受支持或缺少签名者证书），既不能说有效，也不能说无效。",
        "The signature value of these files was not checked (unsupported algorithm, or the signer's certificate is absent). It is neither known to be valid nor invalid.",
    ),
    rule(
        "apple.chain-unchecked",
        "证书链未能逐级验证",
        "Certificate chain not checked",
        "这些文件签名中的证书链有的环节没有验证（算法不受支持）。",
        "Some links of the certificate chain in the signature of these files were not checked (unsupported algorithm).",
    ),
    rule(
        "apple.pages-unchecked",
        "代码页哈希未能核对",
        "Page hashes not compared",
        "这些文件的代码页哈希没有核对（签名声明的范围与文件不符），无法判断文件是否被改动。",
        "The code-page hashes of these files were not compared (the range the signature claims does not fit the file). Whether the file was altered is not known.",
    ),
    rule(
        "apple.entitlements-unreadable",
        "权利数据无法解析",
        "Unreadable entitlements",
        "这些文件签名中的权利（entitlements）数据无法解析，程序声明了哪些权利不清楚。",
        "The entitlements in the signature of these files could not be parsed. Which entitlements the program claims is not known.",
    ),
    rule(
        "apple.profile-unreadable",
        "描述文件无法解析",
        "Unreadable provisioning profile",
        "这些描述文件无法解析，其中的团队、设备和权利信息没有进入报告。",
        "These provisioning profiles could not be parsed. Their team, device and entitlement data are not in the report.",
    ),
    rule(
        "apple.fairplay-encrypted",
        "代码被 FairPlay 加密，无法分析",
        "FairPlay-encrypted code was not analyzed",
        "这些文件的代码段被 FairPlay 加密。加密部分的字符串、符号、网络地址等都读不出来，报告中的相关结论不包含这部分代码；加密范围内的代码页哈希也没有核对。",
        "The code of these files is FairPlay-encrypted. Strings, symbols, addresses and the like in the encrypted part cannot be read, so the report's findings do not cover it; page hashes inside the encrypted range were not compared either.",
    ),
    rule(
        "apple.findings-capped",
        "部分条目未逐一报告",
        "Some items were not reported one by one",
        "同类条目过多，只逐一报告了前面的一部分；其余的数据仍在各文件的事实（facts）中。",
        "There were too many items of one kind; only the first ones were reported individually. The data of the rest is still in the files' facts.",
    ),
    rule(
        "apple.trust-not-evaluated",
        "未做在线和系统级的信任评估",
        "Trust was not evaluated online or against system policy",
        "代码签名的检查全部离线完成：没有查询证书是否被吊销，没有按当前日期判断证书是否过期，没有向 Apple 查询公证状态，也没有模拟 Gatekeeper 的策略（签名要求表达式没有求值）。报告中的「已验证」只指明确写出的那些检查。",
        "Every signature check was made offline: certificate revocation was not queried, expiry as of today was not judged, Apple was not asked about notarization, and Gatekeeper's policy was not simulated (requirement expressions were not evaluated). “Verified” in this report covers only the checks it names.",
    ),
];

#[cfg(test)]
mod tests {
    use super::RULES;

    /// Keys that name facts, not rules.
    const FACTS: &[&str] = &["apple.macho", "apple.xar", "apple.ats", "apple.embedded", "apple.bundles"];

    #[test]
    fn every_id_used_in_the_code_has_text() {
        let sources = [
            include_str!("analyzer.rs"),
            include_str!("extras.rs"),
            include_str!("info.rs"),
            include_str!("signing.rs"),
            include_str!("tree.rs"),
            include_str!("inspect.rs"),
        ];
        let mut used = std::collections::BTreeSet::new();
        for source in sources {
            let mut rest = source;
            while let Some(start) = rest.find("\"apple.") {
                let tail = &rest[start + 1..];
                let end = tail.find('"').unwrap_or(tail.len());
                let id = &tail[..end];
                if id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-') {
                    used.insert(id.to_string());
                }
                rest = &tail[end..];
            }
        }
        let known: std::collections::BTreeSet<&str> = RULES.iter().map(|r| r.id).collect();
        let missing: Vec<&String> = used.iter().filter(|id| !known.contains(id.as_str()) && !FACTS.contains(&id.as_str())).collect();
        assert!(missing.is_empty(), "ids without rule text: {missing:?}");
        let unused: Vec<&&str> = known.iter().filter(|id| !used.contains(**id)).collect();
        assert!(unused.is_empty(), "rules never emitted: {unused:?}");
    }

    #[test]
    fn ids_are_unique_and_texts_complete() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in RULES {
            assert!(seen.insert(rule.id), "duplicate rule {}", rule.id);
            assert!(rule.id.starts_with("apple."));
            for text in [rule.title_zh, rule.title_en, rule.text_zh, rule.text_en] {
                assert!(!text.is_empty(), "empty text in {}", rule.id);
            }
            // Both languages must use the same placeholders.
            let placeholders = |text: &str| {
                let mut names: Vec<String> =
                    text.split('{').skip(1).filter_map(|part| part.split_once('}').map(|(name, _)| name.to_string())).collect();
                names.sort();
                names.dedup();
                names
            };
            assert_eq!(placeholders(rule.text_zh), placeholders(rule.text_en), "placeholders differ in {}", rule.id);
        }
    }
}
