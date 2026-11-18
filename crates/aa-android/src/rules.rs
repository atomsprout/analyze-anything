//! The words for every rule and limitation code of the Android analyzer, in Chinese and English.

use aa_core::plugin::Rule;

const fn r(id: &'static str, title_zh: &'static str, title_en: &'static str, text_zh: &'static str, text_en: &'static str) -> Rule {
    Rule { id, title_zh, title_en, text_zh, text_en }
}

pub const RULES: &[Rule] = &[
    // ---- Identity ----
    r(
        "android.package",
        "Android 应用包",
        "Android package",
        "这是一个 Android 应用包（{format}）：包名 {package}，版本 {version_name}（versionCode {version_code}）。",
        "This is an Android package ({format}): package name {package}, version {version_name} (versionCode {version_code}).",
    ),
    r(
        "android.split-apk",
        "拆分 APK",
        "Split APK",
        "这是拆分 APK“{split}”（属于 {for}），只含应用的一部分，需要与基础 APK 一起安装。对拆分包只做清单和签名检查。",
        "This is the split APK \"{split}\" (of {for}). It holds one part of the app and installs together with the base APK. Only its manifest and signature are checked.",
    ),
    r(
        "android.apk-set",
        "多 APK 安装包",
        "Set of APKs",
        "这是一个 {format} 容器，内含 {apks} 个 APK：包名 {package}，基础 APK 是 {base}，拆分包：{splits}。",
        "This is a {format} container with {apks} APKs: package {package}, base APK {base}, splits: {splits}.",
    ),
    r(
        "android.apk-set-mismatch",
        "容器内的 APK 互不一致",
        "APKs in the set disagree",
        "容器内的 APK 出现了 {packages} 个不同的包名、{signers} 组不同的签名证书。同一应用的各个拆分包必须包名相同、签名相同，否则无法一起安装。",
        "The APKs in the container carry {packages} different package names and {signers} different sets of signing certificates. The parts of one app must share both, or they cannot be installed together.",
    ),
    r(
        "android.app-label",
        "应用名称",
        "App name",
        "应用显示名称是“{label}”（来源：{source}，取默认语言配置）。",
        "The app's display name is \"{label}\" (from {source}, default language configuration).",
    ),
    r(
        "android.sdk-levels",
        "支持的 Android 版本",
        "Supported Android versions",
        "最低支持 {min}，目标版本 {target}，编译所用 SDK：{compile}。",
        "Minimum supported: {min}. Target: {target}. Compiled against: {compile}.",
    ),
    r(
        "android.application-class",
        "自定义 Application 类",
        "Custom Application class",
        "应用启动时最先运行的类是 {class}。",
        "The first class to run when the app starts is {class}.",
    ),
    r(
        "android.launcher-activity",
        "启动入口",
        "Launcher entry",
        "桌面图标打开的界面：{activities}。",
        "The screen opened from the launcher icon: {activities}.",
    ),
    r(
        "android.shared-user-id",
        "共享用户 ID",
        "Shared user ID",
        "清单声明了 sharedUserId“{uid}”：与使用相同 ID 且签名相同的应用共享数据和权限。android.uid.* 是系统身份，只有平台签名的应用才能使用。该机制自 Android 10 起已废弃。",
        "The manifest declares sharedUserId \"{uid}\": the app shares data and permissions with other apps that use the same ID and signature. The android.uid.* IDs are system identities that only platform-signed apps may use. The mechanism is deprecated since Android 10.",
    ),
    r(
        "android.bundle-modules",
        "应用包模块",
        "Bundle modules",
        "这个 App Bundle 有 {count} 个模块：{modules}。",
        "The app bundle has {count} modules: {modules}.",
    ),
    // ---- Provenance ----
    r(
        "android.signature-verified",
        "签名验证通过",
        "Signature verified",
        "{scheme} 签名验证通过（{signers} 个签名者）：{details}。这说明文件自签名后未被改动，并且确由持有下述证书私钥的人签名。",
        "The {scheme} signature verifies ({signers} signer(s)): {details}. The file has not changed since it was signed, and it was signed by the holder of the certificate's private key.",
    ),
    r(
        "android.signature-invalid",
        "签名验证失败",
        "Signature does not verify",
        "{scheme} 签名验证失败：{reason}。文件在签名后被改动过，或签名本身已损坏；Android 会拒绝安装依赖该签名方案的此文件。",
        "The {scheme} signature does not verify: {reason}. The file was changed after signing, or the signature is damaged; Android refuses to install the file where it relies on this scheme.",
    ),
    r(
        "android.signing-block-malformed",
        "APK 签名块损坏",
        "APK Signing Block is malformed",
        "中央目录前有 APK 签名块的标记，但其结构损坏：{reason}。v2/v3 签名无法读取。",
        "The marker of an APK Signing Block sits before the central directory, but the block is malformed: {reason}. The v2/v3 signatures cannot be read.",
    ),
    r(
        "android.unsigned",
        "没有签名",
        "Not signed",
        "这个 {format} 没有任何签名（既没有 META-INF 下的签名文件，也没有 APK 签名块）。未签名的 APK 无法安装，也无从判断来源。",
        "This {format} carries no signature (no signature files under META-INF and no APK Signing Block). An unsigned APK cannot be installed, and nothing ties it to a publisher.",
    ),
    r(
        "android.v1-only",
        "只有 v1（JAR）签名",
        "Only a v1 (JAR) signature",
        "APK 只有 v1（JAR）签名，没有 v2/v3。v1 只保护压缩包内的各个文件，不保护压缩包整体；目标 API 30 及以上的应用在 Android 11+ 上必须带 v2 及以上签名才能安装（本应用目标 API {target}，最低 API {min}）。",
        "The APK has only a v1 (JAR) signature, no v2/v3. v1 protects the files inside the archive but not the archive as a whole; apps targeting API 30 or higher need v2 or newer to install on Android 11+ (this app targets API {target}, minimum API {min}).",
    ),
    r(
        "android.v1-missing",
        "缺少 v1 签名",
        "No v1 signature",
        "APK 没有 v1（JAR）签名，而清单声明的最低版本是 API {min}。Android 7.0（API 24）之前的系统只认 v1 签名，无法安装这个文件。",
        "The APK has no v1 (JAR) signature, yet its manifest declares a minimum of API {min}. Android versions before 7.0 (API 24) know only v1 and cannot install the file.",
    ),
    r(
        "android.signature-stripped",
        "较新的签名方案被移除",
        "A newer signature scheme was removed",
        "签名数据表明此 APK 签名时还带有 {schemes} 签名，但文件中已找不到。这是签名降级的迹象；Android 会因此拒绝安装。",
        "The signature data says the APK was also signed with {schemes}, which is no longer in the file. This is the mark of a signature downgrade; Android refuses to install such a file.",
    ),
    r(
        "android.signer-mismatch",
        "不同签名方案的签名者不一致",
        "Signers differ between schemes",
        "以下签名方案使用的证书与其他方案不一致，且没有密钥轮换记录能解释：{schemes}。正常签名的 APK 各方案出自同一签名者。",
        "The certificates of these schemes differ from the others, and no key rotation history explains it: {schemes}. A normally signed APK has the same signer in every scheme.",
    ),
    r(
        "android.signing-certificate",
        "签名证书",
        "Signing certificate",
        "签名证书（用于 {schemes}）：主体 {subject}；签发者 {issuer}；序列号 {serial}；有效期 {not_before} 至 {not_after}；密钥 {key}；证书签名算法 {signature_algorithm}；SHA-256 指纹 {sha256}；SHA-1 指纹 {sha1}。Android 不校验证书链和有效期，只认证书本身；主体名称由签名者自行填写，不能证明身份。",
        "Signing certificate (used by {schemes}): subject {subject}; issuer {issuer}; serial {serial}; valid {not_before} to {not_after}; key {key}; certificate signature algorithm {signature_algorithm}; SHA-256 fingerprint {sha256}; SHA-1 fingerprint {sha1}. Android checks neither the chain nor the validity period, only the certificate itself; the subject name is whatever the signer typed and proves no identity.",
    ),
    r(
        "android.debug-certificate",
        "使用调试证书签名",
        "Signed with a debug certificate",
        "签名证书是开发工具自动生成的调试证书（{subject}）。调试证书只用于开发阶段，应用商店不接受；用它签名的包通常是调试版或未经正式发布流程。",
        "The signing certificate is a debug certificate generated by the development tools ({subject}). Debug certificates are for development only and app stores reject them; a package signed with one is usually a debug build or was never released properly.",
    ),
    r(
        "android.aosp-test-key",
        "使用公开的 AOSP 测试密钥签名",
        "Signed with a public AOSP test key",
        "签名证书是 Android 开源项目中公开的测试密钥“{key}”（SHA-256 {sha256}）。它的私钥任何人都能下载，因此任何人都能签出同样签名的包，这个签名不能证明来源。",
        "The signing certificate is the public test key \"{key}\" of the Android Open Source Project (SHA-256 {sha256}). Its private key can be downloaded by anyone, so anyone can produce a package with this signature; it proves nothing about the origin.",
    ),
    r(
        "android.weak-signing-key",
        "签名密钥过短",
        "Weak signing key",
        "签名密钥是 {key}，长度低于当前建议的最低强度（RSA/DSA 2048 位）。",
        "The signing key is {key}, shorter than the strength recommended today (2048 bits for RSA/DSA).",
    ),
    r(
        "android.weak-certificate-digest",
        "证书使用过时的摘要算法",
        "Certificate uses an outdated digest",
        "签名证书自身的签名算法是 {algorithm}，其中的摘要算法已不安全。Android 不校验 APK 签名证书的自签名，因此实际影响有限。",
        "The certificate's own signature algorithm is {algorithm}, whose digest is no longer considered secure. Android does not check the self-signature of APK signing certificates, so the practical impact is limited.",
    ),
    r(
        "android.key-rotation",
        "签名密钥轮换记录",
        "Signing key rotation",
        "{scheme} 签名带有密钥轮换记录，共 {count} 个证书：{chain}。最后一个是当前签名证书，之前的是曾用证书。",
        "The {scheme} signature carries a key rotation history of {count} certificates: {chain}. The last is the current signing certificate; the earlier ones were used before.",
    ),
    r(
        "android.signing-block-extras",
        "签名块中的其他数据",
        "Other data in the signing block",
        "APK 签名块中除签名外还有 {count} 项数据：{blocks}。",
        "Besides signatures, the APK Signing Block holds {count} other entries: {blocks}.",
    ),
    r(
        "android.v4-signature-file",
        "存在 v4 签名文件",
        "v4 signature file present",
        "APK 旁有 v4 签名文件 {file}（用于增量安装）。v4 签名只做了识别，没有验证。",
        "A v4 signature file, {file}, sits beside the APK (used for incremental installation). It is detected, not verified.",
    ),
    r(
        "android.source-stamp-certificate",
        "来源戳证书",
        "Source stamp certificate",
        "包内记录了来源戳证书的 SHA-256：{sha256}。来源戳由分发渠道（如 Google Play）添加，用于标明包的分发来源。",
        "The package records the SHA-256 of a source stamp certificate: {sha256}. A source stamp is added by the distributor (such as Google Play) to mark where the package came from.",
    ),
    // ---- Structure and anomalies ----
    r(
        "android.zip-duplicate-entries",
        "压缩包内有重名文件",
        "Duplicate entry names in the archive",
        "压缩包的中央目录里有 {count} 个文件名出现多次：{names}。不同的解析器会取不同的那一份，这是让安全工具与系统看到不同内容的常见手法。",
        "{count} names appear more than once in the archive's central directory: {names}. Different parsers pick different copies, a known way to show security tools something other than what the system runs.",
    ),
    r(
        "android.zip-header-mismatch",
        "本地文件头与中央目录不一致",
        "Local headers disagree with the central directory",
        "{count} 个文件的本地文件头与中央目录记录不一致：{entries}。Android 以中央目录为准，另一些工具以本地文件头为准。",
        "The local headers of {count} entries disagree with the central directory: {entries}. Android goes by the central directory; some tools go by the local headers.",
    ),
    r(
        "android.zip-prefix-data",
        "压缩包开头有额外数据",
        "Data before the first archive entry",
        "第一个文件之前有 {bytes} 字节不属于任何文件的数据。",
        "{bytes} bytes that belong to no entry precede the first file of the archive.",
    ),
    r(
        "android.janus",
        "文件开头是 DEX（Janus 手法）",
        "File starts with a DEX (Janus technique)",
        "这个文件既是合法的 ZIP，开头的 {bytes} 字节又是一个 DEX 文件。在 Android 5.0–8.0 上，只有 v1 签名的此类文件可在不破坏签名的情况下运行被植入的代码（CVE-2017-13156）。",
        "The file is a valid ZIP whose first {bytes} bytes are also a DEX file. On Android 5.0–8.0, a v1-only signed file built this way runs the planted code without breaking the signature (CVE-2017-13156).",
    ),
    r(
        "android.zip-trailing-data",
        "压缩包末尾有额外数据",
        "Data after the end of the archive",
        "ZIP 结束记录之后还有 {bytes} 字节数据。Android 的 v2 及以上签名方案不接受这样的文件。",
        "{bytes} bytes follow the ZIP end record. Android's signature schemes v2 and later do not accept such a file.",
    ),
    r(
        "android.zip-odd-entries",
        "压缩包内有异常条目",
        "Unusual archive entries",
        "{count} 个条目带有加密标志或使用了存储/Deflate 以外的压缩方式：{entries}。APK 中不应出现这些，部分恶意软件借此干扰分析工具。",
        "{count} entries carry the encryption flag or a compression method other than stored/deflate: {entries}. Neither belongs in an APK; some malware uses them to break analysis tools.",
    ),
    r(
        "android.zip-count-mismatch",
        "压缩包条目数不一致",
        "Archive entry count mismatch",
        "结束记录声明有 {declared} 个条目，中央目录实际读到 {found} 个。",
        "The end record declares {declared} entries; {found} were read from the central directory.",
    ),
    r(
        "android.manifest-anomalies",
        "清单文件结构异常",
        "Manifest structure is unusual",
        "AndroidManifest.xml 的二进制结构有 {count} 处与正常构建工具的输出不符：{anomalies}。常见于被二次打包、加固或刻意对抗分析工具的应用。清单内容仍按系统的读取方式解出。",
        "The binary structure of AndroidManifest.xml differs in {count} ways from what the standard build tools write: {anomalies}. This is typical of repackaged, protected or deliberately tool-resistant apps. The content was still decoded the way the system reads it.",
    ),
    r(
        "android.resources-anomalies",
        "资源表结构异常",
        "Resource table structure is unusual",
        "resources.arsc 有 {count} 处结构异常：{anomalies}。",
        "resources.arsc has {count} structural anomalies: {anomalies}.",
    ),
    r(
        "android.tools-leftovers",
        "清单中残留 tools: 属性",
        "tools: attributes left in the manifest",
        "编译后的清单中残留了 {count} 个仅供构建工具使用的 tools: 属性：{attributes}。系统会忽略它们，但这说明清单未经标准流程处理。",
        "{count} tools: attributes, meant for build tools only, remain in the compiled manifest: {attributes}. The system ignores them; they show the manifest did not go through the standard processing.",
    ),
    r(
        "android.implicit-export",
        "组件未声明 exported",
        "Components without an exported attribute",
        "{count} 个带 intent-filter 的组件没有声明 android:exported：{components}。在 Android 11 及更早版本上它们默认对外导出；应用目标为 {target}，目标 API 31 及以上时 Android 12+ 会拒绝安装这样的清单。",
        "{count} components with an intent filter do not declare android:exported: {components}. On Android 11 and older they are exported by default; the app targets {target}, and for targets of API 31 or higher Android 12+ refuses to install such a manifest.",
    ),
    r(
        "android.task-affinity",
        "界面的任务归属指向其他应用",
        "Activity task affinity points at another app",
        "{count} 个界面把 taskAffinity 设为不属于本应用的包名，且使用 singleTask/singleInstance 启动模式：{activities}。这是任务劫持（把自己的界面插入别的应用的任务栈）的典型配置，也可能是正当用途；这是按模式判断的结果。",
        "{count} activities set their taskAffinity to a package name that is not this app's, with a singleTask/singleInstance launch mode: {activities}. This is the usual setup for task hijacking (placing a screen in another app's task), though it has legitimate uses; this is a pattern match.",
    ),
    r(
        "android.abi-mismatch",
        "各 CPU 架构的原生库不一致",
        "Native libraries differ between ABIs",
        "各架构目录下的原生库集合不同：{gaps}。在缺库的架构上，加载该库时应用会崩溃。",
        "The sets of native libraries differ between ABI folders: {gaps}. On an ABI that lacks a library the app crashes when it loads it.",
    ),
    // ---- Capabilities ----
    r(
        "android.permission-dangerous",
        "申请危险权限",
        "Dangerous permission requested",
        "应用申请了危险权限 {permission}：{description_zh}。需要用户在运行时同意（限制：{limits}）。权限等级来自内置的 AOSP 权限表。",
        "The app requests the dangerous permission {permission}: {description_en}. The user must agree at run time (limits: {limits}). The level comes from the embedded AOSP permission table.",
    ),
    r(
        "android.permission-special",
        "申请特殊权限",
        "Special permission requested",
        "应用申请了特殊权限 {permission}：{description_zh}。需要用户在系统设置中手动开启（限制：{limits}）。权限等级来自内置的 AOSP 权限表。",
        "The app requests the special permission {permission}: {description_en}. The user must switch it on in system settings (limits: {limits}). The level comes from the embedded AOSP permission table.",
    ),
    r(
        "android.permissions-normal",
        "普通权限",
        "Normal permissions",
        "应用申请了 {count} 个普通权限（安装时自动授予，不询问用户）：{permissions}。各权限的说明见 android.permissions。",
        "The app requests {count} normal permissions (granted at install without asking): {permissions}. The android.permissions fact describes each.",
    ),
    r(
        "android.permissions-signature",
        "申请签名级/系统级权限",
        "Signature or system permissions requested",
        "应用申请了 {count} 个只授予平台签名或预装特权应用的权限：{permissions}。普通安装的应用得不到这些权限；出现它们说明应用是为系统预装设计的，或者在试探。",
        "The app requests {count} permissions that are granted only to platform-signed or preinstalled privileged apps: {permissions}. An app installed the normal way does not get them; they show the app is meant to be preinstalled, or is probing.",
    ),
    r(
        "android.permissions-other",
        "其他权限",
        "Other permissions",
        "应用申请了 {count} 个不在内置平台权限表中的权限（由本应用、其他应用或设备厂商定义）：{permissions}。",
        "The app requests {count} permissions that are not in the embedded platform table (defined by this app, by other apps or by device vendors): {permissions}.",
    ),
    r(
        "android.permissions-declared",
        "应用自定义的权限",
        "Permissions the app defines",
        "应用定义了 {count} 个权限：{permissions}。其中 {not_signature} 个的保护级别低于 signature，其他应用只要声明就能获得。",
        "The app defines {count} permissions: {permissions}. {not_signature} of them have a protection level below signature, so any other app gets them by asking.",
    ),
    r(
        "android.uses-features",
        "要求的硬件/软件特性",
        "Required device features",
        "应用要求设备具备 {count} 项特性：{features}（另有 {optional} 项声明为可选）。",
        "The app requires {count} device features: {features} ({optional} more are declared optional).",
    ),
    r(
        "android.queries",
        "可见的其他应用",
        "Other apps it can see",
        "清单的 queries 声明让应用能看到 {packages} 个指定的应用和匹配 {intents} 类 Intent 的应用，例如：{examples}。",
        "The manifest's queries element lets the app see {packages} named apps and the apps matching {intents} kinds of intent, for example: {examples}.",
    ),
    r(
        "android.components",
        "应用组件",
        "App components",
        "清单声明了 {activities} 个界面（Activity）、{services} 个服务、{receivers} 个广播接收器、{providers} 个内容提供程序，其中 {exported} 个对其他应用开放（exported）。",
        "The manifest declares {activities} activities, {services} services, {receivers} broadcast receivers and {providers} content providers; {exported} of them are open to other apps (exported).",
    ),
    r(
        "android.exported-activities",
        "对外开放且无权限保护的界面",
        "Exported activities without a protecting permission",
        "{count} 个界面（不含启动入口）可被其他应用直接打开，且没有 signature 级权限保护：{components}。导出状态按系统规则由清单推出；是否构成风险取决于这些界面如何处理外部传入的数据。",
        "{count} activities (launcher entries aside) can be started by any other app and are not protected by a signature-level permission: {components}. The exported state is derived from the manifest by the platform's rules; whether it is a risk depends on how these screens handle what they are sent.",
    ),
    r(
        "android.exported-services",
        "对外开放且无权限保护的服务",
        "Exported services without a protecting permission",
        "{count} 个服务可被其他应用启动或绑定，且没有 signature 级权限保护：{components}。导出状态按系统规则由清单推出。",
        "{count} services can be started or bound by any other app and are not protected by a signature-level permission: {components}. The exported state is derived from the manifest by the platform's rules.",
    ),
    r(
        "android.exported-receivers",
        "对外开放且无权限保护的广播接收器",
        "Exported receivers without a protecting permission",
        "{count} 个广播接收器可接收其他应用发来的广播，且没有 signature 级权限保护：{components}。导出状态按系统规则由清单推出。",
        "{count} broadcast receivers accept broadcasts from any other app and are not protected by a signature-level permission: {components}. The exported state is derived from the manifest by the platform's rules.",
    ),
    r(
        "android.exported-providers",
        "对外开放且无权限保护的内容提供程序",
        "Exported providers without a protecting permission",
        "{count} 个内容提供程序可被其他应用读写，且没有 signature 级权限保护：{components}。内容提供程序直接暴露数据，应确认其中没有敏感内容。",
        "{count} content providers can be read or written by any other app and are not protected by a signature-level permission: {components}. A provider exposes data directly; check that none of it is sensitive.",
    ),
    r(
        "android.provider-grant-uri",
        "内容提供程序可临时授权",
        "Provider grants URI permissions",
        "对外开放的内容提供程序 {provider}（authorities：{authorities}）允许临时授予其他应用访问其数据的权限（grantUriPermissions）。",
        "The exported content provider {provider} (authorities: {authorities}) may hand other apps temporary access to its data (grantUriPermissions).",
    ),
    r(
        "android.special-component",
        "声明了需用户授权的系统级服务",
        "Declares a system-bound service",
        "组件 {component} 是{what_zh}。声明本身不生效，需要用户在系统设置中开启。",
        "The component {component} is {what_en}. The declaration alone does nothing; the user must enable it in system settings.",
    ),
    r(
        "android.deep-links",
        "可唤起应用的链接",
        "Links that open the app",
        "应用登记了 {count} 种可唤起它的链接，例如：{links}。自定义协议：{custom_schemes}；声明了自动验证（App Links）的域名：{verified_hosts}。任何网页或应用都能通过这些链接向应用传入数据。",
        "The app registers {count} kinds of links that open it, for example: {links}. Custom schemes: {custom_schemes}; hosts with automatic verification (App Links): {verified_hosts}. Any web page or app can send data into the app through these links.",
    ),
    // ---- Hardening ----
    r(
        "android.debuggable",
        "应用可被调试",
        "App is debuggable",
        "清单设置了 android:debuggable=\"true\"。任何能连上设备的人都可以附加调试器、读取应用私有数据并执行任意代码；发布版本不应开启。",
        "The manifest sets android:debuggable=\"true\". Anyone who can connect to the device can attach a debugger, read the app's private data and run code in it; release builds must not enable this.",
    ),
    r(
        "android.test-only",
        "仅供测试的包",
        "Test-only package",
        "清单设置了 android:testOnly=\"true\"。这样的包只能通过 adb 的测试选项安装，说明它不是发布版本。",
        "The manifest sets android:testOnly=\"true\". Such a package installs only through adb's test option; it is not a release build.",
    ),
    r(
        "android.allow-backup",
        "允许备份应用数据",
        "App data may be backed up",
        "android:allowBackup {how_zh}，应用数据可通过系统备份（以及旧版本上的 adb backup）导出。备份规则：{rules}。",
        "android:allowBackup {how_en}, so the app's data can leave the device through system backup (and adb backup on older versions). Backup rules: {rules}.",
    ),
    r(
        "android.cleartext-allowed",
        "允许明文网络流量",
        "Cleartext network traffic allowed",
        "应用被允许使用未加密的 HTTP 等明文连接：{how_zh}。明文流量可被同一网络中的人查看和篡改。",
        "The app is allowed to use unencrypted connections such as plain HTTP: {how_en}. Cleartext traffic can be read and altered by anyone on the network path.",
    ),
    r(
        "android.cleartext-domains",
        "对部分域名允许明文流量",
        "Cleartext allowed for some domains",
        "网络安全配置对 {count} 个域名允许明文流量：{domains}。",
        "The network security configuration allows cleartext traffic for {count} domains: {domains}.",
    ),
    r(
        "android.trust-user-cas",
        "信任用户安装的 CA 证书",
        "User-installed CAs are trusted",
        "网络安全配置让应用信任用户自行安装的 CA 证书（范围：{scope}），而且不限于调试版本。在装有此类证书的设备上，HTTPS 流量可被中间人解密。",
        "The network security configuration makes the app trust CA certificates the user installed (scope: {scope}), and not only in debug builds. On a device with such a certificate, HTTPS traffic can be intercepted.",
    ),
    r(
        "android.custom-trust-anchors",
        "使用自带的 CA 证书",
        "Bundled trust anchors",
        "网络安全配置的 base-config 使用应用自带的证书作为信任锚：{anchors}。",
        "The base-config of the network security configuration uses certificates shipped with the app as trust anchors: {anchors}.",
    ),
    r(
        "android.certificate-pinning",
        "证书固定",
        "Certificate pinning",
        "网络安全配置为 {count} 个域名固定了证书公钥：{domains}（过期日期：{expiration}）。",
        "The network security configuration pins certificate keys for {count} domains: {domains} (expiration: {expiration}).",
    ),
    r(
        "android.debug-overrides",
        "调试版本的网络覆盖配置",
        "Debug overrides in the network configuration",
        "网络安全配置含有 debug-overrides（是否信任用户 CA：{user_cas}）。它只在 debuggable 版本中生效。",
        "The network security configuration has debug-overrides (trusts user CAs: {user_cas}). They apply only to debuggable builds.",
    ),
    r(
        "android.extract-native-libs",
        "原生库的安装方式",
        "How native libraries are installed",
        "android:extractNativeLibs={value}：为 false 时原生库不解压，直接从 APK 中加载（要求库在 APK 内不压缩并按页对齐）。",
        "android:extractNativeLibs={value}: when false, native libraries are loaded straight from the APK instead of being extracted (they must be stored uncompressed and page-aligned).",
    ),
    r(
        "android.legacy-external-storage",
        "使用旧版外部存储模式",
        "Legacy external storage requested",
        "清单设置了 requestLegacyExternalStorage=\"true\"，在 Android 10 上绕开分区存储，可访问共享存储上的全部文件。",
        "The manifest sets requestLegacyExternalStorage=\"true\", which opts out of scoped storage on Android 10 and gives access to all files on shared storage.",
    ),
    r(
        "android.min-sdk-old",
        "支持已停止安全更新的旧系统",
        "Runs on Android versions without security updates",
        "最低支持版本是 {min}。这些旧版本缺少后来加入的平台保护（如运行时权限），并且早已不再获得安全更新。",
        "The minimum supported version is {min}. Such old versions lack platform protections added later (runtime permissions, for one) and stopped receiving security updates long ago.",
    ),
    r(
        "android.target-sdk-old",
        "目标 SDK 版本偏旧",
        "Old target SDK",
        "目标版本是 {target}。系统会为低目标版本的应用保留旧行为，较新版本才启用的安全与隐私限制对它不生效。",
        "The target is {target}. The system keeps old behaviour for apps with a low target, so security and privacy restrictions introduced for newer targets do not apply.",
    ),
    r(
        "android.packer",
        "疑似使用加固/加壳",
        "Possible packer or protector",
        "包内出现了 {name}（{vendor}）的特征文件或入口类。加固后的应用真正的代码在运行时才解密加载，静态分析看到的只是壳。这是按文件名和类名匹配的结果，可能误报。",
        "Files or an entry class characteristic of {name} ({vendor}) are present. A packed app decrypts and loads its real code at run time, so static analysis sees only the shell. This is a match on file and class names and may be wrong.",
    ),
    r(
        "android.native-16k-pages",
        "原生库未按 16 KB 页对齐",
        "Native libraries not aligned for 16 KB pages",
        "{total} 个 64 位原生库中有 {count} 个的可加载段对齐小于 16 KB：{libraries}。它们无法在使用 16 KB 内存页的设备上加载。",
        "{count} of {total} 64-bit native libraries have loadable segments aligned to less than 16 KB: {libraries}. They cannot be loaded on devices with a 16 KB page size.",
    ),
    r(
        "android.native-text-relocations",
        "原生库含代码段重定位",
        "Native libraries with text relocations",
        "{count} 个原生库含代码段重定位（TEXTREL）：{libraries}。加载时代码段必须可写，削弱了内存保护；Android 6 起 64 位及目标 API 23+ 的应用不允许这样的库。",
        "{count} native libraries have text relocations (TEXTREL): {libraries}. Their code must be writable while loading, which weakens memory protection; since Android 6 such libraries are refused for 64-bit code and for apps targeting API 23+.",
    ),
    r(
        "android.native-rwx-segment",
        "原生库含可写可执行段",
        "Native libraries with writable and executable segments",
        "{count} 个原生库有同时可写、可执行的段：{libraries}。这使注入代码更容易，也常见于加壳的库。",
        "{count} native libraries have a segment that is both writable and executable: {libraries}. This makes code injection easier and is common in packed libraries.",
    ),
    r(
        "android.native-executable-stack",
        "原生库要求可执行栈",
        "Native libraries with an executable stack",
        "{count} 个原生库把栈标记为可执行：{libraries}。",
        "{count} native libraries mark the stack as executable: {libraries}.",
    ),
    // ---- Composition ----
    r(
        "android.framework",
        "应用框架",
        "App framework",
        "应用使用了 {name}（{vendor}）；{detail}。依据是包内的类包名、原生库或特征文件。",
        "The app is built with {name} ({vendor}); {detail}. This follows from class packages, native libraries or marker files in the package.",
    ),
    r(
        "android.sdk",
        "第三方 SDK",
        "Third-party SDK",
        "包内含有 {name}（{vendor}，类别：{category}）。依据是包内存在该 SDK 的类包名或原生库，不代表其功能一定被启用。",
        "The package contains {name} ({vendor}, category: {category}). This follows from the SDK's class packages or native libraries being present; it does not show the SDK is active.",
    ),
    r(
        "android.libraries",
        "常用开源库",
        "Common libraries",
        "包内含有 {count} 个常见的通用库：{libraries}。",
        "The package contains {count} well-known general-purpose libraries: {libraries}.",
    ),
    r(
        "android.sdk-identifiers",
        "SDK 的应用标识",
        "SDK application identifiers",
        "清单的 meta-data 中有 {count} 个第三方服务的应用标识：{values}。这些是标识而非密钥。",
        "The manifest's meta-data holds {count} application identifiers of third-party services: {values}. These are identifiers, not keys.",
    ),
    r(
        "android.native-libs",
        "原生库",
        "Native libraries",
        "包内有 {count} 个原生库，按 CPU 架构：{abis}。",
        "The package holds {count} native libraries, by ABI: {abis}.",
    ),
    r(
        "android.js-bundles",
        "JavaScript 代码包",
        "JavaScript bundles",
        "assets 中有 {count} 个 JavaScript 文件或代码包，最大的是：{largest}。",
        "The assets hold {count} JavaScript files or bundles; the largest: {largest}.",
    ),
    r(
        "android.build-info",
        "构建信息",
        "Build information",
        "构建工具留下的信息：{details}。",
        "Information left by the build tools: {details}.",
    ),
    // ---- Network / Secrets ----
    r(
        "android.firebase-config",
        "Firebase / Google 服务配置",
        "Firebase / Google services configuration",
        "资源中有 google-services 插件写入的项目配置：{values}。",
        "The resources hold the project configuration written by the google-services plugin: {values}.",
    ),
    r(
        "android.google-api-key",
        "资源中的 Google API 密钥",
        "Google API key in resources",
        "字符串资源 {name} 是一个 Google API 密钥（已脱敏：{redacted}）。这类密钥按设计随应用分发，但应在云端控制台限制其可用的 API 和应用签名，否则可被他人滥用。是否已限制无法从包内判断。",
        "The string resource {name} is a Google API key (redacted: {redacted}). Such keys ship with the app by design, but must be restricted in the cloud console to specific APIs and app signatures or others can abuse them. Whether it is restricted cannot be told from the package.",
    ),
    r(
        "android.metadata-key",
        "清单 meta-data 中的密钥",
        "Key in manifest meta-data",
        "清单 meta-data {name} 的值形似 {what}（已脱敏：{redacted}）。这是按名称匹配的结果；这类密钥是否敏感取决于服务方的限制方式。",
        "The value of manifest meta-data {name} looks like a {what} (redacted: {redacted}). This is a match on the name; how sensitive such a key is depends on how the service restricts it.",
    ),
    // ---- Privacy ----
    r(
        "android.tracker-sdk",
        "数据收集类 SDK",
        "Data-collecting SDK",
        "包内含有 {name}（{vendor}，类别：{category}）。这类 SDK 的用途是收集使用数据、设备信息或投放广告。依据是包内存在其类包名或原生库，不代表一定被启用。",
        "The package contains {name} ({vendor}, category: {category}). SDKs of this kind exist to collect usage data or device information, or to serve ads. This follows from class packages or native libraries being present; it does not show the SDK is active.",
    ),
    r(
        "android.api-device-identifiers",
        "代码引用了读取设备标识的接口",
        "Code refers to device identifier APIs",
        "DEX 的方法引用表中有读取设备或 SIM 卡标识的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that read device or SIM identifiers: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-location",
        "代码引用了定位接口",
        "Code refers to location APIs",
        "DEX 的方法引用表中有获取位置的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that obtain the location: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-sms-send",
        "代码引用了发送短信的接口",
        "Code refers to SMS sending APIs",
        "DEX 的方法引用表中有发送短信的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that send text messages: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-audio-record",
        "代码引用了录音接口",
        "Code refers to audio recording APIs",
        "DEX 的方法引用表中有录音接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name audio recording APIs: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-camera",
        "代码引用了相机接口",
        "Code refers to camera APIs",
        "DEX 的方法引用表中有打开相机的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that open the camera: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-installed-apps",
        "代码引用了列举已安装应用的接口",
        "Code refers to APIs that list installed apps",
        "DEX 的方法引用表中有列举设备上已安装应用的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that list the apps installed on the device: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-clipboard-read",
        "代码引用了读取剪贴板的接口",
        "Code refers to clipboard reading APIs",
        "DEX 的方法引用表中有读取剪贴板的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that read the clipboard: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-accounts",
        "代码引用了读取帐号列表的接口",
        "Code refers to account listing APIs",
        "DEX 的方法引用表中有读取设备帐号列表的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that list the accounts on the device: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-screen-capture",
        "代码引用了屏幕捕获接口",
        "Code refers to screen capture APIs",
        "DEX 的方法引用表中有发起屏幕捕获的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that start screen capture: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    // ---- Code ----
    r(
        "android.dex-summary",
        "DEX 代码概况",
        "DEX code overview",
        "包内有 {files} 个 DEX 文件（格式版本 {versions}），共定义 {classes} 个类，引用 {methods} 个方法、{fields} 个字段、{strings} 个字符串，其中 {native_methods} 个方法由原生代码实现。",
        "The package has {files} DEX files (format version {versions}) defining {classes} classes and referring to {methods} methods, {fields} fields and {strings} strings; {native_methods} methods are implemented in native code.",
    ),
    r(
        "android.dex-packages",
        "代码的包结构",
        "Code packages",
        "类分布在 {count} 个顶层包中，类最多的是：{packages}。",
        "The classes fall into {count} top-level packages; the largest: {packages}.",
    ),
    r(
        "android.obfuscated-names",
        "类名疑似经过混淆",
        "Class names look obfuscated",
        "{classes} 个类中约 {percent}% 的类名只有一两个字符，符合 R8/ProGuard 等工具缩短名称后的特征。这是按名称长度的统计判断。",
        "About {percent}% of the {classes} classes have names of one or two characters, the mark of name shortening by R8/ProGuard and similar tools. This is a statistic on name length.",
    ),
    r(
        "android.code-dynamic-loading",
        "代码引用了动态加载代码的接口",
        "Code refers to dynamic code loading APIs",
        "DEX 的方法引用表中有运行时加载代码的接口：{apis}。应用可以借此运行包内清单之外、甚至下载得到的代码。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that load code at run time: {apis}. With them an app can run code that is not in its visible DEX files, even downloaded code. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.code-command-exec",
        "代码引用了执行系统命令的接口",
        "Code refers to command execution APIs",
        "DEX 的方法引用表中有执行系统命令的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that run system commands: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.code-native-load",
        "代码引用了加载原生库的接口",
        "Code refers to native library loading APIs",
        "DEX 的方法引用表中有加载原生库的接口：{apis}。",
        "The DEX method reference tables name APIs that load native libraries: {apis}.",
    ),
    r(
        "android.code-reflection",
        "代码引用了反射接口",
        "Code refers to reflection APIs",
        "DEX 的方法引用表中有反射接口：{apis}。反射很常见，但也让静态分析看不到实际调用的目标。",
        "The DEX method reference tables name reflection APIs: {apis}. Reflection is common, and it hides the actual call targets from static analysis.",
    ),
    r(
        "android.code-webview-js-interface",
        "代码引用了 WebView 的 JavaScript 接口",
        "Code refers to the WebView JavaScript interface",
        "DEX 的方法引用表中有 {apis}。通过它，网页里的 JavaScript 可以调用应用的 Java 代码；若 WebView 加载了不可信的页面，这些接口就暴露给了对方。这表示代码中引用了它，不表示运行时一定会调用。",
        "The DEX method reference tables name {apis}. Through it, JavaScript in a web page can call the app's Java code; if the WebView loads untrusted pages, those methods are exposed to them. The code refers to it; that does not show it is called at run time.",
    ),
    r(
        "android.code-webview-js-enabled",
        "代码引用了开启 WebView JavaScript 的接口",
        "Code refers to enabling JavaScript in WebView",
        "DEX 的方法引用表中有 {apis}。",
        "The DEX method reference tables name {apis}.",
    ),
    r(
        "android.code-webview-file-access",
        "代码引用了放宽 WebView 文件访问的接口",
        "Code refers to WebView file access settings",
        "DEX 的方法引用表中有 {apis}。开启后，file:// 页面中的脚本可以读取本地文件或跨源访问。这表示代码中引用了它们，不表示运行时一定会调用，也不表示传入的值为 true。",
        "The DEX method reference tables name {apis}. When enabled, scripts in file:// pages can read local files or cross origins. The code refers to them; that does not show they are called at run time, nor that they are called with true.",
    ),
    r(
        "android.code-webview-debugging",
        "代码引用了 WebView 远程调试开关",
        "Code refers to the WebView debugging switch",
        "DEX 的方法引用表中有 {apis}。",
        "The DEX method reference tables name {apis}.",
    ),
    r(
        "android.code-hostname-verifier-set",
        "代码引用了替换主机名校验的接口",
        "Code refers to replacing the hostname verifier",
        "DEX 的方法引用表中有 {apis}。替换主机名校验器是 HTTPS 校验被削弱的常见位置，需要查看传入的实现。",
        "The DEX method reference tables name {apis}. Replacing the hostname verifier is a common place where HTTPS checks get weakened; the implementation passed in needs a look.",
    ),
    r(
        "android.api-accessibility-actions",
        "代码引用了无障碍操作接口",
        "Code refers to accessibility action APIs",
        "DEX 的方法引用表中有通过无障碍服务代替用户点击或操作的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that click or act for the user through an accessibility service: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.api-package-install",
        "代码引用了安装应用的接口",
        "Code refers to package installation APIs",
        "DEX 的方法引用表中有安装应用的接口：{apis}。这表示代码中引用了它们，不表示运行时一定会调用。",
        "The DEX method reference tables name APIs that install apps: {apis}. The code refers to them; that does not show they are called at run time.",
    ),
    r(
        "android.code-custom-trust-manager",
        "自定义的证书信任管理器",
        "Custom trust managers",
        "{count} 个类实现了 X509TrustManager：{classes}。自定义实现可能加强校验（如证书固定），也可能接受任意证书；不反编译无法区分，许多网络库也自带实现。",
        "{count} classes implement X509TrustManager: {classes}. A custom implementation may tighten checks (pinning) or accept any certificate; that cannot be told without decompiling, and many network libraries ship one.",
    ),
    r(
        "android.code-custom-hostname-verifier",
        "自定义的主机名校验器",
        "Custom hostname verifiers",
        "{count} 个类实现了 HostnameVerifier：{classes}。自定义实现可能接受任意主机名；不反编译无法确认，许多网络库也自带实现。",
        "{count} classes implement HostnameVerifier: {classes}. A custom implementation may accept any host name; that cannot be confirmed without decompiling, and many network libraries ship one.",
    ),
    r(
        "android.code-ssl-error-handler",
        "自行处理 WebView 证书错误",
        "WebView SSL errors handled by the app",
        "{count} 个类定义了 onReceivedSslError：{classes}。如果其中调用了 proceed()，WebView 会忽略证书错误；不反编译无法确认。",
        "{count} classes define onReceivedSslError: {classes}. If one of them calls proceed(), the WebView ignores certificate errors; that cannot be confirmed without decompiling.",
    ),
    r(
        "android.code-cipher-strings",
        "代码中的加密算法名称",
        "Cipher names in the code",
        "代码引用了 Cipher.getInstance，字符串常量中有 {count} 个形似加密算法的名称：{ciphers}。字符串与调用之间的对应关系没有核实。",
        "The code refers to Cipher.getInstance, and {count} string constants are shaped like cipher transformations: {ciphers}. Which string goes to which call is not established.",
    ),
    r(
        "android.code-weak-cipher",
        "疑似使用弱加密算法或模式",
        "Possibly weak ciphers or modes",
        "字符串常量中有弱加密算法或模式的名称：{ciphers}（DES、RC4 等已不安全；ECB 模式会泄露数据的重复规律；单写“AES”时默认采用 ECB）。这是按字符串匹配的结果，可能来自第三方库或未被使用。",
        "String constants name weak ciphers or modes: {ciphers} (DES and RC4 are broken; ECB reveals repetition in the data; a bare \"AES\" defaults to ECB). This is a string match; they may come from a library or be unused.",
    ),
    r(
        "android.code-weak-digest",
        "疑似使用过时的摘要算法",
        "Possibly outdated digests",
        "代码引用了 MessageDigest.getInstance，字符串常量中有过时摘要算法的名称：{digests}。MD5 和 SHA-1 不应再用于安全用途，用于校验和等场景则无妨；这是按字符串匹配的结果。",
        "The code refers to MessageDigest.getInstance, and string constants name outdated digests: {digests}. MD5 and SHA-1 must not be used for security purposes, though they are fine as checksums; this is a string match.",
    ),
    r(
        "android.embedded-code",
        "资源中夹带可执行代码",
        "Executable code shipped as data",
        "assets 或 res/raw 中有 {count} 个代码文件：{files}。它们不在系统默认加载的位置，只能由应用在运行时自行加载。",
        "The assets or res/raw hold {count} code files: {files}. They are not where the system loads code from, so only the app itself can load them at run time.",
    ),
    // ---- Limitations ----
    r(
        "android.manifest-unreadable",
        "清单无法解析",
        "Manifest could not be decoded",
        "AndroidManifest.xml 无法解析，这个包的清单、权限和组件没有分析。",
        "AndroidManifest.xml could not be decoded; the package's manifest, permissions and components were not analyzed.",
    ),
    r(
        "android.manifest-truncated",
        "清单只解析了一部分",
        "Manifest decoded in part",
        "AndroidManifest.xml 在解析到末尾前就中断了（文件损坏或超出限额），以上结论只覆盖已读出的部分。",
        "Decoding of AndroidManifest.xml stopped before its end (damaged file or a limit reached); the findings cover the part that was read.",
    ),
    r(
        "android.resources-unreadable",
        "资源表无法解析",
        "Resource table could not be decoded",
        "资源表无法解析，清单中引用资源的值（如应用名称）没有解出。",
        "The resource table could not be decoded; values the manifest takes from resources (the app name, for one) were not resolved.",
    ),
    r(
        "android.resource-xml-unreadable",
        "资源 XML 无法解析",
        "Resource XML could not be decoded",
        "清单引用的这个 XML 资源无法解析，其中的设置没有分析。",
        "This XML resource, which the manifest refers to, could not be decoded; its settings were not analyzed.",
    ),
    r(
        "android.reference-unresolved",
        "资源引用未能解出",
        "Resource reference not resolved",
        "清单中的一个资源引用在资源表里找不到对应的值。",
        "A resource reference in the manifest has no value in the resource table.",
    ),
    r(
        "android.signature-not-checked",
        "签名未能验证",
        "Signature not verified",
        "这里的签名没有得到验证，原因见详情。“未验证”不等于“无效”。",
        "The signature here was not verified; the detail says why. Not verified does not mean invalid.",
    ),
    r(
        "android.dex-unreadable",
        "DEX 文件未能完整读取",
        "DEX file not fully read",
        "这个 DEX 文件的结构有问题或超出限额，代码相关的结论可能不完整。",
        "This DEX file is malformed or beyond a limit; the findings about code may be incomplete.",
    ),
    r(
        "android.packed-code-hidden",
        "加固后的代码不可见",
        "Packed code is not visible",
        "应用疑似经过加固，真正的 DEX 代码在运行时才解密。本报告中关于代码、SDK 和接口引用的结论只反映壳的内容。",
        "The app appears to be packed, and its real DEX code is decrypted only at run time. What this report says about code, SDKs and API references describes the shell only.",
    ),
    r(
        "android.bundle-modules-not-analyzed",
        "App Bundle 的其他模块未深入分析",
        "Other bundle modules not analyzed in depth",
        "只对 base 模块做了完整分析，其余功能模块的代码和资源没有逐一分析。",
        "Only the base module was analyzed in full; the code and resources of the other feature modules were not.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_texts_complete() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        let count = ids.len();
        ids.dedup();
        assert_eq!(count, ids.len());
        for rule in RULES {
            assert!(rule.id.starts_with("android."));
            assert!(
                !rule.title_zh.is_empty() && !rule.title_en.is_empty() && !rule.text_zh.is_empty() && !rule.text_en.is_empty(),
                "{}",
                rule.id
            );
        }
    }

    /// Every rule id and limitation code used in the sources has its text, and every rule is used.
    #[test]
    fn sources_and_rules_agree() {
        let sources =
            [include_str!("lib.rs"), include_str!("emit_manifest.rs"), include_str!("emit_signing.rs"), include_str!("emit_code.rs")];
        let mut used = std::collections::BTreeSet::new();
        for source in sources {
            let mut rest = source;
            while let Some(at) = rest.find("\"android.") {
                let tail = &rest[at + 1..];
                let end = tail.find('"').unwrap_or(tail.len());
                let id = &tail[..end];
                // Fact keys use underscores or a single word and are listed in FACT_KEYS.
                if id[8..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !crate::tests::FACT_KEYS.contains(&id)
                {
                    used.insert(id.to_string());
                }
                rest = &tail[end..];
            }
        }
        let defined: std::collections::BTreeSet<String> = RULES.iter().map(|r| r.id.to_string()).collect();
        let missing: Vec<&String> = used.difference(&defined).collect();
        let unused: Vec<&String> = defined.difference(&used).collect();
        assert!(missing.is_empty(), "used but not defined: {missing:?}");
        assert!(unused.is_empty(), "defined but not used: {unused:?}");
    }

    /// Placeholders in the two languages name the same params, apart from the `_zh`/`_en` pairs.
    #[test]
    fn placeholders_match_between_languages() {
        fn names(text: &str) -> std::collections::BTreeSet<String> {
            let mut out = std::collections::BTreeSet::new();
            let mut rest = text;
            while let Some(open) = rest.find('{') {
                let tail = &rest[open + 1..];
                let Some(close) = tail.find('}') else { break };
                out.insert(tail[..close].trim_end_matches("_zh").trim_end_matches("_en").to_string());
                rest = &tail[close..];
            }
            out
        }
        for rule in RULES {
            assert_eq!(names(rule.text_zh), names(rule.text_en), "{}", rule.id);
        }
    }
}
