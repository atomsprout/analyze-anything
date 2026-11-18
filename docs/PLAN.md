# Analyze Anything — 调研与规划

> 状态：规划稿 v0.1（2026-11-18）
> 一句话定位：**输入电脑上的任意产物（文件 / 文件夹 / 压缩包 / 安装包 / 应用包），输出一份可靠、可溯源、多维度的分析报告（PDF / HTML / Markdown / TXT）。** 使用 Rust 开发，单一静态二进制，离线可用。

---

## 1. 调研结论

### 1.1 参考项目

| 项目 | 它是什么 | 值得借鉴 | 与我们的差异 |
|---|---|---|---|
| **REA**（Reverse Engineer Anything，`morluto/rea`，MIT，Node.js） | 给 AI Agent 用的 MCP 服务器 + CLI。把 Ghidra / IDA / Hopper / JADX / Apktool / Binwalk 等包装成工具，让 Agent 交互式地反编译、追踪、验证假设 | ① 每个结论都带 **证据 + 局限 + 未知项**；② 结果在服务端做 schema 校验；③ 覆盖面的"目标清单"（ELF/PE/Mach-O、.NET、APK、Flutter、Electron、PyInstaller、IL2CPP、Godot、WASM…）可作为我们的格式路线图 | REA 是 **交互式、Agent 驱动、依赖外部重型工具**，没有固定的"报告"产物；我们是 **确定性、一次跑完、零外部依赖、以报告为交付物** |
| **CLI-Anything**（`HKUDS/CLI-Anything`，Apache-2.0） | 用 7 阶段流水线把任意软件包装成 Agent 可调用的 CLI | ① 固定阶段的流水线思路；② "Agent-native"：全部命令支持 `--json`、附带 SKILL.md | 目标不同（生成 CLI 而非分析产物）。我们借鉴其"对 Agent 友好"的接口设计 |
| **MobSF**（Python） | 移动应用静态/动态安全分析，输出 PDF/JSON 报告 | 报告章节是事实标准：权限、组件导出、签名、二进制加固（PIE/Canary/NX/RELRO）、硬编码密钥、URL/域名、Tracker（Exodus 库）、APKiD 加壳识别 | 只覆盖移动端，部署重（Docker + JDK），无桌面格式 |
| **reknife / rbat / binsec**（Rust） | 基于 goblin + yara-x + iced-x86 的二进制体检工具 | 证明了纯 Rust 技术栈可行 | 只看单个可执行文件，不处理"包"，无完整报告 |
| **binwalk v3**（Rust）/ unblob | 递归识别并提取嵌入数据 | 递归解包、熵分析 | 面向固件，不解读语义 |
| **Detect-It-Easy / APKiD / capa / FLOSS** | 编译器/加壳识别、能力识别、混淆字符串还原 | 规则库与识别思路 | 各管一段，无统一报告 |

> 说明：未检索到名为 "Craft Anything" 的项目，按最接近的 **CLI-Anything** 处理；如果你指的是别的仓库，把链接给我，我再补充对比。

**空白点（我们的机会）**：目前没有一个工具同时满足 ——
① 纯 Rust 单文件、离线、跨平台；② 同时覆盖 IPA / APK / Windows 安装包 / 已安装程序目录 / .app / DMG；③ 递归拆包后做**跨文件关联**；④ 以**证据链可溯源的报告**为最终交付物。

### 1.2 Rust 生态可用性（版本为 2026-11-18 crates.io 实测）

| 能力 | 首选 crate | 许可证 | 备注 |
|---|---|---|---|
| ELF / PE / Mach-O 解析 | `goblin` 0.10.7（辅以 `object` 0.41） | MIT | 成熟，fat binary 支持 |
| Apple 代码签名 / entitlements | `apple-codesign` 0.29 | MPL-2.0 | 依赖较重，放在 feature 后面；或自行解析 SuperBlob |
| plist / provisioning profile | `plist` 1.10 + `cms` + `x509-parser` 0.18 | MIT / Apache | mobileprovision 是 CMS 包裹的 plist |
| DMG | `apple-dmg` 0.5 / `dmgwiz` 1.1 + `hfsplus` 0.4 + `apfs` 0.4 | MIT | **风险点**：APFS、加密 DMG 覆盖度需 spike 验证 |
| pkg（xar / bom） | `apple-xar` 0.20、`apple-bom` 0.3 | MPL / MIT | |
| APK 总体（AXML / ARSC / 签名块） | `apk-info` 1.1.1 | Apache-2.0 | 自称 malware-robust；v3/v4 签名校验需自己补 |
| DEX | `dex` 0.5 / `rusty-dex` 0.2 | MIT / Apache | 两者都偏老，可能需要自写轻量解析器（格式稳定、规范公开） |
| NSIS 安装包 | `nsis` 0.6.1 | Apache-2.0 | 面向恶意软件分析，可解析脚本 + 提取文件 |
| Inno Setup | `innospect` 0.2 / `inno` 0.7.6 | Apache / MIT | |
| MSI / CAB / CFB | `msi` 0.11、`cab` 0.6、`cfb` 0.16、`lzxd` | MIT | |
| 通用压缩包 | `zip` 9.7、`tar`、`sevenz-rust2` 0.25、`flate2`/`xz2`/`zstd`/`bzip2` | MIT / Apache | RAR 仅有 C 绑定（`unrar`），设为可选 feature |
| Authenticode | `authenticode` 0.6 + `cms` + `x509-parser` | MIT / Apache | 链验证需自己组装 |
| .NET 元数据 | `dotscope` 0.9.1 | Apache-2.0 | 纯 Rust ECMA-335 |
| Electron asar | `asar` 0.3 | MIT / Apache | |
| 反汇编 | `iced-x86` 1.22、`disarm64` 0.2 / `yaxpeax-arm` | MIT | 只做轻量用途（入口点、特征），不做反编译 |
| 调试信息 / 符号 | `gimli` 0.34、`pdb` 0.8、`symbolic-demangle` | MIT / Apache | |
| 规则引擎 | `yara-x` 1.23（或更轻的 `boreal` 1.4） | BSD-3 / MIT | yara-x 带 wasmtime，体积大；boreal 更轻 |
| 文件类型识别 | `infer` 0.22 + 自有魔数表 | MIT | |
| 相似度哈希 | `tlsh2` 1.1 | Apache / BSD | 避开 GPL 的 `ssdeep` |
| SBOM | `cyclonedx-bom` 0.9 | Apache-2.0 | |
| 模板 / Markdown | `minijinja` 3.1 / `askama` 0.16、`comrak` 1.0 | Apache / MIT / BSD | |
| **PDF** | **`typst` 0.15 + `typst-pdf`（库内嵌）** | Apache-2.0 | 见 §6.3 |

**许可证红线**：不引入 GPL crate（如 `exe`、`ssdeep`）；MPL-2.0（apple-codesign / apple-xar）可动态接受但需在 NOTICE 中声明。

> 局限：本次调研环境无法访问 docs.rs，因此上表各 crate 的"存在性 / 版本 / 许可证"已通过 crates.io 核实，但 **API 深度（例如 apfs 能否读压缩卷、apk-info 是否校验 v3 签名）尚未验证**，已列入 M0 的技术验证任务。

---

## 2. 产品定义

### 2.1 输入（限定为"电脑上的产物"）

| 类别 | 具体格式 | 优先级 |
|---|---|---|
| iOS | `.ipa`、解压后的 `Payload/*.app` | P0 |
| Android | `.apk`、`.aab`、`.xapk` / `.apks` | P0 |
| macOS | `.app` 目录、`.dmg`、`.pkg`、单个 Mach-O、`.framework` / `.dylib` | P0 |
| Windows | `.exe` / `.dll`（PE）、**NSIS 安装包**、Inno Setup、`.msi`、`.msix`、**已安装程序目录** | P0（NSIS/PE/目录）P1（其余） |
| Linux | ELF、`.deb`、`.rpm`、AppImage | P2 |
| 通用 | 任意文件夹、zip / tar.* / 7z / (rar)、未知文件（降级为通用分析） | P0 |

未知格式**永不报错退出**：降级到"通用文件分析"（类型猜测、哈希、熵、字符串、嵌入数据扫描）。

### 2.2 输出

- `report.json` —— **唯一事实来源**（带 JSON Schema 的中间表示，IR）
- `report.md` / `report.txt` / `report.html`（单文件自包含，可离线打开，带搜索与目录）/ `report.pdf`
- 可选：`sbom.cdx.json`（CycloneDX）、`--extract-dir` 保留解包产物

四种人类可读格式**全部由同一个 IR 渲染**，保证内容一致。

### 2.3 CLI 形态

```
aa analyze <PATH> [-o out/] [--format pdf,html,md,txt,json] [--lang zh|en]
                  [--profile quick|standard|deep] [--rules extra.yar] [--offline]
aa inspect <PATH> --json          # 只做识别 + 结构树，给 Agent/脚本用
aa render report.json --format pdf # 由已有 IR 重新渲染，不重新分析
aa explain <FINDING_ID>           # 打印某条结论的完整证据
aa selftest                       # 用内置样本自检
```

### 2.4 非目标（明确不做）

- 不执行、不安装、不动态调试被分析对象（纯静态）
- 不做反编译到伪代码（那是 Ghidra/IDA/REA 的领域；后续可通过可选插件对接）
- 不做 FairPlay 解密、不脱壳、不绕过任何保护；遇到加密/加壳，如实报告"此处不可见"
- 不联网查询（默认离线；VirusTotal 等查询作为显式开启的可选项）

---

## 3. "可靠"如何落地（核心设计原则）

这是整个项目的第一优先级，以机制而不是口号来保证：

1. **证据优先的数据模型**。报告中每一条结论（Finding）都必须携带：
   - `evidence[]`：来源文件（在解包树中的完整路径）、字节偏移 / 结构字段名、原始值、该文件的 SHA-256
   - `method`：由哪个分析器、哪条规则（含规则版本）得出
   - `confidence`：三级 ——
     - **Verified 已验证**：直接从规范定义的结构读出或经密码学校验（如"签名校验通过""Info.plist 中 CFBundleIdentifier = …"）
     - **Derived 推导**：由已验证事实确定性推出（如"链接了 libswiftCore → 含 Swift 代码"）
     - **Heuristic 启发式**：模式匹配 / 规则命中（如"疑似 AWS 密钥""疑似 UPX 加壳"），报告中明确标注，并给出误报提示
2. **无证据不成文**。渲染层只能引用 IR 中的 Finding；模板里不允许出现无 Finding ID 支撑的断言性文字。
3. **如实声明盲区**。每份报告固定有"分析覆盖度与局限"章节：哪些文件解析失败、哪些被加密（FairPlay / 加密 DMG）、哪些因超限被跳过、哪些分析器未启用。**"没发现"与"没检查"严格区分**。
4. **确定性与可复现**。同一输入 + 同一版本 + 同一规则库 ⇒ 字节级相同的 `report.json`（排序稳定、无时间戳进入正文、并行结果归并有序）。报告页眉记录：工具版本、规则库版本、输入 SHA-256、命令行参数。
5. **核心流程不使用 LLM**。事实抽取 100% 由确定性代码完成。LLM 仅作为后期**可选**的"解读层"（见 §8），且只能读取 IR、必须逐句引用 Finding ID，在报告中单独成章并标注"AI 生成"。
6. **对照验证（差分测试）**。CI 中把我们的结果与权威工具对比：`codesign -dvvv` / `apksigner verify` / `aapt2 dump` / `sigcheck` / `otool` / `readelf` / MobSF。不一致即视为 bug。
7. **面对恶意输入的健壮性**。输入是不可信数据：解包限额（总大小、文件数、嵌套深度、压缩比 → 防 zip bomb）、路径穿越防护、符号链接不跟随、解析器 panic 隔离（`catch_unwind` + 每分析器超时）、对所有解析器做 `cargo-fuzz`。单个分析器失败只会降级为一条"局限"记录，不影响整份报告。

---

## 4. 架构

### 4.1 流水线（6 个阶段）

```
 输入路径
   │
   ▼
① Identify   识别类型（魔数 + 结构探测 + 扩展名仅作参考）
   │
   ▼
② Unpack     递归解包 → 构建「产物树」(Artifact Tree)
   │           IPA → Payload/X.app → Mach-O(fat) → arm64 slice
   │           NSIS.exe → 安装脚本 + 内嵌文件 → app.asar → JS …
   ▼
③ Analyze    对树上每个节点并行运行匹配的分析器 → Facts + Findings
   │
   ▼
④ Correlate  跨节点关联：权限声明 vs 实际 API 使用、SDK 归并、
   │           重复文件、同一证书签了哪些文件、URL→域名聚合
   ▼
⑤ Assess     评分与摘要：风险分级、关键信息卡、覆盖度统计
   │
   ▼
⑥ Render     report.json → md / txt / html / pdf
```

### 4.2 Workspace 划分

```
analyze-anything/
├── crates/
│   ├── aa-core        # 数据模型：Artifact / Fact / Finding / Evidence / Confidence，IR schema
│   ├── aa-vfs         # 产物树 + 只读虚拟文件系统（内存 / 临时目录 / mmap），限额与安全策略
│   ├── aa-detect      # 类型识别
│   ├── aa-unpack      # 解包器：zip tar 7z dmg xar/pkg nsis inno msi cab asar ar/deb rpm …
│   ├── aa-binary      # 通用二进制：PE / Mach-O / ELF、加固检查、符号、导入导出、编译器/语言识别
│   ├── aa-apple       # .app / .ipa：Info.plist、签名、entitlements、provisioning、PrivacyInfo
│   ├── aa-android     # APK/AAB：Manifest、resources、DEX、签名 v1–v4、native libs
│   ├── aa-windows     # Authenticode、版本资源、manifest、.NET、安装包语义、已安装目录
│   ├── aa-content     # 通用内容：字符串、URL/域名/IP、密钥、熵、嵌入文件、脚本/配置
│   ├── aa-rules       # 规则引擎与规则库（YARA、密钥正则、SDK/Tracker 指纹、加壳特征）
│   ├── aa-correlate   # 跨产物关联与评估
│   ├── aa-report      # 渲染器：json / md / txt / html / pdf（typst），i18n
│   └── aa-cli         # 二进制 `aa`
├── rules/             # 版本化的规则数据（YAML/YAR），编译期内嵌，也可运行时覆盖
├── testdata/          # 自建的最小样本 + 期望输出（golden）
└── docs/
```

### 4.3 关键抽象

```rust
trait Unpacker { fn probe(&self, a: &Artifact) -> Match; fn unpack(&self, a: &Artifact, ctx: &mut Ctx) -> Result<Vec<Artifact>>; }
trait Analyzer { fn id(&self) -> &'static str; fn applies(&self, a: &Artifact) -> bool;
                 fn analyze(&self, a: &Artifact, ctx: &Ctx) -> AnalyzerOutput /* facts, findings, limitations */; }
trait Renderer { fn render(&self, report: &Report, opts: &RenderOpts) -> Result<Vec<u8>>; }
```

新增一种格式 = 实现一个 `Unpacker` 和/或 `Analyzer` 并注册，不动核心。

---

## 5. 报告维度（"全方位解读"的具体含义）

报告固定为以下章节；某章节不适用时显示"不适用"而不是省略，保证结构稳定。

| # | 章节 | 内容 | 例子 |
|---|---|---|---|
| 0 | **摘要** | 一页看懂：这是什么、谁发布的、多大、用什么做的、关键风险点、覆盖度 | "iOS 应用 com.x.y 3.2.1，Team ABCDE12345，Swift + Flutter，含 14 个三方 SDK" |
| 1 | **身份** | 名称、包名/Bundle ID、版本、构建号、最低系统、架构、哈希（MD5/SHA-1/SHA-256/TLSH）、图标 | |
| 2 | **来源与签名** | 证书链、签名者、有效期、时间戳、签名是否完整覆盖、公证/Notarization ticket、provisioning 类型（开发/AdHoc/企业/商店）、APK 签名方案 v1–v4、Authenticode | |
| 3 | **结构清单** | 产物树、体积分布（Treemap）、文件类型统计、Top N 大文件、重复文件、嵌套包 | |
| 4 | **技术栈与组成** | 语言（Swift/ObjC/Kotlin/Java/C++/Rust/Go/.NET）、框架（Flutter / React Native / Electron / Unity / Qt / Xamarin / Tauri…）、编译器与 SDK 版本、三方库/SDK 清单（含版本）、SBOM | |
| 5 | **权限与能力** | Android 权限与组件导出、iOS entitlements 与 usage descriptions、URL Scheme / deep link、Windows manifest（UAC 级别）、安装包行为（写注册表、自启动、服务、驱动） | |
| 6 | **安全加固** | PIE/ASLR、NX/DEP、Stack Canary、RELRO、CFG、ARC、是否 strip、调试标志、ATS / cleartext、备份开关、加壳/混淆识别 | |
| 7 | **网络与端点** | URL、域名、IP、证书固定配置、云服务端点归类 | |
| 8 | **敏感信息** | 硬编码密钥/Token/私钥（启发式，脱敏显示）、内嵌证书、配置文件中的凭据 | |
| 9 | **隐私** | Tracker/广告/分析 SDK、PrivacyInfo.xcprivacy、Data Safety 相关权限、采集能力推断 | |
| 10 | **代码洞察** | 导入/导出符号、ObjC/Swift 类名、DEX 类包结构、.NET 类型、有趣的字符串、Electron 主进程入口与 IPC | |
| 11 | **异常与可疑点** | 高熵节、签名后被修改、扩展名与内容不符、隐藏文件、YARA 命中 | |
| 12 | **分析覆盖度与局限** | 见 §3.3 | |
| 附录 | 完整证据表、文件清单（含哈希）、规则版本、术语表 | |

---

## 6. 关键技术决策

### 6.1 产物树 + 递归解包
所有输入统一成一棵树，节点 = `Artifact { id, path_in_tree, kind, size, sha256, parent, source: OnDisk|InMemory|Lazy }`。小文件驻留内存，大文件落临时目录并 mmap。文件夹输入与压缩包输入走同一条路，"已安装的 Windows 程序目录"和".app 目录"自然被支持。

### 6.2 规则数据与代码分离
SDK 指纹、Tracker 列表、密钥正则、加壳特征、权限风险等级全部是 `rules/` 下的版本化数据文件，编译期内嵌，可 `--rules` 追加。规则库有独立版本号并写入报告。

### 6.3 PDF 方案：内嵌 Typst
对比结论：

| 方案 | 结论 |
|---|---|
| headless Chrome 打印 HTML | 效果好但引入外部依赖，违背"单文件离线" ✗ |
| `fulgur`（Blitz + krilla，纯 Rust HTML→PDF） | 很有前景，但较新，长表格分页 / CJK 需验证，作为备选 |
| `printpdf` / `krilla` 手写排版 | 工作量大，表格/分页/目录都要自己做 ✗ |
| **`typst` 作为库内嵌** | **选用**：成熟的排版引擎，自动目录/页眉页脚/跨页表格/代码块，CJK 支持好，纯 Rust，产物可复现 ✓ |

做法：IR → Typst 源（模板内嵌）→ `typst-pdf` 输出。内嵌一套开源字体（含中文，如 Noto Sans SC 子集）以保证跨机器一致；提供 `--font` 覆盖。代价是二进制增大约 15–25 MB，可用 `pdf` feature 开关。

### 6.4 HTML
单文件、自包含（CSS/JS/图标内联，无外链），内含完整 IR 数据，支持：章节导航、全文搜索、产物树浏览、按置信度/严重度筛选、点击结论展开证据。深浅色自适应。

### 6.5 i18n
IR 中结论以 `message_id + 参数` 存储，渲染时按 `--lang zh|en` 取文案；首发中文 + 英文。

### 6.6 性能目标
`rayon` 并行分析；500 MB 的 IPA 在 `standard` 档 ≤ 60 秒、内存峰值 ≤ 1 GB（笔记本）。`quick` 档跳过全量字符串/YARA 扫描。

---

## 7. 里程碑

每个里程碑都以"可演示的端到端结果 + golden 测试"为验收标准。

| 里程碑 | 内容 | 验收 |
|---|---|---|
| **M0 地基与技术验证**（约 1 周） | workspace 骨架、`aa-core` 数据模型与 IR schema、CI（fmt/clippy/test/deny）；**4 个 spike**：① typst 内嵌出中文 PDF ② DMG（HFS+/APFS）读取 ③ NSIS 提取 ④ apk-info 签名能力 | `aa analyze 任意文件` 输出含哈希/类型/熵的 JSON + MD；spike 结论文档，确定各格式走现成 crate 还是自研 |
| **M1 通用层 + 四种渲染**（约 2 周） | 产物树、zip/tar/7z 递归解包与限额、通用内容分析（字符串、URL、密钥、熵）、规则引擎、md/txt/html/pdf 渲染器 | 对任意文件夹/压缩包产出完整四格式报告 |
| **M2 原生二进制**（约 2 周） | PE / Mach-O / ELF：头、节、导入导出、加固、符号、语言/编译器/框架识别、依赖库 | 与 `otool`/`readelf`/`dumpbin` 差分一致 |
| **M3 Apple 全家桶**（约 2–3 周） | `.app` / `.ipa` / `.dmg` / `.pkg`：Info.plist、代码签名校验、entitlements、provisioning profile、PrivacyInfo、frameworks、FairPlay 加密检测 | 与 `codesign -dvvv --entitlements` 差分一致 |
| **M4 Android**（约 2–3 周） | APK / AAB / XAPK：Manifest、resources、签名 v1–v4 校验、DEX 结构、native libs、SDK/Tracker 指纹、加壳识别 | 与 `apksigner` / `aapt2` 差分一致；与 MobSF 报告项对照 |
| **M5 Windows**（约 3 周） | Authenticode、版本资源、manifest、.NET、NSIS / Inno / MSI 安装包语义（安装了什么、写了哪些注册表、是否自启动）、已安装目录、Electron(asar) | 与 `sigcheck` / 7-Zip 清单差分一致 |
| **M6 关联、评估与打磨**（约 2 周） | 跨产物关联、风险评分、SBOM 导出、报告视觉打磨、fuzz、性能、发布（各平台预编译二进制） | v1.0 |
| **M7 生态（v1.x）** | MCP server / SKILL.md（供 Claude Code 等 Agent 调用）、可选 LLM 解读层、两个版本的 diff 报告、Linux 包格式、可选对接 Ghidra | |

建议实现顺序按你工作中最常遇到的格式调整 —— 例如若 IPA/APK 最常用，M3/M4 可提到 M2 之前并行推进。

---

## 8. 可选的 AI 解读层（v1.x，默认关闭）

- 输入只有 `report.json`，不接触原始文件
- 输出"通俗解读 / 值得关注的点 / 建议的后续动作"，每句话必须引用 Finding ID；渲染器校验引用存在，否则丢弃该句
- 在报告中独立成章并显式标注"AI 生成，基于上述已验证事实"
- 这样既获得"可读性"，又不污染"可靠性"

---

## 9. 测试与质量

- **Golden 测试**：`testdata/` 中自建的最小合法样本（自己编译/打包的 hello-world 级 IPA/APK/NSIS/DMG…，可入库、无版权问题）+ 期望 `report.json`，`cargo insta` 快照
- **差分测试**：CI 中调用权威工具对比（见 §3.6）
- **畸形样本**：截断、损坏、zip bomb、路径穿越、超深嵌套 —— 必须优雅降级
- **Fuzz**：`cargo-fuzz` 覆盖所有自研解析器
- **确定性测试**：同一输入跑两次，`report.json` 字节一致
- **供应链**：`cargo-deny`（许可证 + 安全公告）、锁定依赖

---

## 10. 风险与对策

| 风险 | 对策 |
|---|---|
| App Store 下载的 IPA 主二进制被 FairPlay 加密，代码段不可读 | 检测 `LC_ENCRYPTION_INFO.cryptid`，如实标注；元数据、资源、签名、frameworks 仍可完整分析 |
| DMG 变体多（APFS、加密、分段、LZFSE/ULMO） | M0 spike；不支持的变体明确报"无法读取"并仍分析外层；必要时自研 UDIF 层 |
| NSIS / Inno 版本众多、有魔改版 | 依赖专门的解析 crate；失败时降级为 PE + overlay 的通用分析 |
| 部分 crate 维护不活跃（dex、apple-dmg 等） | 格式规范公开稳定，必要时 vendor 或自研轻量解析器；所有三方解析器都包在 panic 隔离内 |
| 启发式结论误报（密钥、Tracker） | 置信度分级 + 脱敏 + 证据可点开核对；规则带测试用例 |
| 二进制体积（typst + 字体 + yara-x） | feature 开关；规则引擎先用 `boreal`，确有需要再换 `yara-x` |
| 合规：逆向分析的法律边界 | 纯静态、只读、不解密不绕过；README 声明仅用于有权分析的对象 |

---

## 11. 待你确认的事项（均已给出默认选择，不阻塞开工）

1. **命令名**：默认 `aa`（包名 `analyze-anything`）。
2. **格式优先级**：默认 M3(Apple) → M4(Android) → M5(Windows)；可按你的实际工作频率调整。
3. **报告语言**：默认中英双语可切换，中文为默认。
4. **AI 解读层**：默认 v1.0 不含，v1.x 作为可选项加入。
5. **"Craft Anything"** 具体指哪个项目（见 §1.1 说明）。

---

## 参考来源

- REA：<https://github.com/morluto/rea> ；InfoQ 报道 <https://www.infoq.com/news/2026/10/reverse-engineer-anything/>
- CLI-Anything：<https://github.com/HKUDS/CLI-Anything> ；论文 <https://arxiv.org/html/2606.03854v1>
- MobSF：<https://github.com/MobSF/Mobile-Security-Framework-MobSF>
- Rust crate 版本与许可证：crates.io（2026-11-18 通过 `cargo info` 核实）
