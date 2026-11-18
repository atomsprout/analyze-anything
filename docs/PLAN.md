# Analyze Anything — 调研与规划

> 状态：规划稿 v0.5（2026-11-18）
> 一句话定位：**输入电脑上的任意产物（文件 / 文件夹 / 压缩包 / 安装包 / 应用包），输出一份可靠、可溯源、多维度的分析报告（PDF / HTML / Markdown / TXT）。** 使用 Rust 开发，单一静态二进制，离线可用。

---

## 1. 调研结论

### 1.1 参考项目

| 项目 | 它是什么 | 值得借鉴 | 与我们的差异 |
|---|---|---|---|
| **REA**（Reverse Engineer Anything，`morluto/rea`，MIT，Node.js） | 给 AI Agent 用的 MCP 服务器 + CLI。把 Ghidra / IDA / Hopper / JADX / Apktool / Binwalk 等包装成工具，让 Agent 交互式地反编译、追踪、验证假设 | ① 每个结论都带 **证据 + 局限 + 未知项**；② 结果在服务端做 schema 校验；③ 覆盖面的"目标清单"（ELF/PE/Mach-O、.NET、APK、Flutter、Electron、PyInstaller、IL2CPP、Godot、WASM…）可作为我们的格式路线图 | REA 是 **交互式、Agent 驱动、依赖外部重型工具**，没有固定的"报告"产物；我们是 **确定性、一次跑完、零外部依赖、以报告为交付物** |
| **Craft Anything**（`storytold/craft-anything`，MIT OR Apache-2.0，**纯 Rust**，约 28 万行，early alpha） | "看懂任意软件并重建一个自己的"：Research → Build → Check 循环。约 314 个检查工具，同时暴露为 CLI 子命令与 MCP 工具，另有 egui 桌面端与 WASM 版。默认 clean-room 模式（只看外观行为），`--deep` 才读代码与文件 | **与我们技术栈最接近，是首要参考**：① `crates/evidence` 的证据模型 —— 置信度 `Observed / Derived / Inferred`、权威来源 `Authority`、`Limitation`、`Coverage`、一等公民的 `Unknown`（"absence is not proof"），证据 ID = 规范化 JSON 的 SHA-256；② `crates/formats` 自研了大量解析器（Mach-O、PE、ELF、DEX、AXML、ARSC、APK 签名、Authenticode、codesign、plist、nib、asset catalog、asar、.NET、PyInstaller、IL2CPP、Unity/Unreal/Godot…），底层库拆在 `storytold/craft-libs`（craft-pe / craft-macho / craft-elf / craft-dex / craft-zip / craft-plist…）；③ 全工作区 `unsafe_code = "forbid"`、`cargo-deny`、`docs/pitfalls.md` 的工程纪律 | 目标是**重建软件**，由 Agent 驱动；报告只是附带工具（`core_report_write`）。**不覆盖** DMG / NSIS / Inno / MSI 等安装包，没有 provisioning profile、Tracker/SDK 指纹、加固评估、PDF 输出，也没有"一条命令出完整报告"的固定流水线 |
| **RESX**（`ryftenius/resx`，MIT，纯 Rust，约 7 万行，v2.3.0） | 专注 Windows x64 PE 的静态逆向工具箱：`peinfo` / `pechk` 体检、被隐藏的动态 API 还原（哈希、PEB 遍历）、调用图、行为归类（`network` / `crypto` / `ipc` / `payload`）、内核驱动 IOCTL 码表与设备安全检查、样本 diff / 索引 / 检索、YARA。只读文件字节，从不加载或执行 | ① 依赖极少（仅 `iced-x86` 等 8 个），PE、PDB、YARA 解析全部自研，说明 Windows 这部分自己写是可行的；② JSON 输出纪律：带版本号的信封、**"缺失的证据输出 null，绝不用 0 顶替"**、命中上限时显式报告截断；③ 分层：格式解析 → 单镜像共享事实（惰性计算并缓存）→ 分析 → 渲染，命令层不做分析；④ PE 合法性校验、加壳初筛、行为归类、驱动分析的具体做法，供 M4 Windows 参考 | 只管单个 PE 的深度逆向，面向逆向工程师的终端输出；不处理安装包和其他平台，没有成品报告。它的函数级深度（调用图、CFG 重建、参数恢复）超出我们 v1.0 的范围，列入 `deep` 档的后续候选 |
| **CLI-Anything**（`HKUDS/CLI-Anything`，Apache-2.0） | 用 7 阶段流水线把任意软件包装成 Agent 可调用的 CLI | ① 固定阶段的流水线思路；② "Agent-native"：全部命令支持 `--json`、附带 SKILL.md | 目标不同（生成 CLI 而非分析产物）。我们借鉴其"对 Agent 友好"的接口设计 |
| **MobSF**（Python） | 移动应用静态/动态安全分析，输出 PDF/JSON 报告 | 报告章节是事实标准：权限、组件导出、签名、二进制加固（PIE/Canary/NX/RELRO）、硬编码密钥、URL/域名、Tracker（Exodus 库）、APKiD 加壳识别 | 只覆盖移动端，部署重（Docker + JDK），无桌面格式 |
| **reknife / rbat / binsec**（Rust） | 基于 goblin + yara-x + iced-x86 的二进制体检工具 | 证明了纯 Rust 技术栈可行 | 只看单个可执行文件，不处理"包"，无完整报告 |
| **binwalk v3**（Rust）/ unblob | 递归识别并提取嵌入数据 | 递归解包、熵分析 | 面向固件，不解读语义 |
| **Detect-It-Easy / APKiD / capa / FLOSS** | 编译器/加壳识别、能力识别、混淆字符串还原 | 规则库与识别思路 | 各管一段，无统一报告 |

### 1.1.1 第二轮搜索补充（2026-11-18，仅依据仓库简介与 README，未读源码）

| 项目 | 语言 / 规模 | 是什么 | 对我们的参考价值 |
|---|---|---|---|
| **reverify**（`2akouwu/reverify`） | ★1.3k | "模型提出结论，确定性工具逐条核验" | 与 §8 的 AI 解读层思路一致；做 v1.x 解读层时重点参考其核验机制 |
| **knife / reknife**（`bl4ckr0ss3/knife`） | Rust，★412 | 终端优先的 PE / ELF / Mach-O 逆向工具箱，CLI + TUI + MCP，YARA 走 yara-x | 与 M2 范围最接近的 Rust 同类；参考其子命令划分与 MCP 暴露方式 |
| **binskim**（`microsoft/binskim`） | C#，★869 | 微软的 PE / ELF 二进制安全合规检查，规则有编号，输出 SARIF | 加固检查的**规则清单与判定标准**（§5 第 6 章）；考虑增加 SARIF 输出便于接入 CI |
| **checksec.rs**（`etke/checksec.rs`） | Rust，★122 | ELF / PE / Mach-O 三平台 checksec | 加固项判定逻辑的直接对照（也可作差分测试基准） |
| **capa**（`mandiant/capa`） | Python，★6.3k | 用规则识别可执行文件的"能力"（如"会截屏""会注入进程"），映射 ATT&CK | 行为画像的规则组织方式；规则库为 Apache-2.0，可评估格式兼容 |
| **APEX**（`mlab-sh/apex`） | Rust，★2，GPL-3.0 | APK / AAB / XAPK / IPA 的 15 个分析器 + 加权评分，结论映射 CWE / OWASP MASVS / ATT&CK；证据包带 SHA-256 清单与 RFC 3161 时间戳 | ① 结论映射到 MASVS / CWE 的做法；② 报告清单哈希 + `verify` 命令。**GPL，只看思路不看代码** |
| **ReArk**（`lkimuk/ReArk`） | C++，★977 | 鸿蒙 NEXT（HAP/APP/ABC）、Android、iOS 包的逆向与 AI 辅助分析 | 提醒：**鸿蒙 HAP** 是值得列入 v1.x 的输入格式 |
| **MachOExplorer**（`everettjf/machoexplorer`） | Rust，★647 | Mach-O 结构浏览器 | M3 的 Mach-O 字段展示参考 |
| **disrobe**（`1-3-7/disrobe`） | Rust，★174 | Python 反编译、PyInstaller 等解包与去混淆 | PyInstaller / Python 打包程序的解包参考（v1.x） |
| **Kuna**（`Noelo-Lab/kuna`） | Rust，★907 | 面向 Agent 的反编译器，自 Ghidra 移植 | 若将来 `deep` 档要做伪代码，这是纯 Rust 的候选对接对象 |
| **binsider**（`orhun/binsider`） | Rust，★4.5k | ELF 的终端交互式分析 | 仅 ELF；TUI 交互参考 |
| **cwe_checker**（`fkie-cad/cwe_checker`） | Rust，★1.4k | 在二进制中查找 CWE 漏洞模式（依赖 Ghidra） | 超出 v1.0 范围，记录备查 |
| APKHunt / APKDeepLens / apkAnalyzer | Python | 各类 APK 静态扫描器，输出 HTML / PDF / SARIF | M5 的检查项清单对照 |
| ida-pro-mcp / GhidraMCP / Open ReverseLab / Eleven | — | 把 IDA / Ghidra / x64dbg / Frida 接给 Agent 的 MCP 桥 | 与 REA 同类，交互式逆向，不出报告；与我们互补 |

**这一轮的结论**：仍然没有发现"任意桌面/移动产物 → 一份带证据的完整报告"的同类；最接近的 MobSF（仅移动端、Python）和 APEX（仅移动端、IPA 只跑 3 个分析器）都不覆盖 Windows 安装包、macOS 应用和 DMG。由此新增三项计划内容：结论映射到 **OWASP MASVS / CWE** 编号（M3–M5）、**SARIF** 输出（M6）、报告清单哈希与 `aa verify`（M6）；鸿蒙 HAP 与 PyInstaller 列入 v1.x。

**空白点（我们的机会）**：目前没有一个工具同时满足 ——
① 以**报告**（而非 Agent 交互或软件重建）为交付物的固定流水线；② 同时覆盖 IPA / APK / Windows 安装包 / 已安装程序目录 / .app / DMG；③ 递归拆包后做**跨文件关联**；④ 纯 Rust 单文件、离线、PDF/HTML/MD/TXT 四种输出。

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
   - `id`：结论规范化 JSON 的 SHA-256（借鉴 Craft Anything）—— 同一观察永远得到同一 ID，任何篡改可检测，也让 `aa explain <ID>` 和两份报告的 diff 变得简单
   - `confidence`：三级（与 Craft Anything 的 Observed / Derived / Inferred 对应，便于将来互通）——
     - **Verified 已验证**：直接从规范定义的结构读出或经密码学校验（如"签名校验通过""Info.plist 中 CFBundleIdentifier = …"）
     - **Derived 推导**：由已验证事实确定性推出（如"链接了 libswiftCore → 含 Swift 代码"）
     - **Heuristic 启发式**：模式匹配 / 规则命中（如"疑似 AWS 密钥""疑似 UPX 加壳"），报告中明确标注，并给出误报提示
2. **无证据不成文**。渲染层只能引用 IR 中的 Finding；模板里不允许出现无 Finding ID 支撑的断言性文字。
3. **如实声明盲区**。未解决的问题作为一等公民 `Unknown` 记录（"是什么没搞清楚 + 用什么手段可以搞清楚"）；每个分析器输出 `Coverage`（已检查 / 总量）。每份报告固定有"分析覆盖度与局限"章节：哪些文件解析失败、哪些被加密（FairPlay / 加密 DMG）、哪些因超限被跳过、哪些分析器未启用。**"没发现"与"没检查"严格区分**。
4. **确定性与可复现**。缺失的值在 IR 中一律为 null，绝不用 0 或空串顶替；命中限额时显式记录截断（借鉴 RESX）。同一输入 + 同一版本 + 同一规则库 ⇒ 字节级相同的 `report.json`（排序稳定、无时间戳进入正文、并行结果归并有序）。报告页眉记录：工具版本、规则库版本、输入 SHA-256、命令行参数。
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
| **M4 Windows**（约 3 周） | Authenticode、版本资源、manifest、.NET、NSIS / Inno / MSI 安装包语义（安装了什么、写了哪些注册表、是否自启动）、已安装目录、Electron(asar)；PE 结构合法性校验与加壳初筛、按类别归纳导入 API 的行为画像（网络 / 加密 / 进程间通信 / 持久化）；内核驱动（.sys）识别与基础信息 | 与 `sigcheck` / 7-Zip 清单差分一致 |
| **M5 Android**（约 2–3 周） | APK / AAB / XAPK：Manifest、resources、签名 v1–v4 校验、DEX 结构、native libs、SDK/Tracker 指纹、加壳识别 | 与 `apksigner` / `aapt2` 差分一致；与 MobSF 报告项对照 |
| **M6 关联、评估与打磨**（约 2 周） | 跨产物关联、风险评分、SBOM 导出、SARIF 输出、输出清单哈希与 `aa verify`、报告视觉打磨、fuzz、性能、发布（各平台预编译二进制） | v1.0 |
| **M7 生态（v1.x）** | MCP server / SKILL.md（供 Claude Code 等 Agent 调用）、可选 LLM 解读层、两个版本的 diff 报告、Linux 包格式、鸿蒙 HAP、PyInstaller 等打包程序、可选对接 Ghidra | |

格式顺序已确定为 **Apple → Windows → Android**（2026-11-18 确认）。

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

## 11. 已确定的决策

- **Craft Anything 只作为代码参考**（2026-11-18 确认）：不 fork、不依赖其主仓库或 `craft-libs`。可以阅读其实现来理解格式细节和设计思路（证据模型、宽容解析、畸形输入处理），我们的代码自行编写，依赖只取 crates.io 上的库。若确实改编了其中的具体代码片段，按 MIT / Apache-2.0 要求在 NOTICE 中署名。
- **格式顺序：Apple → Windows → Android**（2026-11-18 确认），对应 M3 → M4 → M5。
- **RESX 同样只作为代码参考**，用于 M4 Windows 部分。

## 12. 待你确认的事项（均已给出默认选择，不阻塞开工）

1. **命令名**：默认 `aa`（包名 `analyze-anything`）。
2. **报告语言**：默认中英双语可切换，中文为默认。
3. **AI 解读层**：默认 v1.0 不含，v1.x 作为可选项加入。

---

## 参考来源

- REA：<https://github.com/morluto/rea> ；InfoQ 报道 <https://www.infoq.com/news/2026/10/reverse-engineer-anything/>
- Craft Anything：<https://github.com/storytold/craft-anything>（已克隆源码阅读：`crates/evidence`、`crates/formats`、`docs/tools.md`）
- RESX：<https://github.com/ryftenius/resx>（已克隆源码阅读：`docs/architecture.md`、`docs/json-schemas.md`、`resx/src`）
- CLI-Anything：<https://github.com/HKUDS/CLI-Anything> ；论文 <https://arxiv.org/html/2606.03854v1>
- MobSF：<https://github.com/MobSF/Mobile-Security-Framework-MobSF>
- Rust crate 版本与许可证：crates.io（2026-11-18 通过 `cargo info` 核实）
