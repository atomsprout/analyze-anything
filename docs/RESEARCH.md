# Analyze Anything — 调研记录

> 2026-11-18。这是 [PLAN.md](PLAN.md) 的依据；规划本身见 PLAN.md。

## 1. 参考项目

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

## 2. 第二轮搜索补充（2026-11-18，仅依据仓库简介与 README，未读源码）

| 项目 | 语言 / 规模 | 是什么 | 对我们的参考价值 |
|---|---|---|---|
| **reverify**（`2akouwu/reverify`） | ★1.3k | "模型提出结论，确定性工具逐条核验" | 与 PLAN.md 的 AI 解读层思路一致；做 v1.x 解读层时重点参考其核验机制 |
| **knife / reknife**（`bl4ckr0ss3/knife`） | Rust，★412 | 终端优先的 PE / ELF / Mach-O 逆向工具箱，CLI + TUI + MCP，YARA 走 yara-x | 与 M2 范围最接近的 Rust 同类；参考其子命令划分与 MCP 暴露方式 |
| **binskim**（`microsoft/binskim`） | C#，★869 | 微软的 PE / ELF 二进制安全合规检查，规则有编号，输出 SARIF | 加固检查的**规则清单与判定标准**；考虑增加 SARIF 输出便于接入 CI |
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

## 3. Rust 生态可用性（版本为 2026-11-18 crates.io 实测）

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
| **PDF** | **`typst` 0.15 + `typst-pdf`（库内嵌）** | Apache-2.0 | 见 PLAN.md §5.3 |

**许可证红线**：不引入 GPL crate（如 `exe`、`ssdeep`）；MPL-2.0（apple-codesign / apple-xar）可动态接受但需在 NOTICE 中声明。

> 局限：本次调研环境无法访问 docs.rs，因此上表各 crate 的"存在性 / 版本 / 许可证"已通过 crates.io 核实，但 **API 深度（例如 apfs 能否读压缩卷、apk-info 是否校验 v3 签名）尚未验证**，已列入 M0 的技术验证任务。

---

## 参考来源

- REA：<https://github.com/morluto/rea> ；InfoQ 报道 <https://www.infoq.com/news/2026/10/reverse-engineer-anything/>
- Craft Anything：<https://github.com/storytold/craft-anything>（已克隆源码阅读：`crates/evidence`、`crates/formats`、`docs/tools.md`）
- RESX：<https://github.com/ryftenius/resx>（已克隆源码阅读：`docs/architecture.md`、`docs/json-schemas.md`、`resx/src`）
- CLI-Anything：<https://github.com/HKUDS/CLI-Anything> ；论文 <https://arxiv.org/html/2606.03854v1>
- MobSF：<https://github.com/MobSF/Mobile-Security-Framework-MobSF>
- Rust crate 版本与许可证：crates.io（2026-11-18 通过 `cargo info` 核实）
