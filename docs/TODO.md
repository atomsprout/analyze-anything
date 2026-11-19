# 剩余待办

第一阶段（命令行工具）和第二阶段的 macOS 桌面版（D0–D5）已完成。这里记录还没做完的事。已知的功能局限见 [LIMITATIONS.md](LIMITATIONS.md)，桌面版的说明见 [DESKTOP.md](DESKTOP.md)。

## 已完成（2026-11-19，在一台 Apple 芯片的 Mac 上）

- [x] **在 Mac 上实测命令行**：8 个已安装的应用、5 个真实的 IPA 和 DMG。与 `codesign` 对照 332 项一致。实测发现并修掉了 5 处问题：App Store 后加的文件被报成“签名后新增”、描述文件的通配符和沙箱权利被报成越权、只有私钥标记没有密钥内容被报成“内嵌私钥（高）”、输入文件夹本身是应用时名称为空、中文报告里夹着英文的文件类型。
- [x] **App Store 下载的加密 IPA**：能识别 FairPlay 加密，元数据、签名、资源完整分析。
- [x] 通用二进制各架构切片相同的结论合并成一条，方括号里列出适用的架构。
- [x] MSI 自身的数字签名：校验内容摘要、元数据摘要、签名值和证书链（与 osslsigncode 对照）。
- [x] Mach-O 的导出字典树、链式修正和绑定操作码（与 `dyld_info`、`nm`、`objdump` 对照）。
- [x] 进程被强行终止后遗留的临时目录：下一次运行开始时清理。
- [x] 对真实样本的对照脚本进仓库：`tools/native-compare/macos_real.py`（签名）、`macos_symbols.py`（导入导出）。
- [x] 分析器卡死时真正终止：桌面版把分析放进子进程，取消后强制结束。命令行仍是“放弃等待”。
- [x] 桌面版 D0–D5：技术验证、引擎补齐、主流程、证据与十六进制视图、历史与对比（含 `aa diff`）、打包签名公证。
- [x] 通过 Homebrew 发布：命令行和桌面版分开安装，仅 Apple 芯片。

## 等待人工操作

- [ ] **恢复 GitHub Actions 并重跑 CI**（已决定推迟：2026-11-19 定下目前只管 macOS Apple 芯片，其他平台的验证和发布不挡当前工作）：2026-11-19 起组织的 Actions 任务不再启动（“recent account payments have failed or your spending limit needs to be increased”）。在此之前，`v0.1.0` 标签的五平台构建里 Windows x64、macOS x64 / arm64、Linux arm64 的测试全部通过，Linux x64 有一项测试失败（工作进程崩溃时退出码的竞态，已修复）。修复之后的提交没有在 Linux 和 Windows 上跑过测试，只在 macOS 上跑过，并从 macOS 对 Linux x64 和 Windows x64 做过编译检查。账单恢复后重跑 CI，再重新触发标签构建以生成其他平台的草稿发布。

- [ ] **决定命令行的名字**：`aa` 与 macOS 自带的 `/usr/bin/aa`（Apple Archive）重名，Homebrew 安装时改成了 `analyze-anything`。是否在所有平台统一改名（包括 `--version` 的输出、CI 的打包名、文档），需要定一下。

- [ ] **桌面版的三处人工检查**：原生菜单和快捷键、拖放、系统的打开 / 保存对话框（见 [DESKTOP.md](DESKTOP.md)）。其余流程由应用的自检模式在真实窗口里跑过。
- [ ] **读一遍真实报告**：`report.html` 和 `report.pdf` 哪里啰嗦、哪里缺内容，需要人来判断；章节详略和同类结论的合并上限（目前每组列 10 条）等这轮反馈再调。
- [ ] **在 Windows 机器上实测**（已决定推迟）：用真实的安装包和已安装程序目录各跑一遍；用 `sigcheck` 或 `signtool verify /pa /v` 对照签名结论，包括新加的 MSI 签名校验。
- [ ] 把 [tools/native-compare/](../tools/native-compare/) 里的两个新脚本接进 “Native comparison” 工作流（它们需要机器上有真实的应用，GitHub 的 runner 上要先挑定样本）。

## 需要真实样本才能验证

以下格式只用构造的数据测试过，本机没有真实样本：

- [ ] **加固过的 APK**（360、腾讯乐固、梆梆等）：确认能识别加固壳，并说明真实代码不可见。
- [ ] **XAPK / APKS / APKM**：可用 Google 的 bundletool 从 AAB 生成 `.apks`：
      `java -jar bundletool-all.jar build-apks --bundle=app.aab --output=app.apks`
- [ ] **加密的 DMG**：目前只验证了“能识别为加密、不声称读出内容”。
- [ ] **Inno Setup 6.4 安装包**：能解出文件，但参考工具 `innoextract` 读不了这个版本，结果未核对。

## 第一阶段的收尾改进

- [ ] 规则文字里剩余的英文片段：文件类型已按语言输出；签名失败的技术原因（来自解析库的英文错误文本）仍是原文。
- [ ] 命令行可以复用子进程方案，让 `--analyzer-timeout` 真正终止卡住的分析。
- [ ] 对比时，文字里带输入名字的结论会被算作“变化”；可以在比较前把输入名字从参数里去掉。

## 第二阶段的后续

- [ ] D6：Windows 和 Linux 版桌面应用（构建、安装包、平台差异、Linux 上的端到端自动化）。
- [ ] Intel Mac 的发布包（目前只发 Apple 芯片）。
- [ ] 自动更新（第二阶段不做）。
- [ ] 签名的发布构建目前在本机用 `tools/release/macos.sh` 完成；放进 CI 需要把证书和公证凭据配成仓库密钥。

## 第三阶段：生态（未开始）

- [ ] 给 AI Agent 调用的接口：MCP server 与 SKILL.md。
- [x] 可选的 AI 解读层：`aa interpret`，只读 `report.json`，每句话必须引用结论 ID，支持 Claude 和 OpenAI 兼容的服务（见 [AI.md](AI.md)）。
- [ ] AI 解读的后续：用真实的模型服务各跑一遍（目前只对着本机的模拟服务测过）；接入桌面版；把解读作为一章放进 HTML / PDF 报告。
- [ ] 更多输入：Linux 包（deb / rpm / AppImage）、鸿蒙 HAP、PyInstaller 等打包程序。
- [ ] `deep` 档：函数级分析，可选对接 Ghidra 或 Kuna。
