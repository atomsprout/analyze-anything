# 使用说明

[English](USAGE.md)

`analyze-anything` 对文件或文件夹做纯静态分析，写出一份带证据的报告。输入只会被读取，不会被执行、安装或加载。

Homebrew 安装时还提供一个短名字 `aaaa`。

## 分析

```
analyze-anything <文件或文件夹> [-o 文件夹] [--format json,html,pdf,md,txt] [--lang en|zh]
```

不写 `-o` 时，报告写到当前目录下的 `<输入的名字>.report`，里面有 `report.json`、`report.html`、`report.pdf`、`report.md`、`report.txt` 和 `manifest.json`。

`analyze-anything analyze <文件或文件夹>` 是同一件事的完整写法。要分析的东西恰好与某个命令同名时（比如一个叫 `diff` 的文件），写出它的路径：`analyze-anything ./diff`。

报告默认是英文，加 `--lang zh` 写中文。`report.html` 里两种语言都有，打开后可以切换；JSON、SARIF、CycloneDX 是数据，不分语言。桌面版同样默认英文，在 View 菜单里切换，选择会记住。

| 格式 | 文件 | 用途 |
|---|---|---|
| `json` | `report.json` | 唯一事实来源：完整的文件树、全部结论和证据、局限、规则文案。其他格式都由它渲染 |
| `html` | `report.html` | 单个自包含文件，可离线打开；可筛选、搜索、浏览文件树、切换语言 |
| `pdf` | `report.pdf` | 用于阅读和存档；内容过多时会截断并在截断处说明 |
| `md` / `txt` | `report.md` / `report.txt` | 纯文本阅读 |
| `sarif` | `report.sarif` | SARIF 2.1.0，供 CI 和代码扫描平台读取 |
| `sbom` | `sbom.cdx.json` | CycloneDX 1.5 组件清单 |

限额用来防止恶意或超大的输入耗尽机器。超出时报告会记下一条局限：

```
--max-files <N>            树中最多的文件数（含解包得到的），默认 200000
--max-depth <N>            最多解包几层嵌套，默认 6
--max-unpacked-bytes <N>   解包总字节上限，默认 8 GiB
--max-entry-bytes <N>      单个被解包文件的上限，默认 2 GiB
--analyzer-timeout <秒>    单个分析器处理单个文件的时间上限，默认 300
--unpack-timeout <秒>      解开单个容器的时间上限，默认 900
--run-timeout <秒>         可选的整次分析期限；到期后最多再等 5 秒接收部分报告
```

`analyze` 在受监督的子进程中执行静态分析。Ctrl+C 或 `--run-timeout` 会请求取消，
子进程最多再用五秒返回有效的部分报告。如果无法返回，就终止子进程并报错，不写入新报告。
报告导出和可选的 AI 解读在分析完成后执行，不受这个期限限制。单个分析器超时仍会放弃
子进程内的线程，并不会立即终止某一个解析器。

`--fail-on low|medium|high`：存在达到该严重度的结论时以退出码 3 结束，供 CI 使用。

`--rules <文件>`：追加你自己的 YARA 规则（可重复）。规则里的 `meta: severity = "high"`（或 `medium`、`low`、`info`）决定结论的严重度，不写则为低。

`--windows-source-root <INF> <ROOT>`：将 INF 显式关联到输入树中的分发根目录（可重复）。
使用逻辑路径，不使用主机路径；`.` 表示外层输入根。例如：

```
analyze-anything ./driver-package -o out --windows-source-root driver.inf .
analyze-anything ./bundle.zip -o out --windows-source-root bundle.zip/pkg/driver.inf bundle.zip/pkg
```

未设置时，源介质根目录保持未解析。支持的松散文件介质路径可关联输入文件及已记录的摘要，
但不会选择 Windows 体系结构、验证目录成员关系或判断安装资格。CAB、标记文件、不支持的别名
和不完整枚举仍以限制说明。初始规则支持 ASCII 逻辑路径、最多 32 条关联，每条路径最多 8 KiB。
引擎和 worker 执行相同校验；桌面界面目前保持默认的未配置根目录行为。
详见[源文件映射范围](spikes/windows-inf-source-mapping.md)（英文）。

`--font <字体文件>`：给 PDF 追加后备字体（可重复），用于内置字体显示不了的文字，例如韩文、阿拉伯文、表情符号。使用后 PDF 的内容也取决于这些字体文件。

`--deep`：再让你电脑上的 Ghidra 或 Hopper 指出是哪些函数在用找到的接口和地址，见 [DEEP.md](DEEP.md)（英文）。默认不启用，而且慢得多。

`--ai`：分析完后让你设置好的 AI 解读报告，见 [AI.md](AI.md)（英文）。默认不启用。

## 其他命令

```
analyze-anything render out/report.json -o out2 --format pdf --lang zh   # 由已有报告写出其他格式，不重新分析
analyze-anything explain out/report.json <结论 ID 的前几位>               # 一条结论和它的全部证据
analyze-anything verify out/                                             # 输出文件是否与 manifest.json 一致
analyze-anything inspect <文件或文件夹>                                    # 只解包并列出文件树（JSON，写到标准输出）
analyze-anything selftest                                                # 用内置样本检查这个构建
analyze-anything diff 旧/report.json 新/report.json                       # 对比两份报告
analyze-anything interpret out/                                          # 可选：让 AI 解读一份报告，见 AI.md
analyze-anything ai                                                      # 查看或选择由谁来做 AI 解读
analyze-anything mcp out/report.json                                     # 把报告的只读工具提供给 AI agent
```

`diff` 的典型用途是同一个应用的两个版本。结论按“同一条规则、输入内同一位置的文件”配对：说法相同算相同，说法不同算变化，只在一边出现算新增或消失。文件按输入内的路径和 SHA-256 比较。`--json` 输出完整结果，`--lang zh` 写中文，`--fail-on-difference` 在有差别时以退出码 3 结束。

`manifest.json` 记录每个输出文件的大小和 SHA-256。`verify` 会指出被改动、丢失或多出来的文件。清单本身没有签名：它能发现无意的改动；如果另外保存了清单自己的 SHA-256，也能发现有意的改动。

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 完成 |
| 1 | 无法运行（比如输入读不了），或 `verify` 发现不一致 |
| 2 | 已运行，但分析不完整；原因在报告的“覆盖度与局限”里 |
| 3 | 有结论达到了 `--fail-on` 指定的严重度，或 `diff --fail-on-difference` 发现了差别 |

## 如何读报告

- **置信度。**“已验证”是直接从格式定义的结构里读出，或经密码学校验的；“推导”是由已验证的事实按固定规则算出的；“启发式”是模式匹配，可能误报。
- **严重度。**“提示”是中性事实，不是问题。低、中、高是每条规则固定的设定，用来排列阅读顺序，不是对输入是否安全的判定。
- **覆盖度与局限**列出没能分析的部分和原因：读不了、被加密、超出限额、解包失败。“没有发现”和“没有检查”是两回事，后者一定会出现在这一章。
- **签名。**报告会写明校验了哪些项。根证书是否受信任、证书是否被吊销、Apple 的公证状态都需要联网或系统信任库，本工具不检查，报告里会注明。

## 支持的输入

| | 格式 |
|---|---|
| 通用 | 任意文件、文件夹；zip、tar、7z、gzip、bzip2、xz、zstd（可嵌套） |
| 原生二进制 | PE（exe / dll / sys）、ELF、Mach-O（含通用二进制） |
| Apple | `.app` 等 bundle、IPA、DMG（HFS+ / APFS）、pkg；代码签名、权利、描述文件、隐私清单 |
| Windows | Authenticode、版本信息与清单、.NET 程序集、NSIS / Inno Setup / MSI / CAB 安装包、自解压程序、Electron（asar）、MSIX、已安装程序目录 |
| Android | APK、AAB、XAPK / APKS / APKM；清单、资源、签名 v1–v3.1、DEX、SDK 与加固壳识别 |

不支持或只能识别的情况见 [LIMITATIONS.md](LIMITATIONS.md)（英文）。

## 构建

```
cargo build --release                                   # 带 PDF 和可选的 AI 命令
cargo build --release --no-default-features             # 两者都不带：小得多，而且完全没有联网的代码
cargo build --release --no-default-features --features pdf   # 带 PDF，没有联网的代码
```

需要 Rust 1.90 或更新版本。程序是 `target/release/analyze-anything`。

## 模糊测试

需要 nightly 工具链和 `cargo-fuzz`：

```
cargo +nightly fuzz run analyze fuzz/corpus/analyze crates/*/tests/data
```
