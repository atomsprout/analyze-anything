# Analyze Anything

输入电脑上的任意产物（IPA / APK / Windows 安装包与程序目录 / macOS .app / DMG / pkg / 压缩包 / 文件夹 / 任意文件），输出一份可靠、可溯源、多维度的分析报告：PDF、HTML、Markdown、TXT，以及 JSON、SARIF、CycloneDX。

使用 Rust 开发，纯静态分析，离线可用。被分析的输入只会被读取，不会被执行。

有两种用法，共用同一套分析引擎，同一个输入得到字节相同的报告：

- **命令行 `aa`**：`aa analyze <文件或文件夹> -o out`
- **桌面版**（macOS）：拖入文件，看进度，读报告，点开证据看字节，导出，查看历史并对比两个版本。

## 安装（macOS，Apple 芯片）

```
brew install atomsprout/tap/analyze-anything                  # 命令行 aa
brew install --cask atomsprout/tap/analyze-anything-desktop   # 桌面版
```

两者互不依赖。其他平台的命令行从源码构建：

```
cargo build --release
target/release/aa analyze <文件或文件夹> -o out
```

每条结论都带证据（来自哪个文件、哪个位置、读到了什么）和置信度，没能分析的部分会如实列在报告的“覆盖度与局限”里。

## 文档

- [docs/USAGE.md](docs/USAGE.md) — 使用说明
- [docs/DESKTOP.md](docs/DESKTOP.md) — 桌面版：结构、开发、测试、发布
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — 已知局限
- [docs/TODO.md](docs/TODO.md) — 剩余待办
- [docs/PLAN.md](docs/PLAN.md) — 规划
- [docs/PLAN-DESKTOP.md](docs/PLAN-DESKTOP.md) — 第二阶段规划：桌面版
- [docs/RESEARCH.md](docs/RESEARCH.md) — 调研记录
- [docs/ANALYZERS.md](docs/ANALYZERS.md) — 如何添加一种格式（英文）
- [docs/spikes/](docs/spikes/) — 技术验证记录：PDF、DMG、NSIS、APK 签名、桌面版

## 开发

```
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。内嵌字体（Noto Sans SC、JetBrains Mono）使用 SIL Open Font License，许可证文件在 `crates/aa-report/fonts/`。

仅用于分析你有权分析的对象。
