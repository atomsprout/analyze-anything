# Analyze Anything

输入电脑上的任意产物（IPA / APK / Windows 安装包与程序目录 / macOS .app / DMG / 压缩包 / 文件夹 / 任意文件），输出一份可靠、可溯源、多维度的分析报告（PDF / HTML / Markdown / TXT）。

使用 Rust 开发，纯静态分析，离线可用。先做命令行版本，之后做桌面版（Tauri）。

- [docs/PLAN.md](docs/PLAN.md) — 最终规划
- [docs/RESEARCH.md](docs/RESEARCH.md) — 调研记录

## 当前进度

M0 进行中。已经能用的部分：对任意文件或文件夹输出 JSON 和 Markdown 报告，内容包括每个文件的大小、MD5 / SHA-1 / SHA-256、识别类型和熵，以及两条通用规则的结论。还不会解包，也不解析任何具体格式；TXT、HTML、PDF 输出在 M1。

## 使用

```
cargo build --release
target/release/aa analyze <文件或文件夹> -o out --format json,md --lang zh
target/release/aa render out/report.json -o out2 --format md --lang en
```

被分析的输入只会被读取，不会被执行。退出码：0 完成，1 无法运行，2 已运行但分析不完整（原因写在报告的"局限"里）。

## 开发

```
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```
