# 桌面版

同一套分析引擎的图形界面：拖入文件 → 看进度 → 读报告 → 看证据字节 → 导出 → 历史与对比。不新增分析能力，同一个输入在桌面版和 `aa` 里得到字节相同的报告。规划见 [PLAN-DESKTOP.md](PLAN-DESKTOP.md)。

目前只有 macOS（Apple 芯片）版本。

## 安装

```
brew install --cask atomsprout/tap/analyze-anything-desktop   # 桌面版
brew install atomsprout/tap/analyze-anything                  # 命令行 aa
```

两者互不依赖，可以只装一个。

## 结构

| 位置 | 内容 |
|---|---|
| `crates/aa-engine` | 分析会话（分析结束后仍能按范围读任意文件的字节）、逐文件进度、可序列化的事件 |
| `crates/aa-worker` | 工作子进程：消息协议（每行一个 JSON）、服务端循环、客户端（能确定地结束子进程并清理它的临时目录） |
| `crates/aa-app` | 不依赖界面的应用层：各格式导出（命令行也用它）、历史记录、通过工作进程运行一次分析 |
| `crates/aa-export` 的 `diff` | 两份报告的对比，`aa diff` 和桌面版共用 |
| `apps/desktop/src-tauri` | Tauri 外壳：窗口、菜单、命令、`report://` 协议、自检模式 |
| `apps/desktop/src` | 页面：TypeScript，不用界面框架 |

桌面程序带 `--worker` 参数启动自己就是工作进程，不另外分发可执行文件。界面进程从不在自己的进程里分析任何东西。

报告视图就是命令行写出的 `report.html`，放在只允许运行脚本的沙箱框架里，通过 `report://localhost/<id>` 加载。它带着自己的严格内容安全策略，访问不到外壳的任何命令；它只会向外壳发一种消息（“显示这个文件的这段字节”），外壳收到后再校验一遍。

页面能调用的命令全部列在 `src-tauri/build.rs`，并在 `capabilities/default.json` 里逐条放行；没有开放文件系统、执行程序或联网的能力。页面只能请求分析用户通过对话框、拖放或“打开方式”选中的路径。

## 开发

```
cd apps/desktop
npm ci
npm run tauri dev          # 开发模式运行
npm test                   # 页面逻辑的单元测试（Vitest）
npm run fixture            # 生成浏览器测试用的样例报告
npm run test:browser       # 在 WebKit 和 Chromium 里测页面（Playwright，后端用模拟数据）
```

工作区的默认成员不含桌面版，`cargo build` / `cargo test` 不会编译它；需要时用 `-p aa-desktop`。

## 测试分层

| 层 | 在哪里 |
|---|---|
| 分析会话、读字节、进度事件、遗留临时目录清理 | `crates/aa-engine/tests/analyze.rs` |
| 消息协议往返、畸形消息、真实子进程的完成 / 取消 / 卡死强杀 / 崩溃清理 | `crates/aa-worker/tests/worker.rs` |
| 运行控制、各格式导出、历史记录 | `crates/aa-app/tests/app.rs` |
| 对比 | `crates/aa-export/src/diff.rs` |
| 页面逻辑（文字、十六进制视图的换算、进度） | `apps/desktop/tests/format.test.ts` |
| 页面与真实报告页的配合（沙箱框架、点击证据发消息、语言同步、导出、历史、对比） | `apps/desktop/tests/browser/app.spec.ts` |
| 真实窗口里的整机流程，以及导出与命令行逐字节一致 | `tools/desktop-check/check.py` |

### 自检模式

macOS 的系统 WebView 没有可用的自动化驱动，所以应用可以自己检查自己：带环境变量 `AA_DESKTOP_SELFTEST=<计划文件>` 启动时，页面像用户一样点击自己的界面走完全流程，记下看到的结果，应用把结果写到文件后退出。这个模式下不弹对话框：“打开”依次返回计划里的输入，“保存”写进计划指定的文件夹。不带这个变量时，相关的三个命令一律拒绝。

```
python3 tools/desktop-check/check.py \
    "target/aarch64-apple-darwin/release/bundle/macos/Analyze Anything.app/Contents/MacOS/analyze-anything" \
    target/release/aa  旧版本.ipa 新版本.ipa --slow 一个很大的.dmg
```

它检查：页面的内容安全策略生效（注入的脚本不运行、不能把文本当代码执行、连不上网络）、分析与进度、报告在框架里加载、十六进制视图显示的字节与文件一致并标出证据范围、跳转偏移、拒绝报告里没有的路径、7 种格式和“全部格式到文件夹”的导出、语言和外观切换、历史的打开与删除、历史报告说明为什么看不了字节、对比的数字、取消后回到主页且不留记录；退出后没有遗留的工作进程和临时文件；每个导出文件与 `aa` 对同一输入写出的文件逐字节相同，`aa verify` 接受导出的文件夹。

### 仍需人工检查的三处

自检走的是页面，下面三处经过系统界面，没有自动化覆盖：

- 原生菜单栏：各项能点、快捷键生效（⌘O、⇧⌘O、⌘E、⇧⌘E、⇧⌘H）。
- 拖放：把文件拖到窗口上，放置区高亮，松开后开始分析。
- 系统的打开 / 保存对话框，以及在 Finder 里用“打开方式”打开文件。

## 发布

```
tools/release/macos.sh
```

构建 Apple 芯片的 `aa`（tar.gz）和桌面版（DMG），用 Developer ID 证书签名、启用 hardened runtime，并提交 Apple 公证。需要环境变量 `APPLE_ID`、`APPLE_TEAM_ID`、`APPLE_SPECIFIC_PASSWORD`，以及钥匙串里该团队的 “Developer ID Application” 证书。产物写到 `dist/release`，脚本本身不上传任何东西。

发布包放在公开仓库 [atomsprout/analyze-anything-release](https://github.com/atomsprout/analyze-anything-release) 的 Releases 里，Homebrew 的定义在 [atomsprout/homebrew-tap](https://github.com/atomsprout/homebrew-tap)。

## 数据放在哪里

- 历史记录：`~/Library/Application Support/com.atomsprout.analyze-anything/history/`，每次分析一个文件夹，里面是 `report.json`、`manifest.json` 和 `entry.json`（名称、时间、输入的 SHA-256、原文件路径）。不保存被分析的文件，也不保存解包出的内容。
- 临时文件：`~/Library/Caches/com.atomsprout.analyze-anything/scratch/`，分析期间解包出的大文件。关闭报告、开始下一次分析或退出时删除；应用被强行结束后，下次启动时清理。
- 环境变量 `AA_DESKTOP_DATA_DIR` 可以把这两处改到别的文件夹，用于试用而不影响真实的历史。
