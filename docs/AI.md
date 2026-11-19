# AI 解读（可选）

`aa interpret` 把一份已经写好的报告交给语言模型，换回一段通俗的说明：这是什么、值得注意什么、接下来可以做什么。它不参与分析，报告本身不会被改动。

默认关闭：没有配置服务之前，程序不会连接任何地方。这也是整个程序里唯一会联网的部分。

```
aa analyze 某应用.ipa -o out
aa interpret out/report.json            # 写出 out/ai.json 和 out/ai.md，并把说明打印出来
```

Homebrew 安装后命令写作 `analyze-anything interpret …`。

## 配置模型

支持两类服务：

| `provider` | 说明 | 默认地址 | 默认的密钥环境变量 | 默认模型 |
|---|---|---|---|---|
| `anthropic` | Claude，使用 Anthropic 的 Messages API | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` | `claude-opus-5-5` |
| `openai-compatible` | 任何使用 OpenAI chat completions 协议的服务：OpenAI、各家网关、本机的模型服务（Ollama、LM Studio、vLLM 等） | `https://api.openai.com/v1` | `OPENAI_API_KEY` | 无，必须写 `model` |

配置写在 `~/.config/analyze-anything/config.toml`（Windows 是 `%APPDATA%\analyze-anything\config.toml`；也可以用环境变量 `AA_CONFIG` 或 `--config` 指定别的文件）：

```toml
# Claude
[ai]
provider = "anthropic"
model = "claude-opus-5-5"          # 可省略
# api_key_env = "ANTHROPIC_API_KEY"  # 可省略：存放密钥的环境变量的名字
```

```toml
# OpenAI 兼容的服务
[ai]
provider = "openai-compatible"
base_url = "https://api.example.com/v1"   # 会在后面加上 /chat/completions
model = "模型的名字"
api_key_env = "EXAMPLE_API_KEY"
```

```toml
# DeepSeek
[ai]
provider = "openai-compatible"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key_env = "DEEPSEEK_API_KEY"
```

```toml
# 本机的模型服务，不需要密钥
[ai]
provider = "openai-compatible"
base_url = "http://localhost:11434/v1"
model = "qwen3"
```

其他可选项：`max_findings`（最多发送多少条结论，默认 300）、`timeout_seconds`（等待回答的秒数，默认 600）。

密钥本身不写进配置文件，文件里只写**环境变量的名字**；写了 `api_key` 会被拒绝。给出了 `base_url` 而没有写 `api_key_env` 时，不带密钥发送请求（适合本机服务）。

每一项都可以在命令行上临时指定，优先于配置文件：

```
aa interpret out/report.json --provider anthropic --model claude-sonnet-5-5
aa interpret out/report.json --provider openai-compatible --base-url http://localhost:11434/v1 --model qwen3
aa interpret out/report.json --lang zh        # 用中文写；默认英文
aa interpret out/report.json --dry-run        # 只打印将要发送的内容，什么都不发
```

## 发送什么

只发送报告的摘要，不发送被分析的文件，也不发送证据里的原始值：

- 输入的名字和类型、覆盖度、局限；
- 每条结论的标题和正文（就是报告里印出来的那句话）、所在章节、严重度、置信度、所在文件的路径；
- 最严重的结论优先；同一条规则的“信息”级结论最多 12 条，总数最多 `max_findings` 条。

报告里的密钥类结论本来就是打过码的，发出去的也是打过码的文字。即便如此，摘要里仍有文件路径、网址、标识符等内容：**如果被分析的东西不该让第三方看到，请用本机的模型服务，或者不要使用这个功能。** `--dry-run` 可以先看清楚要发的每一个字。

## 可靠性是怎么保住的

- 模型被要求每句话都列出它依据的结论。程序逐句核对：没有引用结论的、引用了不存在或没发送过的结论的，整句丢掉，并在结果里记下丢了几句。
- 留下来的每句话后面都带结论 ID，用 `aa explain out/report.json <ID>` 可以看到那条结论和它的全部证据。
- 输出是单独的 `ai.json` 和 `ai.md`，开头写明“AI 生成”，不混进报告正文。报告是依据，两者不一致时以报告为准。
- 输出文件夹里有 `manifest.json` 时，新写的两个文件会登记进去，`aa verify` 照常通过。

核对只能保证每句话**指向了**真实存在的结论，不能保证模型对这条结论的**理解**是对的。请把它当作读报告的向导，而不是结论本身。同一份报告两次解读的措辞一般不同。

## 不需要这个功能

构建时去掉 `ai` 特性，程序里就没有任何联网的代码：

```
cargo build --release --no-default-features --features pdf
```

桌面版目前没有接入这个功能。
