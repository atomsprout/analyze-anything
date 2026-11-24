# The optional AI interpretation

Once a report is written, a language model can explain it in plain words: what this is, what deserves attention, what you could do next. It takes no part in the analysis, and the report itself is never changed.

It is **off until you set it up**. Until then the program connects to nothing. This is also the only part of the program that sends anything anywhere.

```
analyze-anything ai api --provider anthropic --api-key-stdin   # once: choose who does it
analyze-anything App.ipa --ai         # analyze, then interpret
analyze-anything interpret out/       # or interpret a report that already exists
```

The interpretation is written next to the report as `ai.md` (to read) and `ai.json` (the same as data).

## Who does it

A model does not get one question and give one answer. It is shown a brief of the report and then looks things up in it, round after round, until it is ready to answer. Who runs that conversation is your choice:

| | Engine | Who runs the conversation | What it needs |
|---|---|---|---|
| 1 | `api` | This program, talking to a model service: Claude, or anything that speaks OpenAI's protocol | An API key |
| 2 | `claude` | Claude Code, the `claude` command | `claude` installed and signed in. No API key |
| 3 | `codex` | Codex, the `codex` command | `codex` installed and signed in. No API key |
| 4 | `ollama` | This program, talking to a model that Ollama runs on your machine | Ollama running, and a model pulled. No API key; nothing leaves the machine |

For anything else there is a fifth, `command`: a program of your own, described below.

Choose with `analyze-anything ai`:

```
analyze-anything ai api --provider anthropic --api-key-stdin
analyze-anything ai api --provider openai-compatible --base-url https://api.deepseek.com/v1 --model deepseek-chat --api-key-stdin
analyze-anything ai claude
analyze-anything ai codex
analyze-anything ai ollama --model qwen3
analyze-anything ai command -- my-agent --prompt {prompt_file} --mcp {mcp_config}
analyze-anything ai                   # show what is set up
analyze-anything ai off
```

`--api-key-stdin` asks for the key and keeps it in the configuration file. Add `--auto` to any of these to interpret after every analysis without writing `--ai`; `--no-ai` then skips it for one run.

### The configuration file

`analyze-anything ai` writes `~/.analyze-anything/config.toml` (`%USERPROFILE%\.analyze-anything\config.toml` on Windows; the environment variable `AA_CONFIG` or `--config` names another file). You can also edit it by hand:

```toml
[ai]
engine = "api"
provider = "anthropic"            # Claude through Anthropic's API
model = "claude-opus-5-5"         # optional; this is the default
api_key = "sk-ant-…"
```

```toml
[ai]
engine = "api"
provider = "openai-compatible"    # anything that speaks OpenAI's chat-completions protocol
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
api_key = "sk-…"
```

```toml
[ai]
engine = "claude"     # or "codex"
auto = false          # true: interpret after every analysis
```

```toml
[ai]
engine = "ollama"
model = "qwen3"                           # one that `ollama list` shows
# base_url = "http://localhost:11434/v1"  # the default
```

```toml
[ai]
engine = "command"
command = ["my-agent", "--prompt", "{prompt_file}", "--mcp", "{mcp_config}"]
```

Other settings: `max_turns` (how many rounds of questions the model may ask before it must answer; default 12), `timeout_seconds` (default 600), and `model` for the `claude` and `codex` engines when you want them to use a particular one.

**The API key.** Write it in the file as `api_key`, or keep it in an environment variable: `ANTHROPIC_API_KEY` for Anthropic, `OPENAI_API_KEY` for an OpenAI-compatible service, or the one you name with `api_key_env`. The variable wins over the file. The file is created readable by you alone, and the program warns when a file that holds a key can be read by others. The `ollama` engine never sends a key. With the `api` engine, a service at a `base_url` you gave, with no key anywhere, is asked without one; that suits other model servers of your own (LM Studio, vLLM and the like). A model, address and key written in the file belong to the service the file names: when `--engine` or `--provider` asks for another one, they are left out, so a key is never sent to a service it was not given for.

Flags on `interpret` override the file for one run: `--engine`, `--provider`, `--model`, `--base-url`, `--api-key-env`, and `--lang zh` to have it written in Chinese.

### A program of your own

The `command` engine starts your program in an empty folder. It receives the instructions and the brief on standard input, and must print its answer on standard output: the JSON object the instructions describe. In the command, `{prompt_file}` becomes a file holding the same text as standard input, `{report}` the report's path, and `{mcp_config}` a JSON file in the usual `mcpServers` form that says how to start the report's tool server.

## In the desktop app

A report in the desktop app has an **AI interpretation** button (View ▸ AI Interpretation, ⌘I) that opens a panel beside the report. The settings are the same file as the command line's; the app has no settings of its own, and where nothing is set up the panel says so and shows the commands above. Before anything is asked, the panel says who would be asked and that findings of the report, never the analyzed files, are handed over; nothing happens until you press **Interpret**.

The statements are shown as a model's, each followed by the findings it rests on; clicking one shows that finding in the report. The interpretation is kept with the report in the history, one per language, goes when the report is deleted, and is written as `ai.json` and `ai.md` into a folder exported afterwards.

Two things differ from a terminal. An app started from the Dock or the Finder is not given the shell's environment, so an API key has to be in the file (`--api-key-stdin` puts it there), not in an environment variable. And `claude`, `codex` or a command of your own is looked for in `~/.local/bin`, `~/.cargo/bin`, `~/bin`, `/opt/homebrew/bin` and `/usr/local/bin` besides the search path the app was given.

## What the model can see

The report, and only the report. The analyzed files are not sent and cannot be asked for.

- **The brief**, sent first: the input's name and kind, coverage, limitations, how many findings there are in each chapter and at each severity, and every finding above severity "info".
- **Three read-only tools** for the rest: `list_findings` (filter by chapter, severity or words), `get_finding` (one finding with its evidence: which file, where in it, the value that was read there, cut to 400 characters), and `list_files` (paths, sizes and types of the files of the input).

Findings about secrets are already redacted in the report, and that is what the model sees. Even so, the report holds file paths, addresses, identifiers and strings read from the analyzed files. **If what you analyze must not be seen by a third party, use the `ollama` engine, or do not use this.** `analyze-anything interpret out/ --dry-run` prints the instructions and the brief and sends nothing.

With the `claude`, `codex` and `command` engines the conversation is run by that program, which talks to whatever service it is signed in to, on that account's terms. This program starts it with only the report's tools allowed: no file access, no commands, no other tool servers. For Claude Code that is `--tools ""`, `--strict-mcp-config` and an allow-list of the seven read-only report tools; for Codex, its read-only sandbox.

## How it stays honest

- The model is told to cite, for every statement, the findings it rests on. The program checks each statement: one that cites nothing, or cites a finding that is not in the report, is dropped whole, and the result records how many were dropped.
- Every statement that stays ends with the ids of its findings. `analyze-anything explain out/report.json <id>` shows that finding and all its evidence.
- The output is its own pair of files, headed "AI-generated", and is not mixed into the report. The report is the authority: where the two differ, the report is right.
- When the output folder has a `manifest.json`, the two new files are added to it, so `verify` still passes.

The check makes sure every statement **points at** a real finding. It cannot make sure the model **understood** that finding, or that it drew no conclusion of its own from several of them. Treat the interpretation as a guide to the report, not as a finding. Two interpretations of one report will usually be worded differently.

## What has been tried

| | |
|---|---|
| `api`, OpenAI-compatible | Run against a real service (DeepSeek), on a real 456-finding IPA report among others: the model made 17 lookups and every statement it returned cited existing findings |
| `api`, Anthropic | Run against the real service with `claude-opus-5-5`, on the same 456-finding IPA report: the model made 9 lookups and every statement it returned cited existing findings |
| `claude` | Run for real with a signed-in Claude Code on the same 456-finding IPA report: a full answer in about half a minute, every statement citing existing findings. Lookups made through the tool server are not counted for this engine |
| `codex` | Run for real with a signed-in Codex CLI 0.170 on the same report: a full answer in under a minute, every statement citing existing findings. Lookups are not counted for this engine either |
| `ollama` | Run against a real Ollama (0.40) with `qwen3:4b`, on the same 456-finding IPA report: the request with the tools was accepted, the model answered from the brief without looking anything up, and every statement it returned cited existing findings. It took under four minutes on an Apple silicon Mac. Whether a model uses the tools depends on the model; one that cannot take them is asked with the brief alone |
| `command` | Run for real with a stand-in agent that speaks to the tool server |
| desktop app | The panel was run in the real window with a stand-in program and, with a bare search path as when started from the Dock, with a signed-in Claude Code on the 456-finding IPA report: 19 statements, none dropped, kept, shown and exported |

A model or service that does not support tools is noticed on the first request, and is then asked once with the brief alone.

## For agents: the tool server

`analyze-anything mcp out/report.json` serves the same seven read-only report tools over the Model Context Protocol on standard input and output. Any agent that speaks MCP can use it to read a report on its own initiative, apart from the interpretation described here.

The offline queries and this read-only server are available without the AI feature. See [query filters and pagination](QUERY.md).

## Without it

Build without the `ai` feature and the program has no network code at all:

```
cargo build --release --no-default-features --features pdf
```

The desktop app does not include the AI interpretation.
