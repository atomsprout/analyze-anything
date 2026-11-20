#!/usr/bin/env python3
"""Makes the website's examples: real reports about public releases of open-source software.

    tools/site/examples.py

For each sample below it downloads the file from the project's own address (kept in
target/site-samples, and checked against the recorded SHA-256), analyzes it with
`analyze-anything`, puts the report into site/examples/ as a PDF, and writes the cards between the two "examples" marks of site/index.html from what the reports say.

The reports are not kept in git (they can be made again from the same files);
`tools/site/publish.sh` runs this before it publishes. The samples are only read, never run.
"""
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, "target", "site-samples")
SITE = os.path.join(ROOT, "site")
BEGIN, END = "<!-- examples:begin (written by tools/site/examples.py) -->", "<!-- examples:end -->"

# name, colour, what kind of thing (en, zh), the project and version, its page, the file's address, its SHA-256
SAMPLES = [
    ("ipa", "sky", ("iOS app · IPA", "iOS 应用 · IPA"), "iSH 1.3.2", "https://ish.app",
     "https://github.com/ish-app/ish/releases/download/builds/494/iSH.ipa",
     "74b22a209340c5dc6e94975d8c07e4814ae2299dfe0b62cfa22640090d80f36c"),
    ("apk", "lime", ("Android app · APK", "Android 应用 · APK"), "F-Droid 2.0.3", "https://f-droid.org",
     "https://f-droid.org/F-Droid.apk",
     "dac55a0d17b1edf7e7286b48cfbd70c7c52fbb32a00af062c68830a437c47959"),
    ("dmg", "sun", ("macOS disk image · DMG", "macOS 磁盘映像 · DMG"), "Rectangle 2.0.4", "https://rectangleapp.com",
     "https://github.com/rxhanson/Rectangle/releases/download/v2.0.4/Rectangle2.0.4.dmg",
     "9f820a2e56bd2c27cdda4fb4556de3cbcfcbac052d9eeb2179d49e2dae277abc"),
    ("pkg", "orange", ("macOS installer · pkg", "macOS 安装包 · pkg"), "Node.js 22.11.0", "https://nodejs.org",
     "https://nodejs.org/dist/v22.11.0/node-v22.11.0.pkg",
     "8d658eda7699d580ccc268ca8a40ced5aeecef5bb4d19c4187e92eebac5d68ec"),
    ("nsis", "coral", ("Windows installer · NSIS", "Windows 安装程序 · NSIS"), "Notepad++ 8.9.9.1", "https://notepad-plus-plus.org",
     "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.9.1/npp.8.9.9.1.Installer.x64.exe",
     "ce3267f5c4e7e42f847e00f4b20234da6150647203033cdde34a69593efc3152"),
    ("msi", "pink", ("Windows installer · MSI", "Windows 安装程序 · MSI"), "7-Zip 24.08", "https://www.7-zip.org",
     "https://www.7-zip.org/a/7z2408-x64.msi",
     "98330e7e6db3507b444d576dc437a9ac4d82333a88a6bb6ef36a91fe3d85fa92"),
    ("linux", "sky", ("Linux program · tar.gz", "Linux 程序 · tar.gz"), "ripgrep 15.2.0", "https://github.com/BurntSushi/ripgrep",
     "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz",
     "33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c"),
]

# Overview findings worth a line on a card, in this order; the first three a report has are shown.
HEADLINES = [
    "overview.kind-", "overview.apple-distribution", "overview.apple-developer-id", "overview.android-signer", "overview.win-signed",
    "overview.win-inner-signers", "overview.installer-contents", "overview.architectures", "overview.android-sdk", "overview.apple-bundles",
]
SEVERITIES = ["high", "medium", "low"]
WORDS = {
    "high": ("High", "高"), "medium": ("Medium", "中"), "low": ("Low", "低"),
    "input": ("Input", "输入"), "output": ("Output", "输出"),
    "pdf": ("Open the PDF report", "打开 PDF 报告"), "from": ("official download", "官方下载"), "pages": ("pages", "页"),
}


def table(name):
    """A word table of `aa_core::fill`, read from its source so that this copy cannot fall behind."""
    source = open(os.path.join(ROOT, "crates", "aa-core", "src", "lib.rs"), encoding="utf-8").read()
    body = source.split(f"const {name}:", 1)[1].split("];", 1)[0]
    return re.findall(r'\("([^"]+)", "([^"]+)"\)', body) if "(" in body.split("=", 1)[1] else re.findall(r'"([^"]+)"', body.split("=", 1)[1])


NOUNS, VERBS, NOT_DESCRIBING = dict(table("NOUNS")), dict(table("VERBS")), set(table("NOT_DESCRIBING"))


def singular(tail):
    """What `aa_core::fill` writes after a count of one: the noun, and the verb after it, for one."""
    written, rest = "", tail
    for _ in range(4):
        found = re.match(r" ([A-Za-z0-9-]+)", rest)
        if not found:
            return None
        word, after = found.group(1), rest[found.end():]
        if word in NOUNS:
            written += " " + NOUNS[word]
            verb = re.match(r" ([A-Za-z]+)", after)
            if verb and verb.group(1) in VERBS:
                return written + " " + VERBS[verb.group(1)], after[verb.end():]
            return written, after
        if word in NOT_DESCRIBING:
            return None
        written, rest = written + " " + word, after
    return None


def analyzer():
    built = os.path.join(ROOT, "target", "release", "analyze-anything")
    found = built if os.path.exists(built) else shutil.which("analyze-anything")
    if not found:
        sys.exit("no analyze-anything: build it (cargo build --release -p aa-cli) or install it")
    return found


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(name, url, wanted):
    folder = os.path.join(CACHE, name)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, url.rsplit("/", 1)[1])
    if not (os.path.exists(path) and sha256(path) == wanted):
        print(f"downloading {url}", flush=True)
        request = urllib.request.Request(url, headers={"User-Agent": "analyze-anything-site"})
        with urllib.request.urlopen(request, timeout=300) as response, open(path + ".part", "wb") as out:
            shutil.copyfileobj(response, out)
        os.replace(path + ".part", path)
    got = sha256(path)
    if got != wanted:
        sys.exit(f"{path}: SHA-256 is {got}, not the recorded {wanted}; the address now serves another file")
    return path


def fill(template, params):
    """The text of a rule with a finding's values, as `aa_core::fill` writes it."""
    out, rest = "", template
    while "{" in rest:
        before, after = rest.split("{", 1)
        out += before
        name, close, tail = after.partition("}")
        if not close or name not in params:
            out, rest = out + "{", after
            continue
        value = params[name]
        out += value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        if value == 1 and not isinstance(value, bool):
            agreed = singular(tail)
            if agreed:
                out, tail = out + agreed[0], agreed[1]
        rest = tail
    return out + rest


def first_sentence(text, limit=230):
    cut = re.split(r"(?<=[.。])\s|(?<=。)", text, maxsplit=1)[0].strip()
    return cut if len(cut) <= limit else cut[: limit - 1].rstrip() + "…"


def size_text(count):
    for unit, scale in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if count >= scale:
            return f"{count / scale:.1f} {unit}"
    return f"{count} B"


def both(en, zh):
    """The website is in English; the other wording is kept beside it should that change."""
    return en


def card(sample, path, report, pdf, pages):
    name, colour, kind, product, page, url, digest = sample
    rules, findings = report["rules"], report["findings"]
    esc = html.escape

    def said(finding, lang):
        return first_sentence(fill(rules[finding["rule"]][f"text_{lang}"], finding["params"]))

    overview = [f for f in findings if f["section"] == "overview"]
    lines = []
    for wanted in HEADLINES:
        for finding in overview:
            if finding["rule"].startswith(wanted) and len(lines) < 2:
                lines.append(f"<li>{both(esc(said(finding, 'en')), esc(said(finding, 'zh')))}</li>")
    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in SEVERITIES + ["info"]}
    numbers_en = f"{len(report['artifacts']):,} files read · {len(findings):,} findings: " + ", ".join(
        [f"{counts[level]} {level}" for level in SEVERITIES if counts[level]] + [f"{counts['info']} neutral facts"])
    numbers_zh = f"读了 {len(report['artifacts']):,} 个文件 · {len(findings):,} 条结论：" + "，".join(
        [f"{WORDS[level][1]} {counts[level]}" for level in SEVERITIES if counts[level]] + [f"中性事实 {counts['info']}"])

    file_name = os.path.basename(path)
    return f"""      <article class="ex c-{colour}">
        <div class="tags"><span class="tag sec">{both(esc(kind[0]), esc(kind[1]))}</span></div>
        <h3><a href="{esc(page)}" target="_blank" rel="noopener">{esc(product)}</a></h3>
        <div class="ex-io"><b>{both(*WORDS['input'])}</b>
          <span class="mono">$ analyze-anything {esc(file_name)}</span>
          <span class="mono dim">{size_text(os.path.getsize(path))} · sha256 {digest[:12]}… · <a href="{esc(url)}" target="_blank" rel="noopener">{both(*WORDS['from'])}</a></span>
        </div>
        <div class="ex-out"><b>{both(*WORDS['output'])}</b>
          <ul>
{chr(10).join('            ' + line for line in lines)}
          </ul>
          <p class="ex-count">{both(esc(numbers_en), esc(numbers_zh))}</p>
        </div>
        <div class="ex-links"><a class="btn" href="examples/{name}.pdf" target="_blank" rel="noopener">{both(*WORDS['pdf'])}</a><span class="dim">PDF · {pages} {both(*WORDS['pages'])} · {size_text(os.path.getsize(pdf))}</span></div>
      </article>"""


def main():
    tool = analyzer()
    cards = []
    examples = os.path.join(SITE, "examples")
    shutil.rmtree(examples, ignore_errors=True)
    os.makedirs(examples)
    for sample in SAMPLES:
        name, url, digest = sample[0], sample[5], sample[6]
        path = fetch(name, url, digest)
        out = os.path.join(CACHE, name, "out")
        shutil.rmtree(out, ignore_errors=True)
        # Analyzed in its own folder, so that the report names the file and nothing of this machine.
        done = subprocess.run([tool, "analyze", os.path.basename(path), "-o", out, "--format", "pdf,json", "--lang", "en", "--no-ai"],
                              cwd=os.path.dirname(path), capture_output=True, text=True)
        if not os.path.exists(os.path.join(out, "report.pdf")):
            sys.exit(f"{name}: the analysis did not write a report: {done.stderr[-500:]}")
        with open(os.path.join(out, "report.json"), encoding="utf-8") as handle:
            text = handle.read()
        if os.path.expanduser("~") in text or CACHE in text:
            sys.exit(f"the report about {name} names a folder of this machine; not publishing that")
        report = json.loads(text)
        pdf = os.path.join(examples, name + ".pdf")
        shutil.copyfile(os.path.join(out, "report.pdf"), pdf)
        with open(pdf, "rb") as handle:
            pages = len(re.findall(rb"/Type\s*/Page[^s]", handle.read()))
        cards.append(card(sample, path, report, pdf, pages))
        print(f"{name}: {len(report['findings'])} findings about {os.path.basename(path)}, {pages} pages", flush=True)

    index = os.path.join(SITE, "index.html")
    page = open(index, encoding="utf-8").read()
    if BEGIN not in page or END not in page:
        sys.exit("site/index.html has no examples marks")
    head, rest = page.split(BEGIN, 1)
    page = head + BEGIN + "\n" + "\n".join(cards) + "\n      " + END + rest.split(END, 1)[1]
    with open(index, "w", encoding="utf-8") as handle:
        handle.write(page)
    print("site/index.html and site/examples/ are up to date")


main()
