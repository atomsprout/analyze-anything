"""Compares Mach-O imports and exports with dyld_info and nm on binaries already on this Mac.

    python3 tools/native-compare/macos_symbols.py path/to/analyze-anything /bin/ls /Applications/Some.app/Contents/MacOS/Some [...]

For every architecture slice of every file, what this program reports in `binary.imports` and
`binary.exports` must agree with the system tools:

- exported names = `dyld_info -exports` (the export trie) united with `nm -gU` (the symbol table);
- imported names = what dyld binds, united with `nm -u`. What dyld binds is `dyld_info -imports`
  for an image with chained fixups, and the symbols of `objdump --macho --bind --lazy-bind
  --weak-bind` for one with bind opcodes (for those `dyld_info -imports` prints the symbol table);
- `by_source` holds, per source, as many names as the matching tool prints;
- the library of each import is the one `dyld_info` names. One difference is expected and
  counted apart: a symbol dyld finds by weak-definition coalescing, for which the symbol table
  names the library that defines it; the report keeps the library.

The facts keep at most 2000 symbols per list. Counts are compared in full; names and libraries
are compared for the symbols kept (all of them when the list is not truncated). The ignored test
`crosscheck_dyld_info` in crates/aa-binary compares whole lists. Nothing is downloaded or run.
"""
import subprocess
import sys

from common import analyze, check, finish

SPECIAL = {
    "(weak lookup)": "<weak-def-coalesce>",
    "(this image)": "<this-image>",
    "(main executable)": "<main-executable>",
    "(dynamic lookup)": "<flat-namespace>",
}


def tool(*arguments):
    return subprocess.run(["xcrun", *arguments], capture_output=True, text=True, errors="replace").stdout


def leaves(library):
    """The names dyld_info may print for a library: the leaf without `.dylib` and one version suffix."""
    if library in SPECIAL:
        return {SPECIAL[library]}
    base = (library or "").rsplit("/", 1)[-1]
    if base.endswith(".dylib"):
        base = base[: -len(".dylib")]
    return {base, base.rsplit(".", 1)[0]}


def dyld_info(path):
    """Per slice, in file order: the exported names, and {imported name: {library, ...}}."""
    slices, section = [], None
    for line in tool("dyld_info", "-exports", "-imports", path).splitlines():
        words = line.split()
        if line.startswith(path) and line.endswith("]:"):
            slices.append((set(), {}))
        elif words in (["-exports:"], ["-imports:"]):
            section = words[0]
        elif slices and len(words) >= 2 and words != ["offset", "symbol"]:
            if section == "-exports:":
                slices[-1][0].add(words[1])
            else:
                name = words[1] if words[0].startswith("0x") else words[0]
                library = line.rsplit("(from ", 1)[1].rstrip(")") if "(from " in line else ""
                slices[-1][1].setdefault(name, set()).add(library)
    return slices


def bind_opcodes(path):
    """Per slice, in file order: the symbols the bind, lazy bind and weak bind opcodes name."""
    slices = []
    for line in tool("objdump", "--macho", "--arch", "all", "--bind", "--lazy-bind", "--weak-bind", path).splitlines():
        words = [word for word in line.split() if word != "(weak_import)"]  # a note after the symbol
        if line.startswith(path) and line.endswith(":"):
            slices.append(set())
        elif slices and len(words) >= 5 and words[0] != "segment":
            slices[-1].add(words[-1])
    return slices


def nm(path, flag):
    """Per slice, in file order: the names `nm <flag>` prints."""
    slices = []
    for line in tool("nm", "-arch", "all", flag, path).splitlines():
        if line.endswith("):") and "(for architecture " in line:
            slices.append(set())
        elif line:
            if not slices:
                slices.append(set())
            slices[-1].add(line)
    return slices


def slices_of(report):
    """The facts of every Mach-O slice of the analyzed file, as (label, facts)."""
    facts = report["artifacts"][0]["facts"]
    if "binary.slices" in facts:
        return [(s["arch"], s) for s in facts["binary.slices"]]
    return [(facts["binary.header"]["arch"], {key[len("binary."):]: value for key, value in facts.items() if key.startswith("binary.")})]


def compare(aa, path):
    ours = slices_of(analyze(aa, path))
    theirs = dyld_info(path)
    defined, undefined, opcodes = nm(path, "-gUj"), nm(path, "-uj"), bind_opcodes(path)
    check(f"{path}: {len(theirs)} slices", len(ours) == len(theirs), [label for label, _ in ours])
    for index, ((arch, facts), (trie, binds)) in enumerate(zip(ours, theirs)):
        name = f"{path} [{arch}]"
        if "imports" not in facts or "exports" not in facts:
            check(f"{name}: imports and exports reported", False, sorted(facts))
            continue
        table = (defined[index] if index < len(defined) else set(), undefined[index] if index < len(undefined) else set())
        by_opcodes = "bind-opcodes" in facts["imports"]["sources"]
        bound = (opcodes[index] if index < len(opcodes) else set()) if by_opcodes else set(binds)
        for what, fact, dyld_names, nm_names in (
            ("exports", facts["exports"], trie, table[0]),
            ("imports", facts["imports"], bound, table[1]),
        ):
            expected = dyld_names | nm_names
            kept = {symbol["name"] for symbol in fact["symbols"]}
            check(f"{name}: {len(expected)} {what} counted", fact["count"] == len(expected), fact["count"])
            if fact["truncated"]:
                check(f"{name}: the {len(kept)} {what} kept are known to the tools", kept <= expected, sorted(kept - expected)[:10])
            else:
                detail = {"only ours": sorted(kept - expected)[:10], "only the tools": sorted(expected - kept)[:10]}
                check(f"{name}: {len(expected)} {what} names identical", kept == expected, detail)
            held = fact["by_source"]
            from_dyld = sum(held.get(source, 0) for source in ("export-trie", "chained-fixups", "bind-opcodes"))
            check(f"{name}: {len(dyld_names)} {what} from dyld tables ({', '.join(fact['sources'])})", from_dyld == len(dyld_names), held)
            check(f"{name}: {len(nm_names)} {what} from the symbol table", held.get("symtab", 0) == len(nm_names), held)
        same, coalesced, different = 0, 0, []
        for symbol in facts["imports"]["symbols"]:
            libraries = binds.get(symbol["name"])
            if libraries is None:
                continue
            if leaves(symbol["library"]) & libraries:
                same += 1
            elif libraries == {"<weak-def-coalesce>"} and symbol["name"] in table[1]:
                coalesced += 1
            else:
                different.append((symbol["name"], symbol["library"], sorted(libraries)))
        note = f", {coalesced} coalesced symbols keep the library the symbol table names" if coalesced else ""
        check(f"{name}: {same} import libraries identical{note}", not different, different[:10])


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    for path in sys.argv[2:]:
        try:
            compare(sys.argv[1], path)
        except Exception as error:  # one unreadable file must not hide the others
            check(f"{path}: compared", False, error)
    finish()


if __name__ == "__main__":
    main()
