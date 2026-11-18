"""Writes an Electron asar archive from a few in-memory files, following the format directly:
a Chromium Pickle holding the JSON header, then the file contents back to back."""
import hashlib, json, struct, sys

FILES = {
    "package.json": json.dumps({"name": "fixture-electron", "version": "4.5.6", "main": "main.js",
                                "dependencies": {"left-pad": "1.3.0", "express": "^4.18.0"}}, indent=1).encode(),
    "main.js": b"const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true,"
               b" contextIsolation: false, webSecurity: false, sandbox: false } });\n",
    "lib/util.js": b"module.exports = () => 42;\n",
}

def entry(data, offset):
    block = 4 * 1024 * 1024
    return {"size": len(data), "offset": str(offset),
            "integrity": {"algorithm": "SHA256", "hash": hashlib.sha256(data).hexdigest(), "blockSize": block,
                          "blocks": [hashlib.sha256(data[i:i + block]).hexdigest() for i in range(0, max(len(data), 1), block)]}}

tree, body, offset = {"files": {}}, b"", 0
for path, data in FILES.items():
    node = tree
    parts = path.split("/")
    for part in parts[:-1]:
        node = node["files"].setdefault(part, {"files": {}})
    node["files"][parts[-1]] = entry(data, offset)
    body += data
    offset += len(data)

header = json.dumps(tree, separators=(",", ":")).encode()
padded = header + b"\0" * (-len(header) % 4)
# Pickle of a string: payload size, string length, bytes. Wrapped in a pickle holding its size.
string_pickle = struct.pack("<II", 4 + len(padded), len(header)) + padded
size_pickle = struct.pack("<II", 4, len(string_pickle))
open(sys.argv[1], "wb").write(size_pickle + string_pickle + body)
