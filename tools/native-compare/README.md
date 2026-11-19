Checks this program's results against the tools that ship with macOS and Windows: `codesign`,
`hdiutil`, `pkgbuild` on macOS; `Get-AuthenticodeSignature` and `makecab` on Windows.

They run in the "Native comparison" GitHub Actions workflow (started by hand), on machines that
have those tools. Each script prints one line per check and exits non-zero if any check failed.

    python3 tools/native-compare/macos.py   path/to/aa
    python   tools/native-compare/windows.py path\to\aa.exe
