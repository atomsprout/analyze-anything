# Delivery qualification for the 0.2/0.3 implementation

[CI run 45360964209](https://github.com/atomsprout/analyze-anything/actions/runs/45360964209)
at 2caf6d4 passed all three core-platform jobs, three desktop jobs and the advisory/license
gate. Linux Ubuntu 24.04 x64 WebKitGTK under Xvfb/D-Bus and Windows WebView2 each passed
67 native-window checks, including seven-format and complete-folder CLI parity. These
are scoped hosted checks, not physical-display acceptance of every Linux distribution.

[Release rehearsal 45360483004](https://github.com/atomsprout/analyze-anything/actions/runs/45360483004)
at 592e86d passed the four native build/test/self-test/package jobs, Windows desktop
packaging and both Linux packaged-runtime jobs. The subsequent 2caf6d4 commit changed
documentation only. The Linux x64/ARM64 archives passed checksum verification and the
CLI self-test in Ubuntu 24.04 and Debian trixie-slim userspaces with no network, a read-only
root filesystem, a read-only program mount and a writable temporary filesystem.

The earlier rehearsal at c16d090 caught a real x64 compatibility failure: its
ubuntu-latest build required GLIBC_2.43 and could not start in Ubuntu 24.04. Pinning the
release build to Ubuntu 24.04 corrected that failure in the successful rehearsal above.
This establishes those named runtime baselines, not compatibility with older glibc releases.

The Windows CLI ZIP from the successful rehearsal was downloaded, checked against its
SHA-256 sidecar, extracted and self-tested on the development Windows x64 host. Independent
PE inspection and Microsoft dumpbin agreed on its regular/delay-load DLL imports:

```
advapi32.dll
api-ms-win-core-synch-l1-2-0.dll
bcrypt.dll
bcryptprimitives.dll
kernel32.dll
ntdll.dll
ws2_32.dll
```

No VCRUNTIME, MSVCP or separate UCRT dependency is imported. The release's static-CRT setting
remains required, and `tools/release/check-windows-runtime.ps1` now enforces that dependency
contract on the extracted archive. This import check and local self-test do not replace
the separately recorded clean Windows 10 guest run of the earlier preview.2 candidate;
that guest was not rerun with this archive. No broader Windows-version claim is made here.

The release workflow additionally re-extracts Unix archives, compares their executable
bytes with the built program and runs the extracted program's self-test. That new step,
the automated Windows dependency gate, and the final combined 0.2–0.5 implementation
require another final-head rehearsal. Current local records remain under ignored
`out/milestone-02/run-45360483004/`.
