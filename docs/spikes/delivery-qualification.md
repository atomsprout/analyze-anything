# Delivery qualification: 0.2 through 0.5

The candidate observations below are historical. The published preview.2 packages,
their exact qualification boundaries and the subsequent real-report/process review
are recorded in [LIMITATIONS.md](../LIMITATIONS.md#published-preview-and-report-workflow)
and [report-workflow.md](report-workflow.md). An earlier candidate check does not qualify
a different published installer.

## Earlier delivery baseline

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

## Combined implementation

[CI 45382506185](https://github.com/atomsprout/analyze-anything/actions/runs/45382506185)
at d047df8 passed all three core and desktop platforms and the advisory/license gate.
Windows WebView2 and Ubuntu 24.04 x64 WebKitGTK under Xvfb/D-Bus each passed 67
native-window checks. All three desktop jobs passed 38 Chromium/WebKit browser checks.

[Rehearsal 45382485314](https://github.com/atomsprout/analyze-anything/actions/runs/45382485314)
passed on the combined d047df8 implementation. The Unix CLI jobs passed, including
re-extracting each archive, comparing the executable bytes and self-testing the
extracted program. The Windows CLI was packaged and passed the automated checksum,
extracted self-test and static-CRT import gates. Windows portable/NSIS packaging also
passed. Both Linux x64/ARM64 runtime jobs verified the downloaded archive checksum and
self-tested its extracted program in Ubuntu 24.04 and Debian trixie-slim containers
with no network, a read-only root/program mount and writable temporary storage.
The release job was skipped: no tag or release was created.

The downloaded Windows ZIP passed its checksum, extracted CLI self-test and independent
Microsoft dumpbin/pefile regular-and-delay import checks on the development Windows
x64 host. Both readers returned the same seven OS DLLs listed above, with no separate
CRT dependency. Its hashes are:

| Item | SHA-256 |
|---|---|
| `analyze-anything-codex-artifact-understanding-x86_64-pc-windows-msvc.zip` | `bd1beeab868659acac6894da5ba52967182f76b50c72ae9be759c8fde00da248` |
| Extracted `analyze-anything.exe` | `0b8c6c9616f6b886d7459152a2968eb8a76a79646e904f9b4d76069059ed1dc9` |
| Desktop portable ZIP | `79d4bda93f42d7ec1a6943d2061a18e16c6f77aa865fd4759142cf82fd7367ab` |
| Desktop offline NSIS installer | `2604ddf0a7a7ac80e887447e50f27fb51010565bd9f892d9635050f1a451b3f4` |

The two desktop files were also downloaded and verified against their SHA256SUMS;
they were not installed in this final check. Local archive records remain under
ignored `out/milestone-02/run-45382485314/`. The offline Windows 10 guest was not
rerun with these archives.

The subsequent 4f78fe4 revision reconciled documentation. The only later code change,
9dab32b, suppresses a cancelled agent request's reply even during deadline shutdown
without extending its existing grace period. It changes neither packaging nor runtime
dependencies. [CI 45386227144](https://github.com/atomsprout/analyze-anything/actions/runs/45386227144)
passed all seven jobs on that revision; the local default-member `cargo test --release`
run and separate no-AI release agent/query integration tests also passed. See
[workflow qualification](report-workflows.md) for the regression cases. The rehearsal
archive above predates that cancellation correction; it is not a published release.
