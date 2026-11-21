# Independent Windows driver-package checks

W5 remains open. This is one pinned third-party built-driver snapshot, alongside the
project-generated catalog/package fixtures and Microsoft's source INF samples. It is
not a general driver-compatibility or installation qualification.

## Source and scope

The input is `Drivers/x64` from [dorssel/usbipd-win v5.3.0](https://github.com/dorssel/usbipd-win/tree/aa3db8b82c4cb5071fd31bc54211606c70886912/Drivers/x64),
commit `aa3db8b82c4cb5071fd31bc54211606c70886912`. The checked files are:

| File | Bytes | SHA-256 |
|---|---:|---|
| VBoxUSB.cat | 11974 | `021addb8c696fb291a93b3e398cf1f7d3f9d9a4e7cf669360d3d7e1f00c08299` |
| VBoxUSB.inf | 2826 | `841ad3678046b54b1e980c41744da9f64ca7d6e090cad62a661734deadf26189` |
| VBoxUSB.sys | 181728 | `06cee818949d6dce18e6ec291b8ac521a5f0c168c792be8eacd7a8ae99d8fdf9` |

The upstream `.license` sidecars declare GPL-3.0-only and Oracle copyright for the
driver/INF (the INF text also offers CDDL). These third-party bytes are external local
test inputs, not redistributed in this checkout or linked into the program. See the
[upstream license declaration](https://github.com/dorssel/usbipd-win/blob/aa3db8b82c4cb5071fd31bc54211606c70886912/Drivers/x64/VBoxUSB.sys.license).
Only project-authored catalog fixtures and native reference snapshots are added to the
repository for portable regression tests. No installer, driver, service, registry
operation, catalog registration or certificate import is requested by the check.

## What was compared

On the Windows x64 development host with SDK 10.0.26100.0:

- Read-only SetupAPI field access matched all 44 projected INF fields.
- CryptCAT enumerated four members. Each carries File and OSAttr attributes under the
  same repeatable CAT_NAMEVALUE OID. Names, flags, value byte lengths/digests and text
  agree with the reader. The two explicit SHA-256 indirect digests and SIP GUIDs agree;
  the other two compatibility entries remain without a synthesized explicit digest.
- Signature-only SignedCms and the reader agree on the catalog's content/signature
  integrity. This does not check certificate validity, timestamp validity or Windows trust.
- CryptCATAdminCalcHashFromFileHandle2 agrees with the SYS PE digest. This is different
  from its ordinary SHA-256 shown above; ordinary hashing cannot substitute for SIP hashing.
- The pinned supplied INF's bytes do not match the catalog's flat-file digest. SignTool
  likewise did not find that supplied INF in the explicit catalog. This observation says
  nothing about when or why its bytes differ from the declaration.

`windows-usbipd-driver-check.py` verifies the pinned input hashes before making five
controlled copies. In each case it checks native declarations, configured INF source
mapping, repeated JSON and unchanged input bytes, and records separate SignTool
`verify /pa /c` policy observations:

| Supplied layout | SYS digest comparison | INF source mapping | Observed SYS SignTool result |
|---|---|---|---|
| Original folder | Agreement | Supplied SYS associated | Exit 0 |
| Changed DOS-stub byte | No matching checked artifact | Changed supplied SYS associated | Exit 1 |
| SYS omitted | No matching checked artifact | Not supplied at the candidate path | Not run for the absent file |
| SYS renamed | Agreement with renamed file | Not supplied at the original candidate path | Exit 0 for renamed file |
| ZIP of the original files | Agreement within the ZIP | Supplied SYS associated within the ZIP | Exit 0 on the corresponding loose copy |

The INF remained unmatched in all five layouts and SignTool returned exit 1 for it.
The renamed case intentionally distinguishes digest membership from INF source lookup:
a File attribute is preserved as a declaration, not enforced as a Windows installation
filename. The archive comparison does not claim that SignTool itself inspected a ZIP.
The main analyzer never invokes any reference tool or reads the Driver Store.

## Reproducing the check

Obtain the three exact files and their license declarations from the pinned upstream
tree above into a local sample folder. Sample acquisition is a separate development
step; the reference script does no downloading. With a built CLI and Windows SDK:

```
python tools/native-compare/windows-usbipd-driver-check.py --sample <sample folder> --cli target/debug/analyze-anything.exe --output out/windows-baseline/usbipd-package-final
```

The local complete record is `out/windows-baseline/usbipd-package-final/checks.json`;
the initial SetupAPI/SIP records are under `out/windows-baseline/usbipd-win-reference`.
Broader independent packages, ARM64, CAB/tag media, named missing-versus-changed member
relationships and other catalog/INF semantics remain acceptance work.

Reference contracts: Microsoft's [CryptCATEnumerateAttr](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatenumerateattr),
[CRYPTCATATTRIBUTE](https://learn.microsoft.com/en-us/windows/win32/api/mscat/ns-mscat-cryptcatattribute)
and [MakeCat](https://learn.microsoft.com/en-us/windows/win32/seccrypto/makecat).
