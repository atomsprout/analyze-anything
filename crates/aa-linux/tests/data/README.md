# Linux package fixtures

These unmodified published packages are read-only test inputs. Their source and
licenses are recorded in the repository's `NOTICE`; no package is installed or run.

| File | Source | License |
|---|---|---|
| node-isarray_2.0.5-1_all.deb | Debian package pool, node-isarray 2.0.5-1 | Expat/MIT, including Debian packaging; COPYRIGHT-node-isarray.txt |
| xxhash-libs-0.8.4-2.fc43.x86_64.rpm | Fedora 43 updates, xxhash library subpackage | BSD-2-Clause; LICENSE-xxhash.txt |
| native-script.deb / native-script.rpm | Project-authored fixtures built with dpkg-deb/rpmbuild on Ubuntu 24.04 | Apache-2.0 |

`tools/native-compare/linux-packages.py` checks these with dpkg-deb, librpm,
rpm2cpio and libarchive. `linux-package-fixtures.py` builds separate project-owned
script-declaration packages with dpkg-deb/rpmbuild, never running those scripts.
The Native comparison workflow's Linux job records and uploads the reference
results. Run 45373345565 at 425b6b6 passed 112 checks over the four pinned packages
and two freshly built script packages. The hash-bound native values and member
digests are recorded in docs/spikes/linux-packages-native.json and checked by
cross-platform engine tests. Script-text display was added after that run and
will receive its own native check before final acceptance.
