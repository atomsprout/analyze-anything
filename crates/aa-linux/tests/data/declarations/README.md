# Linux declaration fixtures

These upstream text files are read as data. No declared executable, unit, action or
URL is invoked. `sources.json` pins each source commit, exact URL and SHA-256.

- `syncthing.service` and `syncthing-start.desktop` are unmodified Syncthing files
  at commit `1107b3cd11dbe267a8b80bbe1f89fb86a070b5c3`. Syncthing is MPL-2.0;
  `LICENSE-syncthing.txt` preserves its licence. The service's repeated Environment
  declarations and launch commands remain literal; no systemd effective state is claimed.
- `org.flameshot.Flameshot.metainfo.xml` is unmodified Flameshot metainfo at commit
  `dcc3bd3175495e04832c4aac0868f1dd15aba2ca`. Its source header declares no copyright
  and `CC0-1.0`; its project licence declaration is `GPL-3.0-or-later`.
- `org.flameshot.Flameshot.desktop` is an authentic upstream **build template**
  from that same commit, under the project's GPL-3.0-or-later licence preserved in
  `LICENSE-flameshot.txt`. Its `@LAUNCHER_EXECUTABLE@` values are not substituted.
  It exercises explicit unsupported-template output and localized action declarations;
  it is not evidence of a working installed launcher.

`tools/native-compare/linux-declarations.py` independently checks selected literal
fields with Python ConfigParser and the component/launchable metadata with
ElementTree. With `--native`, it also records static `systemd-analyze verify`,
`desktop-file-validate` and offline `appstreamcli validate --no-net` output. Native
diagnostics may report absent host programs or template placeholders; the record
preserves those statuses rather than interpreting them as successful installation.

The initial reader supports bounded UTF-8 literal single-line unit/desktop fields
and one AppStream `component` document. Unknown fields/elements are retained with
limitations; continuations, substitutions, drop-in precedence and runtime state are
not evaluated. Only a complete, original supplied applications namespace can support
the optional AppStream desktop-file-ID relationship.
