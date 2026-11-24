# Delivery dependency qualification

2026-11-24. The advisory gate in [CI run 45356839363](https://github.com/atomsprout/analyze-anything/actions/runs/45356839363)
failed on the branch at c16d090. The license, source and dependency-ban checks passed.

The committed lockfile before the update has SHA-256
`7c65ba3857ddffcc3b10e64760b4a9e09070da65a0e50835ca3c695623d834e0`.
It resolves one copy each of `url 2.5.8` and `cookie 0.18.2` from crates.io.

- [RUSTSEC-2026-0592](https://rustsec.org/advisories/RUSTSEC-2026-0592)
  identifies recursive nested-blob origin processing in url through 2.5.8 and gives
  2.5.9 as the patched release. Parents include Typst's hayagriva dependency and
  Tauri's runtime/build dependencies. Repository source does not directly call
  `Url::origin`; that is not proof of absence in transitive callers.
- [RUSTSEC-2026-0594](https://rustsec.org/advisories/RUSTSEC-2026-0594)
  identifies private-cookie nonce reuse after fork in cookie through 0.18.2 and gives
  0.18.3 as the patched release. Parents are Tauri, tauri-runtime and wry. Repository
  source does not directly use private-cookie APIs or fork. The update removes the
  affected version rather than adding an advisory exception.

The lockfile was refreshed to url 2.5.9 and cookie 0.18.3 without changing parent
requirements. url also resolves form_urlencoded 1.2.3. Cargo normalized the existing
cssparser-macros dependency edge to syn 2.0.119 during resolution. No new package
source or advisory exemption was added. `cargo tree --workspace --locked` confirms
the resolved copies and parent paths. Build, runtime and hosted advisory qualification
of the updated lockfile must pass before this delivery milestone is complete.
