//! Native executables: PE, ELF and Mach-O (thin and universal).
//!
//! The analyzer `binary` recognises a file by its content, sets its kind (`elf`, `pe`, `macho`,
//! `macho-fat`), attaches the facts below and reports identity, composition, hardening and
//! toolchain findings. The parsers are written against the format specifications with checked
//! reads only (see [`common::Rd`]), so every finding can point at the bytes it was read from and
//! a damaged table costs that table, not the whole file.
//!
//! Not done here, by design: Apple code signatures, entitlements and FairPlay (`aa-apple`);
//! Authenticode verification, resources, manifests, .NET metadata, installers (`aa-windows`).
//! The facts say where those structures are so the other analyzers need not parse headers again.
//!
//! In a universal binary every finding about a slice starts with the slice's architecture in
//! brackets (the `label` param, empty for single-architecture files), and evidence offsets are
//! offsets in the whole file.
//!
//! # Facts
//!
//! All offsets are file offsets and all numbers are plain JSON numbers unless noted. A value
//! that could not be read is `null` or the key is absent; it is never `0` or `""`.
//!
//! For a **universal Mach-O** (`macho-fat`) the artifact carries only `binary.header`
//! (`{format: "macho-fat", fat64, slices, archs: [..]}`) and `binary.slices`: an array with one
//! object per slice `{arch, cputype, cpusubtype, offset, size, align, kind}` where `kind` is
//! `macho`, `archive`, `truncated` or `unknown`; a `macho` slice additionally holds every
//! Mach-O fact below under its name without the `binary.` prefix (`header`, `sections`, …).
//! Offsets inside a slice's facts are relative to the slice.
//!
//! ## `binary.header`
//! Common keys: `format` (`elf` | `pe` | `macho`), `arch` (string or null when the machine id is
//! unknown), `bits` (32 | 64), `endian` (`little` | `big`), `file_type`, `entry`,
//! `go_build_id` (string or null).
//! - ELF: `file_type` is `executable` | `pie-executable` | `shared-library` | `object` | `core` |
//!   `unknown`; `machine`, `elf_type`, `os_abi`, `os_abi_raw`, `flags` (raw numbers; `os_abi` a
//!   name or null), `entry` (virtual address), `build_id` (hex or null), `abi_tag`
//!   (`"Linux 3.2.0"` or null), `android_api` (number or null).
//! - PE: `file_type` is `executable` | `dll` | `driver` | `efi`; `pe32plus`, `machine`,
//!   `subsystem` (name or null), `subsystem_raw`, `characteristics` and `dll_characteristics`
//!   (arrays of flag names), `dll_characteristics_raw`, `timestamp` (raw u32),
//!   `timestamp_is_hash` (true when a REPRO debug entry says the field is a build hash),
//!   `entry` (RVA), `image_base`, `size_of_image`, `size_of_headers`, `checksum`,
//!   `linker_version`, `os_version`, `subsystem_version` (`"major.minor"` strings).
//! - Mach-O: `file_type` is `executable` | `dylib` | `bundle` | `object` | `dsym` | `kext` | … or
//!   null; `cputype`, `cpusubtype`, `filetype_raw`, `flags` (names), `flags_raw`, `entry`
//!   (virtual address or null), `entry_offset` (`LC_MAIN` entryoff or null), `uuid`
//!   (`XXXXXXXX-XXXX-…` or null), `min_os` (`{platform, minos, sdk, source}` or null, `source`
//!   the load command it came from), `source_version`.
//!
//! ## `binary.sections`
//! `{sections: [..], total, truncated}`. Each section has `name`, `offset`, `size`, `entropy`
//! (0–8, or null when the section has no bytes in the file), plus
//! - ELF: `type` (name), `flags` (names), `address`, `entsize`;
//! - PE: `virtual_address`, `virtual_size`, `flags` (names), `characteristics` (raw);
//! - Mach-O: `segment`, `address`, `flags` (raw).
//!
//! ## `binary.segments` (ELF, Mach-O)
//! `{segments: [..], truncated}`. ELF program headers: `type`, `flags` (`"r-x"`), `offset`,
//! `vaddr`, `filesz`, `memsz`, `align`. Mach-O segments: `name`, `vmaddr`, `vmsize`, `fileoff`,
//! `filesize`, `maxprot`, `initprot` (`"r-x"`), `flags`, `nsects`.
//!
//! ## `binary.libraries`
//! `{libraries: [{name, kind, ..}], truncated}` in file order. `kind`: ELF `needed`; PE `import`
//! | `delay-import` (plus `functions`, the number imported from it); Mach-O `load` | `weak` |
//! `reexport` | `lazy` | `upward` (plus `current_version`, `compatibility_version`).
//!
//! ## `binary.imports`, `binary.exports`
//! `{count, symbols: [..], truncated}`; `count` is complete, `symbols` holds at most 2000,
//! sorted. Absent when the table could not be read. Import: `name`, `library` (PE: the DLL;
//! Mach-O: the dylib from the two-level namespace, or null; ELF: always null, the format does
//! not bind symbols to libraries), `weak` (ELF, Mach-O), `ordinal` (PE imports by ordinal, whose
//! `name` is `"#<ordinal>"`). Export: `name`, `address`, and for PE `ordinal` and `forwarder`;
//! PE also has top-level `functions` (address-table size).
//!
//! ## `binary.linking` (ELF, Mach-O)
//! ELF: `{static, interp, soname, rpath: [..], runpath: [..], dt_flags, dt_flags_1}`.
//! Mach-O: `{install_name, dylinker, rpaths: [..]}`.
//!
//! ## `binary.symbols`
//! ELF: `{stripped, symtab, dynsym}` (named-symbol counts, null when the table is absent).
//! PE: `{stripped, coff_symbols, coff_symbol_entries}`. Mach-O: `{stripped, symbols, local,
//! debug_entries}`. `stripped` means no local symbol names are left.
//!
//! ## `binary.debug`
//! `{has_debug_info, kinds: [..]}` with kinds `dwarf`, `stabs`, `pdb-reference`. ELF adds
//! `sections`, `debuglink`. PE adds `pdb` (`{path, guid, age}` or null; GUID in registry
//! format), `entries` (`[{type, timestamp, size, offset}]`), `debug_stripped_flag`.
//!
//! ## `binary.hardening`
//! Booleans, `null` meaning not applicable or not determinable.
//! ELF: `pie`, `nx`, `relro` (`full` | `partial` | `none`), `canary`, `fortify`,
//! `fortified_functions`, `rpath`, `runpath`, `writable_executable`, `cf_protection` (names).
//! PE: `applicable`, `aslr`, `high_entropy_va`, `dep`, `cfg`, `gs`, `safe_seh`,
//! `force_integrity`, `cet_compat`, `writable_executable`, `signature_present`.
//! Mach-O: `pie`, `nx_stack`, `nx_heap_flag`, `canary`, `arc`, `restrict_segment`,
//! `writable_executable`.
//!
//! ## `binary.toolchain`
//! `{languages: [{name, confidence, basis}], go, rustc_commit}`. `go` is null or `{format,
//! version, path, module, module_version, deps: [{path, version}], deps_total, deps_truncated,
//! settings}`. ELF adds `compiler_idents`; PE adds `dotnet`, `rich_header`, `mingw_hint`;
//! Mach-O adds `build_tools` (`[{tool, version}]`).
//!
//! ## `binary.pe` (PE)
//! `{directories: [{name, rva, size}], certificate_table: {offset, size} | null, clr:
//! {runtime_version, flags, il_only, requires_32bit, strong_name_signed} | null, load_config:
//! {size, security_cookie, se_handler_table, se_handler_count, guard_flags} | null, rich_header:
//! {offset, key, entries: [{product_id, build, count}]} | null, export_name}`.
//!
//! ## `binary.overlay` (PE, when bytes follow the last section)
//! `{offset, size, payload_size, after_signature_size, certificate_table_only, entropy}`.
//! `offset` is where accounted-for data ends (sections, COFF symbols); `payload_size` the bytes
//! from there to the certificate table or the end of the file.
//!
//! ## `binary.macho` (Mach-O)
//! `{load_commands: [{cmd, offset, size}], code_signature: {offset, size} | null, encryption:
//! {offset, size, cryptid} | null}`.

mod common;
mod elf;
mod lang;
mod macho;
mod pe;
mod rules;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};

use crate::common::finding;

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(Binary)]
}

struct Binary;

impl Analyzer for Binary {
    fn id(&self) -> &'static str {
        "binary"
    }

    fn rules(&self) -> &'static [Rule] {
        rules::RULES
    }

    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        // The smallest of the headers involved is 20 bytes.
        if file.size < 20 {
            return;
        }
        let Ok(bytes) = tree.read(&file.path) else { return };
        analyze_bytes(file, &bytes, out);
    }
}

/// Dispatches on the leading bytes. Files of other types are left alone.
fn analyze_bytes(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if bytes.starts_with(b"\x7fELF") {
        elf::analyze(file, bytes, out);
    } else if pe::is_pe(bytes) {
        pe::analyze(file, bytes, out);
    } else if macho::is_macho(bytes) {
        macho::analyze(file, bytes, out);
    }
}

/// The symbol-table findings every format shares. `stripped` is `None` where the notion does not
/// apply (PE keeps names in a separate PDB); `counts` is `(imports, exports)` when both were read.
fn emit_symbols(file: &Artifact, out: &mut Output, stripped: Option<bool>, named: Option<u64>, counts: Option<(u64, u64)>, label: &str) {
    match stripped {
        Some(true) => out.finding(
            finding(Section::Code, "binary.symbols-stripped", Confidence::Verified, Severity::Info)
                .param("label", label)
                .evidence(Evidence::field(file, format!("{label}symbol table"), "no local symbols")),
        ),
        Some(false) => out.finding(
            finding(Section::Code, "binary.symbols-present", Confidence::Verified, Severity::Info)
                .param("label", label)
                .param("count", named.unwrap_or(0))
                .evidence(Evidence::field(file, format!("{label}symbol table"), named.unwrap_or(0))),
        ),
        None => {}
    }
    if let Some((imports, exports)) = counts {
        out.finding(
            finding(Section::Code, "binary.symbol-counts", Confidence::Verified, Severity::Info)
                .param("label", label)
                .param("imports", imports)
                .param("exports", exports)
                .evidence(Evidence::field(file, format!("{label}imported symbols"), imports))
                .evidence(Evidence::field(file, format!("{label}exported symbols"), exports)),
        );
    }
}

#[cfg(test)]
mod tests;
