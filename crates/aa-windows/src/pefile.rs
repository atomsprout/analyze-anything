//! The per-file analysis of a PE image: signature, resources, .NET metadata, structure
//! checks, import capabilities and kernel-driver facts.

use std::collections::BTreeMap;

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::authenticode::{self, Authenticode};
use crate::pe::{self, Pe, RT_GROUP_ICON, RT_ICON, RT_MANIFEST, RT_VERSION, ResId, SUBSYSTEM_NATIVE};
use crate::{ID, behaviour, dotnet, resources};

/// Section names packers and protectors are known to leave. Matching is by prefix,
/// case-insensitive.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp", "VMProtect"),
    (".MPRESS", "MPRESS"),
    (".enigma", "Enigma Protector"),
    (".petite", "Petite"),
    (".nsp", "NsPack"),
    ("nsp0", "NsPack"),
    ("nsp1", "NsPack"),
    ("pec", "PECompact"),
    ("PEC2", "PECompact"),
    ("pebundle", "PEBundle"),
    (".yP", "Y0da Protector"),
    (".y0da", "Y0da Protector"),
    ("MEW", "MEW"),
    ("FSG!", "FSG"),
    (".svkp", "SVKP"),
    (".RLPack", "RLPack"),
    (".packed", "RLPack"),
    (".boom", "The Boomerang List Builder"),
    (".perplex", "Perplex PE-Protector"),
    ("kkrunchy", "kkrunchy"),
    (".obsidium", "Obsidium"),
    (".taz", "PESpin"),
    (".spack", "Simple Pack"),
    (".shrink", "Shrinker"),
    ("ProCrypt", "ProCrypt"),
    (".neolit", "NeoLite"),
    (".Upack", "Upack"),
    (".ByDwing", "Upack"),
    ("PEPACK", "PE-PACK"),
    (".pelock", "PELock"),
    (".arch", "Alpha packer / also a Windows-on-Alpha section"),
];

/// Largest executable section whose entropy is measured.
const MAX_ENTROPY_BYTES: usize = 256 * 1024 * 1024;

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-console",
        5 => "os2-console",
        7 => "posix-console",
        9 => "windows-ce",
        10 => "efi-application",
        11 => "efi-boot-service-driver",
        12 => "efi-runtime-driver",
        13 => "efi-rom",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => "unknown",
    }
}

fn finding(section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    Finding::new(section, ID, rule, confidence, severity)
}

/// Analyzes one PE file. Returns nothing when `bytes` is not a PE image.
pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !bytes.starts_with(b"MZ") {
        return;
    }
    let pe = match Pe::parse(bytes) {
        Ok(pe) => pe,
        Err(detail) => {
            // Plain DOS programs also start with MZ; only files that claim a PE header are reported.
            if pe::looks_like_pe(bytes) {
                out.limitation("windows.pe-unreadable", Some(file), Some(detail));
            }
            return;
        }
    };
    let imports = pe.imports();
    let res = pe.resources();
    let net = dotnet::analyze(&pe);

    let computed_checksum = pe.compute_checksum();
    let overlay = pe.overlay();
    out.fact(
        file,
        "windows.pe",
        json!({
            "dll": pe.is_dll(),
            "bits": if pe.is64 { 64 } else { 32 },
            "machine": pe.machine,
            "subsystem": subsystem_name(pe.subsystem),
            "timestamp": pe.timestamp,
            "checksum": { "stored": pe.checksum, "computed": computed_checksum },
            "overlay": overlay.map(|(offset, size)| json!({ "offset": offset, "size": size })),
            "tls_callbacks": pe.tls_callbacks(),
            "tls_directory_offset": pe.directory(pe::DIR_TLS).and_then(|(rva, _)| pe.offset_of(rva)),
            "export_name": pe.export_name(),
            "import_libraries": imports.dlls.len(),
            "import_functions": imports.dlls.iter().map(|d| d.functions.len()).sum::<usize>(),
        }),
    );

    signature(file, &pe, out);
    let version = version_and_manifest(file, &pe, &res, out);
    resource_summary(file, &pe, &res, out);
    if let Some(net) = &net {
        dotnet_findings(file, &pe, net, out);
    }
    triage(file, &pe, &imports, net.is_some(), computed_checksum, out);

    let pinvokes = net.as_ref().map(|n| n.pinvokes.clone()).unwrap_or_default();
    let categories = behaviour::classify(&imports, &pinvokes);
    if !categories.is_empty() {
        out.fact(file, "windows.capabilities", behaviour::json(&categories));
    }
    driver(file, &pe, &imports, version.as_ref(), out);
}

fn signature(file: &Artifact, pe: &Pe, out: &mut Output) {
    let Some(auth) = authenticode::analyze(pe) else {
        out.fact(file, "windows.authenticode", json!({ "signed": false }));
        return;
    };
    let mut fact = auth.json();
    if let Some(object) = fact.as_object_mut() {
        object.insert("signed".into(), json!(!auth.signatures.is_empty()));
    }
    out.fact(file, "windows.authenticode", fact);
    for error in &auth.errors {
        out.limitation("windows.signature-unreadable", Some(file), Some(error.clone()));
    }
    signature_findings(file, &auth, out);
}

fn signature_findings(file: &Artifact, auth: &Authenticode, out: &mut Output) {
    for signature in &auth.signatures {
        let signer = signature.signer_name.clone().unwrap_or_else(|| "?".into());
        let at = |value: Value| Evidence::bytes(file, signature.offset as u64, signature.length as u64, value);
        if signature.file_digest.failed() {
            out.finding(
                finding(Section::Provenance, "windows.signature-digest-mismatch", Confidence::Verified, Severity::High)
                    .param("signer", signer.clone())
                    .param("algorithm", signature.digest_algorithm_name.clone())
                    .param("signed", signature.signed_digest.clone().unwrap_or_default())
                    .param("computed", signature.computed_digest.clone().unwrap_or_default())
                    .evidence(at(json!({ "signed_digest": signature.signed_digest, "computed_digest": signature.computed_digest }))),
            );
        }
        if signature.content_digest.failed() || signature.signature.failed() {
            out.finding(
                finding(Section::Provenance, "windows.signature-invalid", Confidence::Verified, Severity::High)
                    .param("signer", signer.clone())
                    .evidence(at(json!({
                        "content_digest_matches": !signature.content_digest.failed(),
                        "signature_verifies": !signature.signature.failed(),
                    }))),
            );
        }
        if signature.chain_check.failed() {
            out.finding(
                finding(Section::Provenance, "windows.signature-chain-broken", Confidence::Verified, Severity::Medium)
                    .param("signer", signer.clone())
                    .evidence(at(json!(signature.chain))),
            );
        }
        if signature.signer_self_issued {
            out.finding(
                finding(Section::Provenance, "windows.signature-self-signed", Confidence::Verified, Severity::Low)
                    .param("signer", signature.signer_subject.clone().unwrap_or_default())
                    .evidence(at(signature.signer.clone().unwrap_or(Value::Null))),
            );
        }
        if signature.valid_at_timestamp() == Some(false)
            && let Some((not_before, not_after)) = &signature.signer_validity
        {
            out.finding(
                finding(Section::Provenance, "windows.signature-outside-validity", Confidence::Derived, Severity::Medium)
                    .param("signer", signer.clone())
                    .param("time", signature.trusted_time().unwrap_or_default())
                    .param("not_before", not_before.clone())
                    .param("not_after", not_after.clone())
                    .evidence(at(json!({ "timestamp": signature.trusted_time(), "not_before": not_before, "not_after": not_after }))),
            );
        }
        for stamp in &signature.timestamps {
            if stamp.covers_signature.failed() || stamp.content_digest.failed() || stamp.signature.failed() {
                out.finding(
                    finding(Section::Provenance, "windows.signature-timestamp-invalid", Confidence::Verified, Severity::Low)
                        .param("signer", signer.clone())
                        .param("authority", stamp.authority_name.clone().unwrap_or_else(|| "?".into()))
                        .evidence(at(json!({
                            "covers_signature": !stamp.covers_signature.failed(),
                            "content_digest_matches": !stamp.content_digest.failed(),
                            "signature_verifies": !stamp.signature.failed(),
                        }))),
                );
            }
        }
        if signature.timestamps.is_empty()
            && let Some((_, not_after)) = &signature.signer_validity
        {
            out.finding(
                finding(Section::Provenance, "windows.signature-no-timestamp", Confidence::Verified, Severity::Info)
                    .param("signer", signer.clone())
                    .param("not_after", not_after.clone())
                    .evidence(at(json!({ "timestamps": 0, "claimed_signing_time": signature.signing_time }))),
            );
        }
    }
    // A weak digest matters only when no signature on the file uses a strong one.
    if let Some(first) = auth.signatures.first()
        && auth.signatures.iter().all(|s| s.digest_algorithm.is_some_and(|h| h.weak()))
    {
        out.finding(
            finding(Section::Provenance, "windows.signature-weak-digest", Confidence::Verified, Severity::Low)
                .param("algorithm", first.digest_algorithm_name.clone())
                .reference("CWE-328")
                .evidence(Evidence::bytes(file, first.offset as u64, first.length as u64, first.digest_algorithm_name.clone())),
        );
    }
    for &(offset, length) in &auth.extra_in_table {
        out.finding(
            finding(Section::Anomalies, "windows.signature-extra-data", Confidence::Verified, Severity::Medium)
                .param("bytes", length)
                .param("offset", offset)
                .reference("CVE-2013-3900")
                .evidence(Evidence::bytes(file, offset as u64, length as u64, json!({ "bytes": length }))),
        );
    }
    if let Some((offset, length)) = auth.after_table {
        out.finding(
            finding(Section::Anomalies, "windows.data-after-signature", Confidence::Verified, Severity::Medium)
                .param("bytes", length)
                .param("offset", offset)
                .evidence(Evidence::bytes(file, offset as u64, length as u64, json!({ "bytes": length }))),
        );
    }
}

fn version_and_manifest(file: &Artifact, pe: &Pe, res: &pe::Resources, out: &mut Output) -> Option<resources::VersionInfo> {
    let data_of = |kind: u32| {
        res.entries.iter().find(|r| r.kind == ResId::Id(kind)).and_then(|r| {
            let offset = r.offset?;
            Some((offset, pe.data.get(offset..offset + r.size as usize)?))
        })
    };
    let mut version_info = None;
    if let Some((offset, data)) = data_of(RT_VERSION) {
        match resources::parse_version(data) {
            Some(version) => {
                // Findings about versions are made in the tree pass, where files can be grouped.
                let mut fact = version.json();
                fact["offset"] = json!(offset);
                fact["size"] = json!(data.len());
                out.fact(file, "windows.version", fact);
                version_info = Some(version);
            }
            None => out.limitation("windows.version-unreadable", Some(file), None),
        }
    }
    if let Some((offset, data)) = data_of(RT_MANIFEST) {
        match resources::parse_manifest(data) {
            Ok(manifest) => {
                out.fact(file, "windows.manifest", manifest.json());
                let at = |field: &str, value: Value| {
                    Evidence::bytes(file, offset as u64, data.len() as u64, json!({ "element": field, "value": value }))
                };
                if let Some(level) = manifest.execution_level.as_deref().filter(|l| !l.eq_ignore_ascii_case("asInvoker")) {
                    out.finding(
                        finding(Section::Capabilities, "windows.manifest-elevation", Confidence::Verified, Severity::Info)
                            .param("level", level)
                            .evidence(at("requestedExecutionLevel/@level", json!(level))),
                    );
                }
                if manifest.ui_access == Some(true) {
                    out.finding(
                        finding(Section::Capabilities, "windows.manifest-ui-access", Confidence::Verified, Severity::Low)
                            .evidence(at("requestedExecutionLevel/@uiAccess", json!(true))),
                    );
                }
                if manifest.auto_elevate == Some(true) {
                    out.finding(
                        finding(Section::Capabilities, "windows.manifest-auto-elevate", Confidence::Verified, Severity::Low)
                            .evidence(at("autoElevate", json!(true))),
                    );
                }
            }
            Err(detail) => out.limitation("windows.manifest-unreadable", Some(file), Some(detail)),
        }
    }
    version_info
}

fn resource_summary(file: &Artifact, pe: &Pe, res: &pe::Resources, out: &mut Output) {
    if res.entries.is_empty() {
        return;
    }
    // type -> (count, bytes)
    let mut by_type: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut languages = std::collections::BTreeSet::new();
    let mut high_entropy = Vec::new();
    let mut embedded = Vec::new();
    for entry in &res.entries {
        let kind = match &entry.kind {
            ResId::Id(id) => pe::resource_type_name(*id).map(str::to_string).unwrap_or_else(|| format!("#{id}")),
            ResId::Name(name) => name.clone(),
        };
        let slot = by_type.entry(kind.clone()).or_default();
        slot.0 += 1;
        slot.1 += u64::from(entry.size);
        languages.insert(entry.language);
        let Some(offset) = entry.offset else { continue };
        let Some(data) = pe.data.get(offset..offset + entry.size as usize) else { continue };
        if pe::looks_like_pe(data) {
            embedded.push((kind.clone(), entry.name.to_string(), offset, data.len()));
        }
        // Icons and pictures are compressed by design; only other large resources are measured.
        let picture = matches!(entry.kind, ResId::Id(RT_ICON) | ResId::Id(2) | ResId::Id(1))
            || data.starts_with(b"\x89PNG")
            || data.starts_with(b"\xff\xd8\xff")
            || data.starts_with(b"GIF8");
        if !picture && data.len() >= 64 * 1024 && data.len() <= MAX_ENTROPY_BYTES {
            let entropy = pe::entropy(data);
            if entropy >= 7.5 {
                high_entropy.push((kind, entry.name.to_string(), offset, data.len(), entropy));
            }
        }
    }
    let icons = res.entries.iter().filter(|r| r.kind == ResId::Id(RT_GROUP_ICON)).count();
    out.fact(
        file,
        "windows.resources",
        json!({
            "count": res.entries.len(),
            "truncated": res.truncated,
            "types": by_type.iter().map(|(k, (count, bytes))| json!({ "type": k, "count": count, "bytes": bytes })).collect::<Vec<_>>(),
            "languages": languages,
            "icon_groups": icons,
            "high_entropy": high_entropy.iter().take(50).map(|(k, n, o, l, e)| json!({ "type": k, "name": n, "offset": o, "size": l, "entropy": (e * 100.0).round() / 100.0 })).collect::<Vec<_>>(),
            "embedded_pe": embedded.iter().take(50).map(|(k, n, o, l)| json!({ "type": k, "name": n, "offset": o, "size": l })).collect::<Vec<_>>(),
        }),
    );
    if !high_entropy.is_empty() {
        let bytes: usize = high_entropy.iter().map(|h| h.3).sum();
        let mut f = finding(Section::Anomalies, "windows.resource-high-entropy", Confidence::Heuristic, Severity::Info)
            .param("count", high_entropy.len())
            .param("bytes", bytes);
        for (kind, name, offset, length, entropy) in high_entropy.iter().take(5) {
            f = f.evidence(Evidence::bytes(
                file,
                *offset as u64,
                *length as u64,
                json!({ "type": kind, "name": name, "entropy": (entropy * 100.0).round() / 100.0 }),
            ));
        }
        out.finding(f);
    }
    if !embedded.is_empty() {
        let mut f =
            finding(Section::Anomalies, "windows.resource-embedded-pe", Confidence::Derived, Severity::Low).param("count", embedded.len());
        for (kind, name, offset, length) in embedded.iter().take(5) {
            f = f.evidence(Evidence::bytes(file, *offset as u64, *length as u64, json!({ "type": kind, "name": name })));
        }
        out.finding(f);
    }
}

fn dotnet_findings(file: &Artifact, pe: &Pe, net: &dotnet::DotNet, out: &mut Output) {
    out.fact(file, "windows.dotnet", net.json());
    if let Some(error) = &net.metadata_error {
        out.limitation("windows.dotnet-unreadable", Some(file), Some(error.clone()));
    }
    let clr_offset = pe.directory(pe::DIR_CLR).and_then(|(rva, _)| pe.offset_of(rva)).unwrap_or(0) as u64;
    let name = net.assembly_name.clone().or(net.module.clone()).unwrap_or_else(|| file.name().to_string());
    let mut mode = Vec::new();
    mode.push(if net.il_only { "IL only" } else { "mixed mode (contains native code)" });
    if net.requires_32bit {
        mode.push("32-bit required");
    }
    if net.prefers_32bit {
        mode.push("32-bit preferred");
    }
    mode.push(if net.strong_name_signature_size > 0 && net.strong_name_flag {
        "strong-name signed"
    } else if net.public_key_token.is_some() {
        "has a public key but no strong-name signature (delay-signed or public-signed)"
    } else {
        "no strong name"
    });
    out.finding(
        finding(Section::Composition, "windows.dotnet-assembly", Confidence::Verified, Severity::Info)
            .param("name", name)
            .param("version", net.assembly_version.clone().unwrap_or_else(|| "?".into()))
            .param("framework", net.target_framework.clone().or(net.runtime_version.clone()).unwrap_or_else(|| "?".into()))
            .param("mode", mode.join(", "))
            .param("types", net.types.map(Value::from).unwrap_or(Value::Null))
            .param("methods", net.methods.map(Value::from).unwrap_or(Value::Null))
            .param("references", net.references.len())
            .evidence(Evidence::bytes(file, clr_offset, 72, json!({ "assembly": net.assembly_name, "version": net.assembly_version }))),
    );
    if !net.obfuscator_hints.is_empty() {
        let tools: Vec<&str> = {
            let mut tools: Vec<&str> = net.obfuscator_hints.iter().map(|(tool, _)| tool.as_str()).collect();
            tools.dedup();
            tools
        };
        let mut f =
            finding(Section::Anomalies, "windows.dotnet-obfuscated", Confidence::Heuristic, Severity::Low).param("tools", tools.join(", "));
        for (tool, marker) in net.obfuscator_hints.iter().take(5) {
            f = f.evidence(Evidence::field(file, "metadata type name", json!({ "tool": tool, "marker": marker })));
        }
        out.finding(f);
    }
}

/// Structure checks and packer triage.
fn triage(file: &Artifact, pe: &Pe, imports: &pe::Imports, managed: bool, computed_checksum: u32, out: &mut Output) {
    let section_evidence = |s: &pe::Section, value: Value| Evidence::bytes(file, s.header_offset as u64, 40, value);

    // Known packer section names.
    let mut packers: Vec<(&str, &pe::Section)> = Vec::new();
    for section in &pe.sections {
        if let Some((_, tool)) = PACKER_SECTIONS.iter().find(|(prefix, _)| {
            section.name.len() >= prefix.len() && section.name.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        }) {
            // ".arch" exists in ordinary Alpha images; everything else is specific enough.
            if *tool != "Alpha packer / also a Windows-on-Alpha section" {
                packers.push((tool, section));
            }
        }
    }
    if let Some((tool, _)) = packers.first() {
        let mut f = finding(Section::Anomalies, "windows.packer-section", Confidence::Heuristic, Severity::Low)
            .param("packer", *tool)
            .param("sections", packers.iter().map(|(_, s)| s.name.as_str()).collect::<Vec<_>>().join(", "));
        for (_, section) in packers.iter().take(4) {
            f = f.evidence(section_evidence(section, json!(section.name)));
        }
        out.finding(f);
    }

    // Sections that are both writable and executable.
    let rwx: Vec<&pe::Section> = pe.sections.iter().filter(|s| s.writable() && s.executable()).collect();
    if !rwx.is_empty() {
        let mut f = finding(Section::Anomalies, "windows.section-rwx", Confidence::Verified, Severity::Low)
            .param("sections", rwx.iter().map(|s| printable_name(&s.name)).collect::<Vec<_>>().join(", "));
        for section in rwx.iter().take(4) {
            f = f.evidence(section_evidence(
                section,
                json!({ "name": section.name, "characteristics": format!("{:#010x}", section.characteristics) }),
            ));
        }
        out.finding(f);
    }

    // Section data that runs past the end of the file, or two sections sharing file bytes.
    let mut problems = Vec::new();
    let mut evidence = Vec::new();
    if (pe.declared_sections as usize) > pe.sections.len() {
        problems.push(format!(
            "the header declares {} sections but only {} headers fit in the file",
            pe.declared_sections,
            pe.sections.len()
        ));
    }
    let mut ranges: Vec<(u64, u64, &pe::Section)> = Vec::new();
    for section in &pe.sections {
        if section.raw_size == 0 {
            continue;
        }
        let (start, end) = (u64::from(section.raw_pointer), u64::from(section.raw_pointer) + u64::from(section.raw_size));
        if end > pe.data.len() as u64 {
            problems.push(format!(
                "section {} ends at offset {end}, past the end of the file ({})",
                printable_name(&section.name),
                pe.data.len()
            ));
            evidence.push(section_evidence(section, json!({ "raw_pointer": section.raw_pointer, "raw_size": section.raw_size })));
        }
        ranges.push((start, end, section));
    }
    ranges.sort_by_key(|r| (r.0, r.1));
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            problems.push(format!("sections {} and {} share file bytes", printable_name(&pair[0].2.name), printable_name(&pair[1].2.name)));
            evidence.push(section_evidence(pair[1].2, json!({ "raw_pointer": pair[1].2.raw_pointer, "raw_size": pair[1].2.raw_size })));
        }
    }
    if !problems.is_empty() {
        let mut f =
            finding(Section::Anomalies, "windows.pe-structure", Confidence::Verified, Severity::Low).param("problems", problems.join("; "));
        if evidence.is_empty() {
            f = f.evidence(Evidence::bytes(file, pe.pe_offset as u64 + 6, 2, pe.declared_sections));
        }
        for item in evidence.into_iter().take(6) {
            f = f.evidence(item);
        }
        out.finding(f);
    }

    // Entry point placement. Images without an entry point (resource DLLs) are skipped, and so
    // are kernel drivers, whose INIT section is legitimately last.
    if pe.entry_point != 0 && pe.subsystem != SUBSYSTEM_NATIVE {
        let entry_evidence = Evidence::bytes(file, pe.pe_offset as u64 + 24 + 16, 4, format!("{:#x}", pe.entry_point));
        match pe.section_of(pe.entry_point) {
            None => {
                out.finding(
                    finding(Section::Anomalies, "windows.entry-point-outside-sections", Confidence::Verified, Severity::Medium)
                        .param("entry", format!("{:#x}", pe.entry_point))
                        .evidence(entry_evidence),
                );
            }
            Some(section) => {
                let last = pe.sections.iter().max_by_key(|s| s.virtual_address).is_some_and(|l| std::ptr::eq(l, section));
                let mut oddities = Vec::new();
                if section.writable() {
                    oddities.push("writable");
                }
                if !section.executable() {
                    oddities.push("not marked executable");
                }
                if last && pe.sections.len() > 1 && !managed {
                    oddities.push("the last section of the image");
                }
                if !oddities.is_empty() {
                    out.finding(
                        finding(Section::Anomalies, "windows.entry-point-unusual", Confidence::Heuristic, Severity::Low)
                            .param("section", printable_name(&section.name))
                            .param("oddities", oddities.join(", "))
                            .evidence(entry_evidence)
                            .evidence(section_evidence(section, json!(section.name))),
                    );
                }
            }
        }
    }

    // Few imports together with high-entropy code: the usual shape of a packed image.
    let functions: usize = imports.dlls.iter().map(|d| d.functions.len()).sum();
    if !managed && functions <= 12 {
        let mut dense: Vec<(&pe::Section, f64)> = Vec::new();
        for section in pe.sections.iter().filter(|s| s.executable() && s.raw_size >= 4096) {
            let start = section.raw_pointer as usize;
            if let Some(data) = pe.data.get(start..start.saturating_add(section.raw_size as usize))
                && data.len() <= MAX_ENTROPY_BYTES
            {
                let entropy = pe::entropy(data);
                if entropy >= 7.2 {
                    dense.push((section, entropy));
                }
            }
        }
        if !dense.is_empty() {
            let mut f =
                finding(Section::Anomalies, "windows.packed-likely", Confidence::Heuristic, Severity::Low).param("imports", functions);
            for (section, entropy) in dense.iter().take(4) {
                f = f.evidence(Evidence::bytes(
                    file,
                    u64::from(section.raw_pointer),
                    u64::from(section.raw_size),
                    json!({ "section": section.name, "entropy": (entropy * 100.0).round() / 100.0 }),
                ));
            }
            out.finding(f);
        }
    }

    // Every import by ordinal: names are hidden from a casual reader.
    let by_ordinal = imports.dlls.iter().flat_map(|d| &d.functions).filter(|f| f.name.is_none()).count();
    if functions >= 4 && by_ordinal == functions {
        let offset = pe.directory(pe::DIR_IMPORT).and_then(|(rva, _)| pe.offset_of(rva)).unwrap_or(0);
        out.finding(
            finding(Section::Anomalies, "windows.imports-by-ordinal-only", Confidence::Verified, Severity::Info)
                .param("count", functions)
                .param("libraries", imports.dlls.iter().map(|d| d.name.as_str()).take(8).collect::<Vec<_>>().join(", "))
                .evidence(Evidence::bytes(file, offset as u64, 20, json!({ "imports_by_ordinal": by_ordinal }))),
        );
    }

    // Only the two values no linker writes by accident are reported; reproducible builds store
    // a hash in this field, so "implausible dates" are normal.
    if pe.timestamp == 0 || pe.timestamp == u32::MAX {
        out.finding(
            finding(Section::Anomalies, "windows.timestamp-blank", Confidence::Verified, Severity::Info)
                .param("value", format!("{:#010x}", pe.timestamp))
                .evidence(Evidence::bytes(file, pe.pe_offset as u64 + 8, 4, format!("{:#010x}", pe.timestamp))),
        );
    }

    if pe.checksum != 0 && pe.checksum != computed_checksum {
        out.finding(
            finding(Section::Anomalies, "windows.checksum-mismatch", Confidence::Verified, Severity::Info)
                .param("stored", format!("{:#010x}", pe.checksum))
                .param("computed", format!("{computed_checksum:#010x}"))
                .evidence(Evidence::bytes(file, pe.checksum_offset as u64, 4, format!("{:#010x}", pe.checksum))),
        );
    }
}

/// A section name safe to print: packers put arbitrary bytes there.
fn printable_name(name: &str) -> String {
    if name.is_empty() {
        return "(unnamed)".into();
    }
    name.chars().map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect()
}

/// Kernel drivers: native subsystem images that import from the kernel.
fn driver(file: &Artifact, pe: &Pe, imports: &pe::Imports, version: Option<&resources::VersionInfo>, out: &mut Output) {
    if pe.subsystem != SUBSYSTEM_NATIVE {
        return;
    }
    let libraries: Vec<String> = imports.dlls.iter().map(|d| d.name.to_ascii_lowercase()).collect();
    let has = |name: &str| libraries.iter().any(|l| l == name);
    let kernel = [
        "ntoskrnl.exe",
        "hal.dll",
        "wdfldr.sys",
        "ndis.sys",
        "fltmgr.sys",
        "ntkrnlpa.exe",
        "ks.sys",
        "storport.sys",
        "win32k.sys",
        "cng.sys",
    ];
    if !kernel.iter().any(|k| has(k)) {
        return;
    }
    let model = if has("wdfldr.sys") {
        "WDF (KMDF)"
    } else if has("fltmgr.sys") {
        "file-system minifilter"
    } else if has("ndis.sys") {
        "NDIS network driver"
    } else if has("storport.sys") {
        "Storport miniport"
    } else {
        "WDM / legacy"
    };
    let imported = |name: &str| imports.dlls.iter().flat_map(|d| &d.functions).any(|f| f.name.as_deref() == Some(name));
    let notable: Vec<&str> = [
        "IoCreateDevice",
        "IoCreateDeviceSecure",
        "IoCreateSymbolicLink",
        "IoCreateUnprotectedSymbolicLink",
        "WdfVersionBind",
        "FltRegisterFilter",
        "NdisMRegisterMiniportDriver",
        "ZwMapViewOfSection",
        "MmMapIoSpace",
        "MmMapIoSpaceEx",
        "MmCopyVirtualMemory",
        "ZwOpenProcess",
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetLoadImageNotifyRoutine",
        "PsSetCreateThreadNotifyRoutine",
        "ObRegisterCallbacks",
        "CmRegisterCallback",
        "CmRegisterCallbackEx",
        "KeStackAttachProcess",
        "ZwTerminateProcess",
        "__readmsr",
        "HalSetBusDataByOffset",
    ]
    .into_iter()
    .filter(|name| imported(name))
    .collect();

    // Device and symbolic-link names stored as plain UTF-16 strings.
    let mut names: Vec<(usize, String)> = Vec::new();
    for prefix in ["\\Device\\", "\\DosDevices\\", "\\??\\", "\\GLOBAL??\\"] {
        let needle: Vec<u8> = prefix.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut from = 0;
        while names.len() < 32 {
            let Some(found) = pe.data.get(from..).and_then(|rest| rest.windows(needle.len()).position(|w| w == needle.as_slice())) else {
                break;
            };
            let start = from + found;
            let units: Vec<u16> = pe.data[start..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| (0x20..0x7f).contains(&u))
                .take(128)
                .collect();
            let text = String::from_utf16_lossy(&units);
            if text.len() > prefix.len() {
                names.push((start, text));
            }
            from = start + needle.len();
        }
    }
    names.sort();
    names.dedup_by(|a, b| a.1 == b.1);

    out.fact(
        file,
        "windows.driver",
        json!({
            "model": model,
            "kernel_libraries": libraries,
            "notable_imports": notable,
            "device_names": names.iter().map(|(offset, name)| json!({ "offset": offset, "name": name })).collect::<Vec<_>>(),
            "description": version.and_then(|v| v.get("FileDescription")),
        }),
    );
    out.finding(
        finding(Section::Capabilities, "windows.kernel-driver", Confidence::Derived, Severity::Low)
            .param("model", model)
            .param("imports", if notable.is_empty() { "—".to_string() } else { notable.join(", ") })
            .evidence(Evidence::bytes(file, pe.pe_offset as u64 + 24 + 68, 2, json!({ "subsystem": "native", "libraries": libraries }))),
    );
    if !names.is_empty() {
        let mut f = finding(Section::Capabilities, "windows.driver-device-names", Confidence::Heuristic, Severity::Info)
            .param("names", names.iter().map(|(_, n)| n.as_str()).take(8).collect::<Vec<_>>().join(", "));
        for (offset, name) in names.iter().take(8) {
            f = f.evidence(Evidence::bytes(file, *offset as u64, name.len() as u64 * 2, name.as_str()));
        }
        out.finding(f);
    }
}
