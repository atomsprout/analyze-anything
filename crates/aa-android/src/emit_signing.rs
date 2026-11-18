//! Findings and facts about the package file as a ZIP archive and about its signatures.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::{Value as Json, json};

use crate::manifest::Manifest;
use crate::sigblock::{self, Absent, Check, ContentDigests, SchemeResult};
use crate::x509::{Certificate, KeyAlgorithm};
use crate::{Package, PackageKind, finding, jarsign, known_certs, listed, zipraw};

fn trailing_reason(archive: &zipraw::Archive) -> String {
    format!(
        "{} bytes follow the ZIP end record; apksigner rejects such a file as not being a ZIP archive, and so do Android's v2+ verifiers",
        archive.trailing_bytes
    )
}

/// Whether a device running `min_sdk` or later would accept the signatures, by the rules
/// `apksigner verify` applies: every scheme present must verify, nothing may be stripped, and a
/// v1 signature is required when Android versions before 7.0 (API 24) are supported.
pub(crate) fn install_check(
    verified: &[&str],
    failed: &[String],
    has_v1: bool,
    has_v2_plus: bool,
    stripped: bool,
    min_sdk: i64,
) -> (bool, Vec<String>) {
    let mut reasons: Vec<String> = failed.to_vec();
    if stripped {
        reasons.push("a newer signature scheme was removed".into());
    }
    if !has_v1 && !has_v2_plus {
        reasons.push("the package is not signed".into());
    }
    if min_sdk < 24 && !has_v1 && has_v2_plus {
        reasons.push(format!("no v1 signature, which Android versions before 7.0 need (minimum API {min_sdk})"));
    }
    if verified.is_empty() && reasons.is_empty() {
        reasons.push("no signature could be verified".into());
    }
    (reasons.is_empty(), reasons)
}

fn check_json(check: &Check) -> Json {
    json!({ "status": check.as_str(), "detail": check.detail() })
}

/// Runs every archive and signature check. Returns the SHA-256 fingerprints of the signing
/// certificates of the strongest scheme that verified (empty when none did).
pub fn run(package: &Package, manifest: &Manifest, out: &mut Output) -> Vec<String> {
    let Some(container) = package.container else {
        out.limitation(
            "android.signature-not-checked",
            Some(package.manifest),
            Some("an extracted folder has no archive to verify; signatures cover the package file".into()),
        );
        return Vec::new();
    };
    let Ok(bytes) = package.tree.read(&container.path) else {
        out.limitation("android.signature-not-checked", Some(container), Some("the package file could not be read".into()));
        return Vec::new();
    };
    let Some(archive) = zipraw::parse(&bytes) else {
        out.limitation("android.signature-not-checked", Some(container), Some("no ZIP end-of-central-directory record was found".into()));
        return Vec::new();
    };
    archive_checks(container, &bytes, &archive, out);

    let is_bundle = package.kind == PackageKind::Bundle;
    let v1 = jarsign::verify(&bytes, &archive);
    let block = sigblock::find(&bytes, &archive);
    let mut schemes: Vec<SchemeResult> = Vec::new();
    let mut other_blocks: Vec<(u32, usize)> = Vec::new();
    let mut block_json = Json::Null;
    match &block {
        Ok(block) => {
            // apksigner and the platform refuse a v2+ signature on a file with data after the
            // end record or with ZIP64 structures; the digests are not recomputed for those.
            let mut digests =
                if archive.trailing_bytes == 0 && !archive.zip64 { ContentDigests::new(&bytes, &archive, block.start) } else { None };
            for (id, value, offset) in &block.pairs {
                match *id {
                    sigblock::ID_V2 | sigblock::ID_V3 | sigblock::ID_V31 => {
                        schemes.push(sigblock::verify_scheme(*id, value, *offset, &mut digests))
                    }
                    other => other_blocks.push((other, value.len())),
                }
            }
            block_json = json!({
                "offset": block.start,
                "size": block.size,
                "entries": block.pairs.iter().take(200).map(|(id, value, _)| json!({
                    "id": format!("0x{id:08x}"),
                    "name": sigblock::block_name(*id),
                    "size": value.len(),
                })).collect::<Vec<_>>(),
            });
        }
        Err(Absent::Malformed(why)) => {
            out.finding(
                finding(Section::Provenance, "android.signing-block-malformed", Confidence::Verified, Severity::High)
                    .param("reason", why.clone())
                    .evidence(Evidence::bytes(container, archive.cd_offset.saturating_sub(16), 16, "APK Sig Block 42")),
            );
        }
        Err(Absent::None) => {}
    }

    // Per-scheme findings.
    let mut certificates: BTreeMap<String, (Certificate, BTreeSet<&'static str>)> = BTreeMap::new();
    let mut note = |certificate: &Certificate, scheme: &'static str| {
        certificates.entry(certificate.sha256.clone()).or_insert_with(|| (certificate.clone(), BTreeSet::new())).1.insert(scheme);
    };
    let mut verified_schemes: Vec<&'static str> = Vec::new();
    let mut failed_schemes: Vec<String> = Vec::new();
    let mut best_signers: Vec<String> = Vec::new();

    if let Some(v1) = &v1 {
        let name = "v1";
        for signer in &v1.signers {
            if let Some(certificate) = &signer.signer_certificate {
                note(certificate, name);
            }
        }
        let checks: Vec<&Check> =
            std::iter::once(&v1.entries).chain(v1.signers.iter().flat_map(|s| [&s.signature, &s.manifest_link])).collect();
        let first_file = v1.signers.first().map(|s| s.signature_file.clone()).unwrap_or_default();
        let evidence = Evidence::field(
            container,
            first_file.as_str(),
            json!({
                "files": v1.entries.as_str(), "manifest": v1.signers.first().map(|s| s.manifest_link.as_str()), "signature": v1.signers.first().map(|s| s.signature.as_str()),
            }),
        );
        let trailing = (archive.trailing_bytes > 0 && !is_bundle).then(|| trailing_reason(&archive));
        if let Some(reason) = checks.iter().find(|c| c.failed()).and_then(|c| c.detail().map(str::to_string)).or(trailing) {
            failed_schemes.push(format!("v1: {reason}"));
            out.finding(
                finding(Section::Provenance, "android.signature-invalid", Confidence::Verified, Severity::High)
                    .param("scheme", "v1 (JAR)")
                    .param("reason", reason)
                    .reference("MASVS-RESILIENCE-2")
                    .evidence(evidence),
            );
        } else if let Some(unchecked) = checks.iter().find(|c| !c.passed()) {
            out.limitation(
                "android.signature-not-checked",
                Some(container),
                Some(format!("v1: {}", unchecked.detail().unwrap_or_default())),
            );
        } else {
            verified_schemes.push(name);
            best_signers = v1.signers.iter().filter_map(|s| s.signer_certificate.as_ref()).map(|c| c.sha256.clone()).collect();
            out.finding(
                finding(Section::Provenance, "android.signature-verified", Confidence::Verified, Severity::Info)
                    .param("scheme", "v1 (JAR)")
                    .param("signers", v1.signers.len())
                    .param(
                        "details_en",
                        format!(
                            "{} files match their {} digests in the manifest; signature algorithm {}",
                            v1.entries_checked,
                            v1.manifest_digest_algorithms.join(", "),
                            v1.signers.iter().filter_map(|s| s.signature_algorithm.clone()).collect::<Vec<_>>().join(", ")
                        ),
                    )
                    .param(
                        "details_zh",
                        format!(
                            "{} 个文件与清单中的 {} 摘要一致；签名算法 {}",
                            v1.entries_checked,
                            v1.manifest_digest_algorithms.join(", "),
                            v1.signers.iter().filter_map(|s| s.signature_algorithm.clone()).collect::<Vec<_>>().join(", ")
                        ),
                    )
                    .evidence(evidence),
            );
        }
    }
    for scheme in &schemes {
        let name = scheme.name();
        for signer in &scheme.signers {
            for certificate in signer.certificates.iter().take(1) {
                note(certificate, name);
            }
        }
        let label = format!("{name} (APK Signature Scheme)");
        let evidence = Evidence::bytes(
            container,
            scheme.offset,
            4,
            json!({
                "digest": scheme.signers.first().map(|s| s.digest.as_str()),
                "signature": scheme.signers.first().map(|s| s.signature.as_str()),
            }),
        );
        let mut failure: Option<String> = scheme.malformed.clone();
        let mut unchecked: Option<String> = None;
        if archive.trailing_bytes > 0 {
            failure = Some(trailing_reason(&archive));
        } else if archive.zip64 {
            unchecked = Some("the archive uses ZIP64 structures".into());
        }
        for signer in &scheme.signers {
            if let Some(problem) = signer.problems.first() {
                failure.get_or_insert(problem.clone());
            }
            for check in [&signer.digest, &signer.signature] {
                match check {
                    Check::Failed(why) => {
                        failure.get_or_insert(why.clone());
                    }
                    Check::NotChecked(why) => {
                        unchecked.get_or_insert(why.clone());
                    }
                    Check::Passed => {}
                }
            }
        }
        if let Some(reason) = failure {
            failed_schemes.push(format!("{name}: {reason}"));
            out.finding(
                finding(Section::Provenance, "android.signature-invalid", Confidence::Verified, Severity::High)
                    .param("scheme", label)
                    .param("reason", reason)
                    .reference("MASVS-RESILIENCE-2")
                    .evidence(evidence),
            );
        } else if let Some(reason) = unchecked {
            out.limitation("android.signature-not-checked", Some(container), Some(format!("{name}: {reason}")));
        } else {
            verified_schemes.push(name);
            // The newest scheme a device understands is the one it uses.
            best_signers = scheme.signers.iter().filter_map(|s| s.certificates.first()).map(|c| c.sha256.clone()).collect();
            let algorithms: BTreeSet<&str> = scheme.signers.iter().flat_map(|s| s.algorithms.iter().map(String::as_str)).collect();
            let algorithms = algorithms.into_iter().collect::<Vec<_>>().join(", ");
            let (sdk_en, sdk_zh) = match scheme.signers.first().and_then(|s| s.min_sdk.zip(s.max_sdk)) {
                Some((min, max)) if max == u32::MAX || max == i32::MAX as u32 => {
                    (format!("; applies to API {min} and later"), format!("；适用于 API {min} 及以上"))
                }
                Some((min, max)) => (format!("; applies to API {min} to {max}"), format!("；适用于 API {min} 至 {max}")),
                None => (String::new(), String::new()),
            };
            out.finding(
                finding(Section::Provenance, "android.signature-verified", Confidence::Verified, Severity::Info)
                    .param("scheme", label)
                    .param("signers", scheme.signers.len())
                    .param("details_en", format!("the content digest matches and the signature is valid; algorithm {algorithms}{sdk_en}"))
                    .param("details_zh", format!("内容摘要一致、签名有效；算法 {algorithms}{sdk_zh}"))
                    .evidence(evidence),
            );
        }
        for signer in &scheme.signers {
            if signer.lineage.len() > 1 {
                let chain: Vec<String> = signer
                    .lineage
                    .iter()
                    .map(|n| n.certificate.as_ref().map(|c| format!("{} ({}…)", c.subject, &c.sha256[..16])).unwrap_or_else(|| "?".into()))
                    .collect();
                let mut f = finding(Section::Provenance, "android.key-rotation", Confidence::Verified, Severity::Info)
                    .param("count", signer.lineage.len())
                    .param("chain", chain.join(" → "))
                    .param("scheme", name);
                for node in &signer.lineage {
                    if let Some(certificate) = &node.certificate {
                        f = f.evidence(Evidence::bytes(
                            container,
                            scheme.offset,
                            4,
                            json!({
                                "sha256": certificate.sha256,
                                "flags": node.flags,
                                "signed_by_previous": node.signed_by_previous.as_ref().map(Check::as_str),
                            }),
                        ));
                    }
                }
                out.finding(f);
            }
        }
    }

    let has_block_scheme = !schemes.is_empty();
    if v1.is_none() && !has_block_scheme {
        out.finding(
            finding(
                Section::Provenance,
                "android.unsigned",
                Confidence::Verified,
                if is_bundle { Severity::Info } else { Severity::Medium },
            )
            .param("format", if is_bundle { "app bundle" } else { "APK" })
            .reference("MASVS-RESILIENCE-2")
            .evidence(Evidence::whole(container, "no META-INF/*.SF and no APK Signing Block")),
        );
    }
    if !is_bundle && v1.is_some() && !has_block_scheme {
        let min = manifest.min_sdk.unwrap_or(1);
        out.finding(
            finding(Section::Provenance, "android.v1-only", Confidence::Verified, Severity::Low)
                .param("target", manifest.effective_target_sdk())
                .param("min", min)
                .reference("MASVS-RESILIENCE-2")
                .evidence(Evidence::whole(container, "no APK Signing Block before the central directory")),
        );
    }
    if !is_bundle && v1.is_none() && has_block_scheme && manifest.min_sdk.unwrap_or(1) < 24 {
        out.finding(
            finding(Section::Provenance, "android.v1-missing", Confidence::Verified, Severity::Low)
                .param("min", manifest.min_sdk.unwrap_or(1))
                .evidence(Evidence::whole(container, "no META-INF/*.SF")),
        );
    }
    // A v1 signature names the newer schemes applied with it; a v2 signer names v3. If the named
    // scheme is gone, someone removed it.
    let scheme_present = |id: u32| schemes.iter().any(|s| s.id == id);
    let mut stripped: Vec<&str> = Vec::new();
    if let Some(v1) = &v1 {
        let named: BTreeSet<u32> = v1.signers.iter().flat_map(|s| s.also_signed_with.iter().copied()).collect();
        if named.contains(&2) && !scheme_present(sigblock::ID_V2) && !is_bundle {
            stripped.push("v2");
        }
        if named.contains(&3) && !scheme_present(sigblock::ID_V3) && !is_bundle {
            stripped.push("v3");
        }
    }
    if schemes.iter().filter(|s| s.id == sigblock::ID_V2).flat_map(|s| s.signers.iter()).any(|s| s.stripping_protection == Some(3))
        && !scheme_present(sigblock::ID_V3)
        && !stripped.contains(&"v3")
    {
        stripped.push("v3");
    }
    if !stripped.is_empty() {
        out.finding(
            finding(Section::Provenance, "android.signature-stripped", Confidence::Verified, Severity::High)
                .param("schemes", stripped.join(", "))
                .reference("MASVS-RESILIENCE-2")
                .evidence(Evidence::whole(container, "X-Android-APK-Signed / stripping-protection attribute")),
        );
    }
    // The same signer must stand behind every scheme. With key rotation, v3 may use a newer
    // certificate as long as its history contains the older one.
    let v1_set: BTreeSet<&str> =
        v1.iter().flat_map(|v| v.signers.iter()).filter_map(|s| s.signer_certificate.as_ref()).map(|c| c.sha256.as_str()).collect();
    let set_of = |id: u32| -> BTreeSet<&str> {
        schemes
            .iter()
            .filter(|s| s.id == id)
            .flat_map(|s| s.signers.iter())
            .filter_map(|s| s.certificates.first())
            .map(|c| c.sha256.as_str())
            .collect()
    };
    let v2_set = set_of(sigblock::ID_V2);
    let lineage: BTreeSet<&str> = schemes
        .iter()
        .flat_map(|s| s.signers.iter())
        .flat_map(|s| s.lineage.iter())
        .filter_map(|n| n.certificate.as_ref())
        .map(|c| c.sha256.as_str())
        .collect();
    let mut mismatches = Vec::new();
    if !v1_set.is_empty() && !v2_set.is_empty() && v1_set != v2_set {
        mismatches.push("v1 / v2");
    }
    for (id, label) in [(sigblock::ID_V3, "v3"), (sigblock::ID_V31, "v3.1")] {
        let set = set_of(id);
        let older = if v2_set.is_empty() { &v1_set } else { &v2_set };
        if !set.is_empty() && !older.is_empty() && set != *older && !older.iter().all(|c| lineage.contains(c)) {
            mismatches.push(label);
        }
    }
    if !mismatches.is_empty() {
        out.finding(
            finding(Section::Provenance, "android.signer-mismatch", Confidence::Verified, Severity::High)
                .param("schemes", mismatches.join(", "))
                .reference("MASVS-RESILIENCE-2")
                .evidence(Evidence::whole(container, json!({ "v1": v1_set, "v2": v2_set, "v3": set_of(sigblock::ID_V3) }))),
        );
    }

    for (certificate, used_by) in certificates.values() {
        certificate_findings(container, certificate, used_by, out);
    }

    if !other_blocks.is_empty() {
        let names: Vec<String> = other_blocks
            .iter()
            .map(|(id, _)| match sigblock::block_name(*id) {
                "" => format!("0x{id:08x}"),
                name => format!("{name} (0x{id:08x})"),
            })
            .collect();
        let mut f = finding(Section::Provenance, "android.signing-block-extras", Confidence::Verified, Severity::Info)
            .param("count", names.len())
            .param("blocks", listed(&names, 8));
        for (id, size) in other_blocks.iter().take(8) {
            f = f.evidence(Evidence::field(container, format!("APK Signing Block id 0x{id:08x}"), json!({ "size": size })));
        }
        out.finding(f);
    }
    // v4 lives in a separate file beside the APK.
    let idsig = package.tree.get(&format!("{}.idsig", container.path));
    if let Some(idsig) = idsig {
        out.finding(
            finding(Section::Provenance, "android.v4-signature-file", Confidence::Verified, Severity::Info)
                .param("file", idsig.name())
                .evidence(Evidence::whole(idsig, idsig.size)),
        );
        out.limitation("android.signature-not-checked", Some(idsig), Some("v4 (.idsig) signatures are detected, not verified".into()));
    }
    if let Some(stamp) = package.file("META-INF/stamp-cert-sha256")
        && let Ok(stamp_bytes) = package.tree.read(&stamp.path)
        && stamp_bytes.len() <= 64
    {
        out.finding(
            finding(Section::Provenance, "android.source-stamp-certificate", Confidence::Verified, Severity::Info)
                .param("sha256", hex::encode(&stamp_bytes[..]))
                .evidence(Evidence::whole(stamp, hex::encode(&stamp_bytes[..]))),
        );
    }

    let scheme_json = |scheme: &SchemeResult| {
        json!({
            "scheme": scheme.name(),
            "verified": scheme.verified() && archive.trailing_bytes == 0 && !archive.zip64,
            "malformed": scheme.malformed,
            "signers": scheme.signers.iter().map(|s| json!({
                "certificates": s.certificates.iter().map(Certificate::to_json).collect::<Vec<_>>(),
                "unparsed_certificates": s.unparsed_certificates,
                "algorithms": s.algorithms,
                "min_sdk": s.min_sdk,
                "max_sdk": s.max_sdk,
                "content_digest": check_json(&s.digest),
                "signature": check_json(&s.signature),
                "problems": s.problems,
                "rotation_min_sdk": s.rotation_min_sdk,
                "additional_attributes": s.additional_attributes.iter().map(|id| format!("0x{id:08x}")).collect::<Vec<_>>(),
                "lineage": s.lineage.iter().map(|n| json!({
                    "sha256": n.certificate.as_ref().map(|c| c.sha256.clone()),
                    "subject": n.certificate.as_ref().map(|c| c.subject.clone()),
                    "flags": n.flags,
                    "signed_by_previous": n.signed_by_previous.as_ref().map(check_json),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    };
    let min_sdk = manifest.min_sdk.unwrap_or(1);
    let (accepted, reasons) =
        install_check(&verified_schemes, &failed_schemes, v1.is_some(), has_block_scheme, !stripped.is_empty(), min_sdk);
    out.fact(
        container,
        "android.signing",
        json!({
            "verified_schemes": verified_schemes,
            "failed_schemes": failed_schemes,
            "stripped_schemes": stripped,
            // Not meaningful for app bundles, which are re-signed by the store.
            "install_check": (!is_bundle).then(|| json!({ "min_sdk": min_sdk, "accepted": accepted, "reasons": reasons })),
            "v1": v1.as_ref().map(|v1| json!({
                "verified": v1.verified(),
                "files": check_json(&v1.entries),
                "files_checked": v1.entries_checked,
                "digest_algorithms": v1.manifest_digest_algorithms,
                "digest_mismatches": v1.digest_mismatches,
                "not_in_manifest": v1.unsigned_entries,
                "missing_files": v1.missing_entries,
                "signers": v1.signers.iter().map(|s| json!({
                    "signature_file": s.signature_file,
                    "block_file": s.block_file,
                    "certificate": s.signer_certificate.as_ref().map(Certificate::to_json),
                    "digest_algorithm": s.digest_algorithm,
                    "signature_algorithm": s.signature_algorithm,
                    "signature": check_json(&s.signature),
                    "manifest": check_json(&s.manifest_link),
                    "also_signed_with": s.also_signed_with,
                    "created_by": s.created_by,
                })).collect::<Vec<_>>(),
            })),
            "schemes": schemes.iter().map(scheme_json).collect::<Vec<_>>(),
            "signing_block": block_json,
            "v4_idsig": idsig.map(|a| a.path.clone()),
        }),
    );
    best_signers.sort();
    best_signers
}

fn certificate_findings(container: &Artifact, certificate: &Certificate, used_by: &BTreeSet<&'static str>, out: &mut Output) {
    let schemes = used_by.iter().copied().collect::<Vec<_>>().join(", ");
    let evidence = || Evidence::field(container, format!("signing certificate ({schemes})"), certificate.sha256.clone());
    out.finding(
        finding(Section::Provenance, "android.signing-certificate", Confidence::Verified, Severity::Info)
            .param("subject", certificate.subject.clone())
            .param(
                "issuer_en",
                if certificate.self_issued { "same as the subject (self-signed)".to_string() } else { certificate.issuer.clone() },
            )
            .param("issuer_zh", if certificate.self_issued { "与主体相同（自签名）".to_string() } else { certificate.issuer.clone() })
            .param("serial", certificate.serial.clone())
            .param("not_before", certificate.not_before.clone().unwrap_or_else(|| "?".into()))
            .param("not_after", certificate.not_after.clone().unwrap_or_else(|| "?".into()))
            .param("key", certificate.key.describe())
            .param("signature_algorithm", certificate.signature_algorithm.clone())
            .param("sha256", certificate.sha256.clone())
            .param("sha1", certificate.sha1.clone())
            .param("schemes", schemes.clone())
            .evidence(evidence()),
    );
    if let Some(key) = known_certs::aosp_test_key(&certificate.sha256) {
        out.finding(
            finding(Section::Provenance, "android.aosp-test-key", Confidence::Verified, Severity::High)
                .param("key", key)
                .param("sha256", certificate.sha256.clone())
                .reference("MASVS-RESILIENCE-2")
                .evidence(evidence()),
        );
    } else if known_certs::is_debug_certificate(&certificate.subject) {
        out.finding(
            finding(Section::Provenance, "android.debug-certificate", Confidence::Verified, Severity::Medium)
                .param("subject", certificate.subject.clone())
                .reference("MASVS-RESILIENCE-2")
                .evidence(evidence()),
        );
    }
    let weak = match &certificate.key {
        KeyAlgorithm::Rsa { bits } | KeyAlgorithm::Dsa { bits } => *bits < 2048,
        KeyAlgorithm::Ec { bits, .. } => bits.is_some_and(|b| b < 224),
        KeyAlgorithm::Other(_) => false,
    };
    if weak {
        out.finding(
            finding(Section::Provenance, "android.weak-signing-key", Confidence::Verified, Severity::Medium)
                .param("key", certificate.key.describe())
                .reference("CWE-326")
                .reference("MASVS-RESILIENCE-2")
                .evidence(evidence()),
        );
    }
    if certificate.signature_algorithm.starts_with("MD5")
        || certificate.signature_algorithm.starts_with("MD2")
        || certificate.signature_algorithm.starts_with("SHA1")
    {
        out.finding(
            finding(Section::Provenance, "android.weak-certificate-digest", Confidence::Verified, Severity::Low)
                .param("algorithm", certificate.signature_algorithm.clone())
                .reference("CWE-328")
                .evidence(evidence()),
        );
    }
}

fn archive_checks(container: &Artifact, bytes: &[u8], archive: &zipraw::Archive, out: &mut Output) {
    let duplicates = archive.duplicate_names();
    if !duplicates.is_empty() {
        let names: Vec<String> = duplicates.iter().map(|(name, count)| format!("{name} ×{count}")).collect();
        let mut f = finding(Section::Anomalies, "android.zip-duplicate-entries", Confidence::Verified, Severity::High)
            .param("count", duplicates.len())
            .param("names", listed(&names, 8))
            .reference("MASVS-RESILIENCE-2");
        for (name, _) in duplicates.iter().take(8) {
            for entry in archive.entries.iter().filter(|e| e.name == *name).take(4) {
                f = f.evidence(Evidence::bytes(container, entry.cd_offset, 46, name.clone()));
            }
        }
        out.finding(f);
    }
    let mismatched: Vec<&zipraw::Entry> = archive.entries.iter().filter(|e| e.local_mismatch.is_some()).collect();
    if !mismatched.is_empty() {
        let shown: Vec<String> = mismatched.iter().map(|e| format!("{}: {}", e.name, e.local_mismatch.as_deref().unwrap_or(""))).collect();
        let mut f = finding(Section::Anomalies, "android.zip-header-mismatch", Confidence::Verified, Severity::Medium)
            .param("count", mismatched.len())
            .param("entries", listed(&shown, 5));
        for entry in mismatched.iter().take(10) {
            f = f.evidence(Evidence::bytes(container, entry.local_offset, 30, entry.local_mismatch.clone()));
        }
        out.finding(f);
    }
    if let Some(first) = archive.first_local_offset.filter(|o| *o > 0) {
        let dex = bytes.starts_with(b"dex\n");
        let head = &bytes[..bytes.len().min(8)];
        if dex {
            out.finding(
                finding(Section::Anomalies, "android.janus", Confidence::Verified, Severity::High)
                    .param("bytes", first)
                    .reference("CVE-2017-13156")
                    .reference("MASVS-RESILIENCE-2")
                    .evidence(Evidence::bytes(container, 0, head.len() as u64, hex::encode(head))),
            );
        } else {
            out.finding(
                finding(Section::Anomalies, "android.zip-prefix-data", Confidence::Verified, Severity::Low)
                    .param("bytes", first)
                    .evidence(Evidence::bytes(container, 0, head.len() as u64, hex::encode(head))),
            );
        }
    }
    if archive.trailing_bytes > 0 {
        out.finding(
            finding(Section::Anomalies, "android.zip-trailing-data", Confidence::Verified, Severity::Medium)
                .param("bytes", archive.trailing_bytes)
                .evidence(Evidence::bytes(
                    container,
                    archive.eocd_offset + 22 + u64::from(archive.comment_len),
                    archive.trailing_bytes,
                    json!(null),
                )),
        );
    }
    let flagged: Vec<&zipraw::Entry> = archive.entries.iter().filter(|e| e.flags & 1 != 0 || !matches!(e.method, 0 | 8)).collect();
    if !flagged.is_empty() {
        let shown: Vec<String> = flagged.iter().map(|e| format!("{} (method {}, flags 0x{:04x})", e.name, e.method, e.flags)).collect();
        let mut f = finding(Section::Anomalies, "android.zip-odd-entries", Confidence::Verified, Severity::Medium)
            .param("count", flagged.len())
            .param("entries", listed(&shown, 5));
        for entry in flagged.iter().take(10) {
            f = f.evidence(Evidence::bytes(container, entry.cd_offset, 46, json!({ "method": entry.method, "flags": entry.flags })));
        }
        out.finding(f);
    }
    if archive.truncated || archive.declared_entries != archive.entries.len() as u64 {
        out.finding(
            finding(Section::Anomalies, "android.zip-count-mismatch", Confidence::Verified, Severity::Low)
                .param("declared", archive.declared_entries)
                .param("found", archive.entries.len())
                .evidence(Evidence::bytes(container, archive.eocd_offset, 22, archive.declared_entries)),
        );
    }
    out.fact(
        container,
        "android.zip",
        json!({
            "entries": archive.entries.len(),
            "declared_entries": archive.declared_entries,
            "central_directory_offset": archive.cd_offset,
            "end_record_offset": archive.eocd_offset,
            "bytes_before_first_entry": archive.first_local_offset,
            "bytes_after_end_record": archive.trailing_bytes,
            "zip64": archive.zip64,
            "duplicate_names": duplicates.iter().take(100).map(|(n, c)| json!({ "name": n, "count": c })).collect::<Vec<_>>(),
            "local_header_mismatches": mismatched.len(),
        }),
    );
}
