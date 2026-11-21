//! Literal publisher/qualified signer-subject correspondence, with signed coverage separate.

use super::{Directory, Result, signature};
use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

fn child<'a>(tree: &'a dyn Tree, parent: &Artifact, name: &str) -> Result<&'a Artifact> {
    let path = if parent.path.is_empty() { name.into() } else { format!("{}/{name}", parent.path) };
    tree.get(&path)
        .filter(|a| a.parent.as_deref() == Some(parent.path.as_str()))
        .ok_or("canonical publisher input was not captured in the same container")
}

fn coverage(tree: &dyn Tree, parent: &Artifact, binding: &Value, manifest_name: &str, plain: &[u8]) -> Value {
    let result = (|| -> Result<()> {
        let map_digest = binding["checks"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["label"] == "AXBM" && c["status"] == "declared-digest-agrees")
            .and_then(|c| c["computed"].as_str())
            .ok_or("block-map digest was not bound to the CMS capsule")?;
        let source = child(tree, parent, "AppxBlockMap.xml")?;
        let map = source.facts.get("windows.msix-blockmap").ok_or("captured block-map declarations absent")?;
        if source.digests.as_ref().is_none_or(|d| d.sha256 != map_digest) || map["source_sha256"] != map_digest {
            return Err("captured block-map declarations differ from signed footprint bytes");
        }
        let rows: Vec<_> = map["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["path"].as_str().is_some_and(|p| p.eq_ignore_ascii_case(manifest_name)))
            .take(2)
            .collect();
        if rows.len() != 1 || !rows[0]["unresolved"].is_null() {
            return Err("manifest block-map declaration is absent or ambiguous");
        }
        let row = rows[0];
        let blocks = row["blocks"].as_array().ok_or("manifest block list absent")?;
        if row["size"].as_u64() != Some(plain.len() as u64) || blocks.len() != plain.len().div_ceil(65536) {
            return Err("manifest size or block count differs from signed map");
        }
        let algorithm = map["algorithm"].as_str().ok_or("manifest block algorithm absent")?;
        for (block, bytes) in blocks.iter().zip(plain.chunks(65536)) {
            let computed = crate::msix_blockmap::computed(algorithm, bytes).ok_or("manifest block hash algorithm unsupported")?;
            if block["digest"] != computed {
                return Err("manifest block content differs from signed map");
            }
        }
        if let Some(expected) = row["file_digest"].as_str() {
            let computed = crate::msix_blockmap::computed(algorithm, plain).ok_or("manifest whole-file hash algorithm unsupported")?;
            if expected != computed {
                return Err("manifest whole-file content differs from signed map");
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => json!({"established":true,"basis":"verified-CMS-capsule/AXBM/manifest-content-hashes"}),
        Err(reason) => json!({"established":false,"reason":reason}),
    }
}

pub(super) fn analyze(
    tree: &dyn Tree,
    parent: &Artifact,
    bytes: &[u8],
    directory: &Directory<'_>,
    budget: &mut signature::Budget,
    binding: &Value,
    out: &mut Output,
) -> Value {
    let result = (|| -> Result<(Value, &Artifact, &Artifact)> {
        let signature = child(tree, parent, "AppxSignature.p7x")?;
        let envelope = signature.facts.get("windows.msix-signature").ok_or("publisher CMS declarations absent")?;
        let digest = binding["signature_sha256"].as_str().ok_or("bound P7X digest absent")?;
        if signature.digests.as_ref().is_none_or(|d| d.sha256 != digest) || envelope["source_sha256"] != digest {
            return Err("publisher signature declarations do not match bound P7X");
        }
        let cms = envelope["cms"].as_array().ok_or("CMS signers absent")?;
        if cms.len() != 1 {
            return Err("publisher profile requires one CMS signer; no first signer selected");
        }
        let signer = &cms[0];
        if signer["signer_certificate_candidates"] != 1
            || ["signed_attributes", "algorithms", "content_digest", "signature"].iter().any(|k| signer["checks"][k] != "passed")
        {
            return Err("publisher CMS signer/key/attributes/signature were not uniquely verified");
        }
        let subject = &signer["msix_publisher_subject"];
        if subject["status"] != "projected" || subject["profile"] != crate::msix_publisher::PROFILE {
            return Err("signer subject spelling is outside qualified publisher profile");
        }
        let subject = subject["value"].as_str().ok_or("qualified signer subject spelling absent")?;
        let candidates: Vec<_> = [("AppxManifest.xml", "windows.msix"), (crate::msix_bundle::MANIFEST, "windows.msix-bundle")]
            .into_iter()
            .filter_map(|(name, key)| child(tree, parent, name).ok().map(|artifact| (name, key, artifact)))
            .collect();
        if candidates.len() != 1 {
            return Err("publisher requires one canonical package or bundle manifest");
        }
        let (manifest_name, key, manifest) = candidates[0];
        let model = manifest.facts.get(key).ok_or("manifest declarations absent")?;
        if model["identity_projection_established"] != true || model["identity_status"] != "unique" {
            return Err("manifest has no reusable unique qualified identity");
        }
        let entry = directory.entries.iter().find(|e| e.name == manifest_name).ok_or("canonical original manifest entry absent")?;
        let plain = signature::read(bytes, entry, budget)?;
        let manifest_digest = aa_core::sha256_hex(&plain);
        if manifest.size != plain.len() as u64
            || manifest.digests.as_ref().is_none_or(|d| d.sha256 != manifest_digest)
            || model["source_sha256"] != manifest_digest
        {
            return Err("original manifest differs from captured identity source");
        }
        let publisher = model["identity"]["publisher"].as_str().ok_or("unique manifest publisher absent")?;
        let matches = publisher == subject;
        Ok((
            json!({"profile":crate::msix_publisher::PROFILE,"status":if matches {"matches"}else{"differs"},"publisher_checked":true,"matches":matches,
            "manifest_sha256":manifest_digest,"signature_sha256":digest,"manifest_publisher":publisher,"signer_subject_spelling":subject,
            "signer_certificate_sha256":signer["signer"]["sha256"],"signer_subject_sha256":signer["msix_publisher_subject"]["subject_sha256"],
            "manifest_name":manifest_name,"manifest_signed_coverage":coverage(tree,parent,binding,manifest_name,&plain),"schema_validated":false,"certificate_policy_checked":false,"windows_trust_checked":false}),
            manifest,
            signature,
        ))
    })();
    let fact = match result {
        Ok((fact, manifest, signature)) => {
            out.finding(Finding::new(Section::Provenance,"windows",if fact["matches"]==true {"windows.msix-publisher-correspondence"}else{"windows.msix-publisher-mismatch"},Confidence::Verified,if fact["matches"]==true {Severity::Info}else{Severity::High})
                .evidence(Evidence::field(manifest,"Identity/Publisher",fact["manifest_publisher"].clone()))
                .evidence(Evidence::field(signature,"verified CMS signer/qualified reverse X500 subject",json!({"spelling":fact["signer_subject_spelling"],"certificate_sha256":fact["signer_certificate_sha256"],"subject_sha256":fact["signer_subject_sha256"]}))));
            if fact["manifest_signed_coverage"]["established"] != true {
                out.limitation(
                    "windows.msix-publisher-unresolved",
                    Some(parent),
                    Some("literal comparison was performed; manifest coverage by the signed block map was not established".into()),
                );
            }
            fact
        }
        Err(reason) => {
            out.limitation("windows.msix-publisher-unresolved", Some(parent), Some(reason.into()));
            json!({"profile":crate::msix_publisher::PROFILE,"status":"unresolved","publisher_checked":false,"reason":reason,"windows_trust_checked":false})
        }
    };
    out.fact(parent, "windows.msix-publisher", fact.clone());
    fact
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;
    use std::collections::BTreeMap;

    #[derive(Clone)]
    struct Captured(Vec<Artifact>);
    impl Tree for Captured {
        fn artifacts(&self) -> &[Artifact] {
            &self.0
        }
        fn read(&self, _: &str) -> std::io::Result<Bytes> {
            Err(std::io::Error::other("publisher must use the supplied original ZIP bytes"))
        }
    }

    fn artifact(name: &str, bytes: &[u8], parent: Option<&str>) -> Artifact {
        Artifact {
            path: name.into(),
            parent: parent.map(str::to_string),
            size: bytes.len() as u64,
            digests: Some(aa_core::Digests { md5: String::new(), sha1: String::new(), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    #[test]
    fn stale_sources_ambiguous_signers_and_unqualified_subjects_do_not_become_comparisons() {
        let bytes = include_bytes!("../../tests/data/upstream-TestAppxPackage_Win32.appx");
        let directory = super::super::parse(bytes).expect("native ZIP");
        let parent = artifact("pkg.msix", bytes, None);
        let mut captured = Captured(vec![parent.clone()]);
        let mut binding = json!({"checks":[]});
        for name in ["AppxBlockMap.xml", "AppxManifest.xml", "AppxSignature.p7x"] {
            let entry = directory.entries.iter().find(|e| e.name == name).expect("native footprint");
            let plain = super::super::map_bytes(bytes, entry).expect("native content");
            let mut source = artifact(&format!("pkg.msix/{name}"), &plain, Some("pkg.msix"));
            let mut out = Output::default();
            match name {
                "AppxBlockMap.xml" => {
                    crate::msix_blockmap::analyze_file(&source, &plain, &mut out);
                    binding["checks"] = json!([{"label":"AXBM","status":"declared-digest-agrees","computed":aa_core::sha256_hex(&plain)}]);
                }
                "AppxManifest.xml" => crate::appx::analyze(&source, &plain, &mut out),
                _ => {
                    source.facts.insert("windows.msix-signature".into(), crate::msix_signature::parse(&plain).expect("native CMS"));
                    binding["signature_sha256"] = json!(aa_core::sha256_hex(&plain));
                }
            }
            for fact in out.facts {
                source.facts.insert(fact.key, fact.value);
            }
            captured.0.push(source);
        }
        for case in 0..11 {
            let mut tree = captured.clone();
            match case {
                1 => tree.0[3].digests.as_mut().expect("P7X digest").sha256 = "00".repeat(32),
                2 => tree.0[3].facts.get_mut("windows.msix-signature").expect("CMS")["source_sha256"] = json!("stale"),
                3 => {
                    let cms = tree.0[3].facts.get_mut("windows.msix-signature").expect("CMS")["cms"].as_array_mut().expect("signers");
                    cms.push(cms[0].clone());
                }
                4 => tree.0[3].facts.get_mut("windows.msix-signature").expect("CMS")["cms"][0]["signer_certificate_candidates"] = json!(2),
                5 => {
                    tree.0[3].facts.get_mut("windows.msix-signature").expect("CMS")["cms"][0]["msix_publisher_subject"]["status"] =
                        json!("unresolved")
                }
                6 => tree.0[2].facts.get_mut("windows.msix").expect("identity")["source_sha256"] = json!("stale"),
                7 => tree.0[2].facts.get_mut("windows.msix").expect("identity")["identity_status"] = json!("ambiguous"),
                8 => tree.0[2].parent = Some("other.msix".into()),
                9 => tree.0[1].facts.get_mut("windows.msix-blockmap").expect("map")["source_sha256"] = json!("stale"),
                10 => {
                    let files = tree.0[1].facts.get_mut("windows.msix-blockmap").expect("map")["files"].as_array_mut().expect("files");
                    let manifest = files.iter().find(|r| r["path"] == "AppxManifest.xml").expect("manifest declaration").clone();
                    files.push(manifest);
                }
                _ => {}
            }
            let mut out = Output::default();
            let fact = analyze(&tree, &parent, bytes, &directory, &mut signature::Budget::default(), &binding, &mut out);
            assert_eq!(fact["publisher_checked"], case == 0 || case >= 9, "case {case}: {fact}");
            if case == 0 || case >= 9 {
                assert_eq!(fact["matches"], true);
                assert_eq!(fact["manifest_signed_coverage"]["established"], case == 0);
            }
            assert!(!out.findings.iter().any(|f| f.rule == "windows.msix-publisher-mismatch"));
        }
    }
}
