//! The tree pass: bundles, their executables' signatures, and everything that needs more than
//! one file to say.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::{Value, json};

use crate::bundle::{self, Bundle, Layout};
use crate::extras;
use crate::info::{self, finding, shown};
use crate::signing::{self, main_slice, slices};

/// Top-level bundles reported in full.
const MAX_BUNDLES: usize = 12;
/// Mach-O files outside any bundle whose signature is reported in full.
const MAX_STANDALONE: usize = 10;
/// Bundles listed in the summary fact.
const MAX_SUMMARY_BUNDLES: usize = 500;
/// Files named as evidence in one aggregate finding.
const MAX_EVIDENCE: usize = 25;

fn encryption(file: &Artifact) -> Option<(&Value, &Value)> {
    slices(file).iter().find_map(|s| Some((s, s.get("encryption").filter(|e| e["id"].as_u64().is_some_and(|id| id != 0))?)))
}

/// Reports FairPlay encryption of `file`, as a finding and as a limitation.
fn fairplay(file: &Artifact, out: &mut Output) -> bool {
    let Some((slice, encryption)) = encryption(file) else { return false };
    out.finding(
        finding(Section::Code, "apple.fairplay", Confidence::Verified, Severity::Low)
            .param("file", file.name())
            .param("arch", slice["arch"].as_str().unwrap_or("?"))
            .param("bytes", encryption["size"].clone())
            .evidence(Evidence::bytes(
                file,
                encryption["command_offset"].as_u64().unwrap_or(0),
                20,
                json!({ "cryptoff": encryption["offset"], "cryptsize": encryption["size"], "cryptid": encryption["id"] }),
            )),
    );
    out.limitation(
        "apple.fairplay-encrypted",
        Some(file),
        Some(format!(
            "{} bytes of {} are encrypted (cryptid {})",
            encryption["size"],
            slice["arch"].as_str().unwrap_or("?"),
            encryption["id"]
        )),
    );
    true
}

/// Everything about one top-level bundle. Returns the team that signed its main executable.
///
/// With `brief`, the signature is reported as for loose code: who signed and what is wrong;
/// the returned page count feeds the summary of code found intact.
fn report_bundle<'t>(
    tree: &'t dyn Tree,
    bundles: &[Bundle<'t>],
    index: usize,
    brief: bool,
    subjects: &mut BTreeSet<&'t str>,
    cms_examined: &mut bool,
    out: &mut Output,
) -> (Option<String>, Option<(&'t Artifact, u64)>) {
    let bundle = &bundles[index];
    let plist = match &bundle.plist {
        Ok(plist) => plist,
        Err(_) => return (None, None),
    };
    let bundle_id = info::identity(bundle, plist, out);
    info::capabilities(bundle, plist, out);
    info::transport_security(bundle, plist, out);

    let mut team = None;
    let mut intact = None;
    let executable = bundle.executable_path();
    let file = executable.as_deref().and_then(|path| tree.get(path));
    match (bundle.string("CFBundleExecutable"), file) {
        (None, _) => {}
        (Some(name), None) => out.finding(
            finding(Section::Anomalies, "apple.executable-missing", Confidence::Verified, Severity::Low)
                .param("bundle", bundle.name())
                .param("executable", name)
                .evidence(Evidence::field(bundle.info, "CFBundleExecutable", name)),
        ),
        (Some(name), Some(file)) if slices(file).is_empty() => out.finding(
            finding(Section::Anomalies, "apple.executable-not-macho", Confidence::Verified, Severity::Low)
                .param("bundle", bundle.name())
                .param("executable", name)
                .param("mime", file.mime())
                .evidence(Evidence::field(bundle.info, "CFBundleExecutable", name))
                .evidence(Evidence::whole(file, file.mime())),
        ),
        (Some(name), Some(file)) => {
            subjects.insert(file.path.as_str());
            let archs: Vec<&str> = slices(file).iter().filter_map(|s| s["arch"].as_str()).collect();
            let slice = main_slice(file);
            let built = slice.and_then(|s| Some(format!("{} {}", s["platform"].as_str()?, s["min_os"].as_str()?)));
            let mut found = finding(
                Section::Identity,
                if built.is_some() { "apple.executable-built-for" } else { "apple.executable" },
                Confidence::Verified,
                Severity::Info,
            )
            .param("bundle", bundle.name())
            .param("executable", name)
            .param("archs", archs.join(", "))
            .evidence(Evidence::field(bundle.info, "CFBundleExecutable", name))
            .evidence(Evidence::whole(file, json!({ "architectures": archs, "size": file.size })));
            if let Some(built) = built {
                found = found.param("target", built);
            }
            out.finding(found);
            fairplay(file, out);
            let signed = signing::report(tree, file, Some(bundle), brief, out);
            if signed.intact_pages > 0 {
                intact = Some((file, signed.intact_pages));
            }
            *cms_examined |= signed.cms_examined;
            // The signature names the code; the bundle names itself. They normally agree.
            if let (Some(bundle_id), Some(identifier)) = (&bundle_id, main_slice(file).and_then(|s| s["signature"]["identifier"].as_str()))
                && bundle_id != identifier
            {
                out.finding(
                    finding(Section::Anomalies, "apple.identifier-mismatch", Confidence::Verified, Severity::Low)
                        .param("bundle", bundle.name())
                        .param("bundle_id", bundle_id.as_str())
                        .param("identifier", identifier)
                        .evidence(Evidence::field(bundle.info, "CFBundleIdentifier", bundle_id.as_str()))
                        .evidence(Evidence::whole(file, json!({ "signature_identifier": identifier }))),
                );
            }
            let profile_file =
                ["embedded.mobileprovision", "embedded.provisionprofile"].iter().find_map(|name| tree.get(&bundle.rooted(name)));
            if let Some(profile_file) = profile_file
                && let Some(profile) = signing::profile(tree, profile_file, out)
            {
                *cms_examined = true;
                signing::compare_profile(file, profile_file, &profile, &signed, out);
            }
            team = signed.team;
        }
    }
    signing::resources(tree, bundles, bundle, false, out);
    if bundle.layout == Layout::Contents
        && let Some(ticket) = tree.get(&bundle.rooted("CodeResources"))
    {
        out.kind(ticket, "notarization-ticket");
        out.finding(
            finding(Section::Provenance, "apple.notarization-ticket", Confidence::Verified, Severity::Info)
                .param("bundle", bundle.name())
                .param("bytes", ticket.size)
                .evidence(Evidence::whole(ticket, json!({ "size": ticket.size }))),
        );
    }
    extras::privacy(tree, bundle, out);
    extras::embedded(tree, bundles, index, out);
    extras::frameworks(tree, bundle, file, out);
    extras::structure(tree, bundle, out);
    (team, intact)
}

pub fn analyze(tree: &dyn Tree, out: &mut Output) {
    let bundles = bundle::discover(tree);
    let mut cms_examined = false;
    for artifact in tree.artifacts() {
        extras::disk_image(artifact, out);
        cms_examined |= extras::package(artifact, out);
        extras::package_contents(tree, artifact, out);
    }
    for bundle in &bundles {
        out.kind(bundle.info, "info-plist");
        if let Err(error) = &bundle.plist {
            out.limitation("apple.plist-unreadable", Some(bundle.info), Some(error.clone()));
        }
    }

    // IPA: a ZIP whose Payload folder holds the app.
    for bundle in bundles.iter().filter(|b| b.parent.is_none() && b.layout == Layout::Flat) {
        if let Some(archive_path) = bundle.dir.strip_suffix(bundle.name()).and_then(|rest| rest.strip_suffix("/Payload/"))
            && let Some(archive) = tree.get(archive_path)
            && archive.unpacked_by.as_deref() == Some("zip")
        {
            extras::ipa(tree, archive, bundle, out);
        }
    }

    let tops: Vec<usize> = (0..bundles.len()).filter(|index| bundles[*index].parent.is_none()).collect();
    if tops.len() > MAX_BUNDLES {
        out.limitation(
            "apple.findings-capped",
            None,
            Some(format!("{} bundles at the top level; the first {MAX_BUNDLES} were reported in full", tops.len())),
        );
    }
    let mut subjects: BTreeSet<&str> = BTreeSet::new();
    // Team of each fully reported top-level bundle, by index.
    let mut teams: BTreeMap<usize, Option<String>> = BTreeMap::new();
    let mut loose_intact: Vec<&Artifact> = Vec::new();
    let mut loose_pages = 0u64;
    // Apps get the full account. Other bundles do too when there is nothing else to report on.
    let apps = tops.iter().filter(|index| bundles[**index].kind() == "app").count();
    for &index in tops.iter().take(MAX_BUNDLES) {
        let brief = bundles[index].kind() != "app" && (apps > 0 || tops.len() > 1);
        let (team, intact) = report_bundle(tree, &bundles, index, brief, &mut subjects, &mut cms_examined, out);
        teams.insert(index, team);
        if let Some((file, pages)) = intact {
            loose_intact.push(file);
            loose_pages += pages;
        }
    }
    // The bundles at a glance, for whoever reads the report's summary.
    if !bundles.is_empty() {
        let listed: Vec<Value> = bundles
            .iter()
            .enumerate()
            .take(MAX_SUMMARY_BUNDLES)
            .map(|(index, bundle)| {
                let executable = bundle.executable_path().and_then(|path| tree.get(&path));
                let signature = executable.and_then(main_slice).map(|slice| &slice["signature"]);
                json!({
                    "path": bundle.dir,
                    "kind": bundle.kind(),
                    "top_level": bundle.parent.is_none(),
                    "parent": bundle.parent.map(|parent| bundles[parent].dir.as_str()),
                    "bundle_id": bundle.string("CFBundleIdentifier"),
                    "version": bundle.string("CFBundleShortVersionString"),
                    "build": bundle.string("CFBundleVersion"),
                    "executable": executable.map(|file| file.path.as_str()),
                    "architectures": executable.map(|file| slices(file).iter().filter_map(|s| s["arch"].as_str()).collect::<Vec<_>>()),
                    "team_id": teams.get(&index).cloned().flatten().or_else(|| signature.and_then(|s| s["team_id"].as_str().map(str::to_string))),
                    "signing_type": signature.map(|s| if s.is_object() { s["signing_type"].as_str().unwrap_or("other") } else { "unsigned" }),
                    "cdhash": signature.and_then(|s| s["cdhash"].as_str()),
                })
            })
            .collect();
        out.summary(
            "apple.bundles",
            json!({ "bundles": listed, "total": bundles.len(), "truncated": bundles.len() > MAX_SUMMARY_BUNDLES }),
        );
    }

    // Nested bundles: what they add to the app's surface, and whether their seals hold.
    let mut nested_sealed = 0u64;
    let mut first_sealed: Option<&Artifact> = None;
    for bundle in bundles.iter().filter(|b| b.parent.is_some()) {
        if let Ok(plist) = &bundle.plist
            && bundle.kind() == "app-extension"
        {
            info::extension_point(bundle, plist, out);
        }
        if signing::resources(tree, &bundles, bundle, true, out) {
            nested_sealed += 1;
            first_sealed = first_sealed.or(tree.get(&bundle.rooted("_CodeSignature/CodeResources")));
        }
    }
    if let Some(first) = first_sealed {
        out.finding(
            finding(Section::Provenance, "apple.nested-resources-intact", Confidence::Verified, Severity::Info)
                .param("count", nested_sealed)
                .evidence(Evidence::whole(first, json!({ "nested_bundles_intact": nested_sealed }))),
        );
    }

    // Every Mach-O in the tree.
    let machos: Vec<&Artifact> = tree.artifacts().iter().filter(|a| a.facts.contains_key("apple.macho")).collect();
    if machos.is_empty() {
        if cms_examined {
            out.limitation("apple.trust-not-evaluated", None, None);
        }
        return;
    }
    let top_of = |path: &str| tops.iter().copied().find(|index| bundles[*index].contains(path));
    let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
    let mut all_teams: BTreeSet<String> = BTreeSet::new();
    let mut standalone = 0usize;
    let mut unsigned_nested: Vec<&Artifact> = Vec::new();
    let mut foreign_team: BTreeMap<String, Vec<&Artifact>> = BTreeMap::new();
    for &file in &machos {
        let Some(slice) = main_slice(file) else { continue };
        if let Some(error) = slice["error"].as_str() {
            out.limitation("apple.macho-unreadable", Some(file), Some(error.to_string()));
            continue;
        }
        let signature = &slice["signature"];
        let signing_type = if signature.is_object() { signature["signing_type"].as_str().unwrap_or("other") } else { "unsigned" };
        *by_type.entry(signing_type.to_string()).or_default() += 1;
        if let Some(team) = signature["team_id"].as_str() {
            all_teams.insert(team.to_string());
        }
        if subjects.contains(file.path.as_str()) {
            continue;
        }
        let top = top_of(&file.path);
        let loadable = matches!(slice["kind"].as_str(), Some("executable" | "dylib" | "bundle" | "kext"));
        if top.is_none() && loadable {
            // Code that belongs to no bundle is reported on its own.
            standalone += 1;
            if standalone <= MAX_STANDALONE {
                fairplay(file, out);
                let signed = signing::report(tree, file, None, true, out);
                cms_examined |= signed.cms_examined;
                if signed.intact_pages > 0 {
                    loose_intact.push(file);
                    loose_pages += signed.intact_pages;
                }
            }
            continue;
        }
        // Code inside a reported bundle: only what is wrong with it.
        fairplay(file, out);
        if let Some(error) = slice["signature_error"].as_str() {
            out.limitation("apple.signature-unreadable", Some(file), Some(error.to_string()));
        }
        if signature.is_null() && loadable {
            unsigned_nested.push(file);
        }
        cms_examined |= signature["cms"].is_object();
        let mut modified = 0u64;
        let mut broken_slots: BTreeSet<&str> = BTreeSet::new();
        for other in slices(file) {
            for directory in other["signature"]["directories"].as_array().into_iter().flatten() {
                modified += directory["pages"]["mismatched"].as_u64().unwrap_or(0);
                for (slot, outcome) in directory["slots"].as_object().into_iter().flatten() {
                    if outcome == "mismatch" {
                        broken_slots.insert(slot.as_str());
                    }
                }
            }
        }
        if modified > 0 {
            out.finding(
                finding(Section::Provenance, "apple.code-modified", Confidence::Verified, Severity::High)
                    .param("file", file.name())
                    .param("pages", modified)
                    .evidence(Evidence::whole(file, json!({ "mismatched_pages": modified }))),
            );
        }
        for slot in broken_slots {
            out.finding(
                finding(Section::Provenance, "apple.seal-broken", Confidence::Verified, Severity::High)
                    .param("file", file.name())
                    .param("slot", slot)
                    .evidence(Evidence::whole(file, json!({ "slot": slot, "outcome": "mismatch" }))),
            );
        }
        let cms = &signature["cms"];
        if cms["signature"] == "invalid" || cms["digest_matches"] == false {
            out.finding(
                finding(Section::Provenance, "apple.cms-invalid", Confidence::Verified, Severity::High)
                    .param("file", file.name())
                    .evidence(Evidence::whole(
                        file,
                        json!({ "signature": cms["signature"], "message_digest_matches_code_directory": cms["digest_matches"] }),
                    )),
            );
        }
        if let (Some(top), Some(team)) = (top, signature["team_id"].as_str())
            && let Some(Some(expected)) = teams.get(&top)
            && expected != team
        {
            foreign_team.entry(team.to_string()).or_default().push(file);
        }
    }
    if standalone > MAX_STANDALONE {
        out.limitation(
            "apple.findings-capped",
            None,
            Some(format!(
                "{standalone} Mach-O files outside any bundle; the signatures of the first {MAX_STANDALONE} were reported in full"
            )),
        );
    }
    if !loose_intact.is_empty() {
        let mut found = finding(Section::Provenance, "apple.other-code-intact", Confidence::Verified, Severity::Info)
            .param("count", loose_intact.len())
            .param("pages", loose_pages);
        for file in loose_intact.iter().take(MAX_EVIDENCE) {
            found = found.evidence(Evidence::whole(file, json!({ "page_hashes_match": true })));
        }
        out.finding(found);
    }
    let summary = by_type.iter().map(|(kind, count)| format!("{count} {kind}")).collect::<Vec<_>>().join(", ");
    let teams_list: Vec<String> = all_teams.into_iter().collect();
    let mut found = finding(Section::Provenance, "apple.code-summary", Confidence::Verified, Severity::Info)
        .param("count", machos.len())
        .param("summary", summary)
        .param("teams", if teams_list.is_empty() { "-".to_string() } else { shown(&teams_list) });
    for file in machos.iter().take(5) {
        found = found.evidence(Evidence::whole(file, main_slice(file).map(|s| s["signature"]["signing_type"].clone()).unwrap_or_default()));
    }
    out.finding(found);
    if !unsigned_nested.is_empty() {
        let mut found =
            finding(Section::Anomalies, "apple.unsigned-nested", Confidence::Verified, Severity::Low).param("count", unsigned_nested.len());
        for file in unsigned_nested.iter().take(MAX_EVIDENCE) {
            found = found.evidence(Evidence::whole(file, json!({ "LC_CODE_SIGNATURE": null })));
        }
        out.finding(found);
    }
    for (team, files) in foreign_team {
        let mut found = finding(Section::Provenance, "apple.nested-team-differs", Confidence::Verified, Severity::Info)
            .param("team", team.as_str())
            .param("count", files.len());
        for file in files.iter().take(MAX_EVIDENCE) {
            found = found.evidence(Evidence::whole(file, json!({ "team_id": team })));
        }
        out.finding(found);
    }
    if cms_examined {
        out.limitation("apple.trust-not-evaluated", None, None);
    }
}
