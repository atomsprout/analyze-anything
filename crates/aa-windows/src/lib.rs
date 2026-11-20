//! Windows: signatures, .NET, installers and Electron apps.
//!
//! **Unpackers**, tried in this order before the generic archive unpackers:
//! NSIS installers (`nsis`), Inno Setup installers (`inno`), MSI packages (`msi`),
//! cabinets (`cab`), Electron asar archives (`asar`) and self-extracting 7z / ZIP / RAR / CAB
//! stubs (`sfx`, which hands the appended archive on as one child). A PE file whose overlay
//! is none of these is left alone.
//!
//! **Analyzer `windows`.** The file pass reads each PE file on its own (`pefile`): the
//! Authenticode signature with offline verification (`authenticode`), version resource and
//! manifest (`resources`), .NET metadata (`dotnet`), structure checks and packer triage,
//! imports grouped into capabilities (`behaviour`) and kernel-driver facts; it also reads
//! what an installer does (`installer`), verifies the signature an MSI package carries for
//! itself (`msisig`, over the compound-file reader `compound`) and reads `AppxManifest.xml`
//! (`appx`), Windows entry-point declarations (`lnk`, `shortcuts`, `registry`, `tasks`)
//! and INF syntax (`inf`). The tree pass
//! (`tree`) reports what needs several files: who signed what, vendors, capabilities across
//! files, Electron applications and other frameworks recognised from the folder layout.
//!
//! Findings about things that occur once per file in a large folder (version resources, .NET
//! assemblies, TLS callbacks, blank timestamps) are made in the tree pass as one finding with
//! the files as evidence; the per-file detail is in the facts.

mod appx;
mod asar;
mod authenticode;
mod behaviour;
mod cab;
mod compound;
mod der;
mod dotnet;
mod inf;
mod inno;
mod installer;
mod lnk;
mod msi;
mod msisig;
mod nsis;
mod pe;
mod pefile;
mod references;
mod registry;
mod resources;
mod rules;
mod sfx;
mod shortcuts;
mod tasks;
mod text;
mod tree;

use aa_core::Artifact;
use aa_core::plugin::{Analyzer, Output, Rule, Tree, Unpacker};

/// Analyzer id: the prefix of every rule id and fact key of this crate.
const ID: &str = "windows";

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(Windows)]
}

/// The unpackers this crate provides, most specific first.
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![
        Box::new(nsis::Nsis),
        Box::new(inno::Inno),
        Box::new(msi::Msi),
        Box::new(cab::Cab),
        Box::new(asar::AsarUnpacker),
        Box::new(sfx::Sfx),
    ]
}

struct Windows;

/// Records what an asar archive holds and whether its contents match the hashes in its header.
fn asar_fact(file: &Artifact, bytes: &[u8], out: &mut Output) {
    // Same cheap test as the unpacker: the fixed pickle field and the opening brace of the JSON.
    if pe::u32_at(bytes, 0) != Some(4) || bytes.get(16) != Some(&b'{') {
        return;
    }
    let Ok(archive) = asar::parse(bytes) else { return };
    let (with_hash, matching, failed) = archive.verify(bytes);
    out.fact(
        file,
        "windows.asar",
        serde_json::json!({
            "files": archive.files.len(),
            "unpacked_files": archive.unpacked.len(),
            "links": archive.links,
            "truncated": archive.truncated,
            "files_with_integrity": with_hash,
            "integrity_verified": matching,
            "integrity_failed": failed.iter().take(200).collect::<Vec<_>>(),
        }),
    );
}

impl Analyzer for Windows {
    fn id(&self) -> &'static str {
        ID
    }

    fn rules(&self) -> &'static [Rule] {
        rules::RULES
    }

    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        nsis::script_note(tree, file, out);
        if file.size < 64 && !matches!(file.extension().as_deref(), Some("url" | "lnk" | "reg" | "inf")) {
            return;
        }
        let Ok(bytes) = tree.read(&file.path) else { return };
        shortcuts::analyze(file, &bytes, out);
        lnk::analyze(file, &bytes, out);
        registry::analyze(file, &bytes, out);
        tasks::analyze(file, &bytes, out);
        inf::analyze(file, &bytes, out);
        pefile::analyze(file, &bytes, out);
        appx::analyze(file, &bytes, out);
        asar_fact(file, &bytes, out);
        let model = nsis::analyze(tree, file, &bytes, out)
            .or_else(|| inno::analyze(tree, file, &bytes, out))
            .or_else(|| msi::analyze(file, &bytes, out));
        msisig::analyze(file, &bytes, model.as_ref().is_some_and(|m| m.kind == "MSI"), out);
        if let Some(model) = model {
            installer::report(file, &model, out);
        }
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        tree::analyze(tree, out);
    }
}
