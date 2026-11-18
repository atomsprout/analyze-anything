//! Windows: signatures, .NET, installers and Electron apps.

mod appx;
mod asar;
mod authenticode;
mod behaviour;
mod cab;
mod der;
mod dotnet;
mod inno;
mod installer;
mod msi;
mod nsis;
mod pe;
mod pefile;
mod resources;
mod rules;
mod sfx;
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
        if file.size < 64 {
            return;
        }
        let Ok(bytes) = tree.read(&file.path) else { return };
        pefile::analyze(file, &bytes, out);
        appx::analyze(file, &bytes, out);
        asar_fact(file, &bytes, out);
        if let Some(model) = nsis::analyze(tree, file, &bytes, out)
            .or_else(|| inno::analyze(tree, file, &bytes, out))
            .or_else(|| msi::analyze(file, &bytes, out))
        {
            installer::report(file, &model, out);
        }
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        tree::analyze(tree, out);
    }
}
