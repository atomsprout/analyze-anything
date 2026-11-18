//! The `apple` analyzer.

use aa_core::Artifact;
use aa_core::plugin::{Analyzer, Output, Rule, Tree};

use crate::inspect;

pub struct Apple;

pub const ID: &str = "apple";

impl Analyzer for Apple {
    fn id(&self) -> &'static str {
        ID
    }

    fn rules(&self) -> &'static [Rule] {
        crate::rules::RULES
    }

    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        // Every format handled here is recognised by magic bytes, whatever the file is called.
        if file.size < 8 {
            return;
        }
        let Ok(bytes) = tree.read(&file.path) else { return };
        if let Some(fact) = inspect::macho_fact(&bytes) {
            out.kind(file, "macho");
            out.fact(file, "apple.macho", fact);
        } else if file.is("dmg") {
            if let Some(fact) = inspect::dmg_fact(&bytes) {
                out.fact(file, "apple.dmg", fact);
            }
        } else if file.is("xar")
            && let Some(fact) = inspect::xar_fact(&bytes)
        {
            out.fact(file, "apple.xar", fact);
        }
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        crate::tree::analyze(tree, out);
    }
}
