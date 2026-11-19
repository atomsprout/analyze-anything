//! Lists the files of a folder in a stable order, without following symbolic links.

use std::path::{Path, PathBuf};

use aa_core::Limitation;

pub struct Entry {
    /// Path relative to the input, with `/` separators.
    pub path: String,
    pub on_disk: PathBuf,
}

pub struct Listing {
    pub entries: Vec<Entry>,
    pub limitations: Vec<Limitation>,
    /// True when `max_files` stopped the listing.
    pub truncated: bool,
}

pub fn list(root: &Path, max_files: u64) -> Listing {
    let mut listing = Listing { entries: Vec::new(), limitations: Vec::new(), truncated: false };
    // Folders still to visit, as (path on disk, path inside the tree). Depth-first, sorted.
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = pending.pop() {
        let shown = if prefix.is_empty() { None } else { Some(prefix.trim_end_matches('/').to_string()) };
        let reader = match std::fs::read_dir(&dir) {
            Ok(reader) => reader,
            Err(error) => {
                listing.limitations.push(Limitation { code: "read_failed".into(), artifact: shown, detail: Some(error.to_string()) });
                continue;
            }
        };
        let mut children: Vec<(String, PathBuf, std::fs::FileType)> = Vec::new();
        for child in reader {
            let described = child.and_then(|c| c.file_type().map(|t| (c.file_name().to_string_lossy().into_owned(), c.path(), t)));
            match described {
                Ok(child) => children.push(child),
                Err(error) => listing.limitations.push(Limitation {
                    code: "read_failed".into(),
                    artifact: shown.clone(),
                    detail: Some(error.to_string()),
                }),
            }
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));
        let mut subfolders = Vec::new();
        for (name, on_disk, file_type) in children {
            let path = format!("{prefix}{name}");
            if file_type.is_symlink() {
                listing.limitations.push(Limitation { code: "symlink_skipped".into(), artifact: Some(path), detail: None });
            } else if file_type.is_dir() {
                subfolders.push((on_disk, format!("{path}/")));
            } else if file_type.is_file() {
                if listing.entries.len() as u64 >= max_files {
                    if !listing.truncated {
                        listing.limitations.push(Limitation {
                            code: "limit_reached".into(),
                            artifact: None,
                            detail: Some(format!("only the first {max_files} files were listed")),
                        });
                    }
                    listing.truncated = true;
                } else {
                    listing.entries.push(Entry { path, on_disk });
                }
            } else {
                listing.limitations.push(Limitation { code: "special_file_skipped".into(), artifact: Some(path), detail: None });
            }
        }
        // Reversed so the stack pops them in sorted order.
        pending.extend(subfolders.into_iter().rev());
    }
    listing.entries.sort_by(|a, b| a.path.cmp(&b.path));
    listing
}
