//! Ownership markers let the next run recover scratch folders after a supervisor crash.

use std::fs::{File, OpenOptions};
use std::path::Path;

const MARKER: &str = ".owner.lock";

pub fn hold(folder: &Path) -> std::io::Result<File> {
    let marker = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(folder.join(MARKER))?;
    marker.try_lock_shared().map_err(std::io::Error::other)?;
    Ok(marker)
}

fn indirect(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.file_type().is_symlink()
}

/// Removes only recognized direct children with an unlocked ownership marker.
/// A running supervisor or worker holds a shared lock, preventing recovery until both end.
pub fn sweep(root: &Path) -> usize {
    let Ok(root) = root.canonicalize() else { return 0 };
    let Ok(entries) = std::fs::read_dir(&root) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let parts: Vec<_> = name.split('-').collect();
        if parts.len() != 4
            || parts[0] != "worker"
            || parts[1].parse::<u32>().is_err()
            || u128::from_str_radix(parts[2], 16).is_err()
            || parts[3].parse::<u32>().is_err()
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else { continue };
        if !metadata.is_dir() || indirect(&metadata) {
            continue;
        }
        // Verify the resolved target remains a direct child of the intended scratch root.
        let Ok(resolved) = path.canonicalize() else { continue };
        if resolved.parent() != Some(root.as_path()) {
            continue;
        }
        let marker_path = resolved.join(MARKER);
        let Ok(metadata) = std::fs::symlink_metadata(&marker_path) else { continue };
        if !metadata.is_file() || indirect(&metadata) {
            continue;
        }
        let Ok(marker) = OpenOptions::new().read(true).write(true).open(&marker_path) else { continue };
        if marker.try_lock().is_ok() && std::fs::remove_dir_all(&resolved).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_requires_all_owners_to_release_the_marker() {
        let dir = tempfile::tempdir().expect("private scratch root");
        let scratch = dir.path().join("worker-123-abc-0");
        std::fs::create_dir(&scratch).expect("scratch folder");
        std::fs::write(scratch.join("payload"), "temporary bytes").expect("scratch data");
        let parent = hold(&scratch).expect("supervisor ownership");
        let child = hold(&scratch).expect("worker ownership");
        assert_eq!(sweep(dir.path()), 0);
        drop(parent);
        assert_eq!(sweep(dir.path()), 0, "worker is still alive");
        drop(child);
        assert_eq!(sweep(dir.path()), 1);
        assert!(!scratch.exists());
        let unrelated = dir.path().join("worker-not-ours");
        std::fs::create_dir(&unrelated).expect("unrelated folder");
        let marker = hold(&unrelated).expect("unrelated marker");
        drop(marker);
        assert_eq!(sweep(dir.path()), 0);
        assert!(unrelated.exists());
        let unmarked = dir.path().join("worker-123-def-0");
        std::fs::create_dir(&unmarked).expect("unmarked folder");
        assert_eq!(sweep(dir.path()), 0, "a name alone is not proof of ownership");
        assert!(unmarked.exists());
    }

    #[test]
    #[cfg(windows)]
    fn recovery_does_not_follow_a_junction_outside_the_scratch_root() {
        let dir = tempfile::tempdir().expect("private test root");
        let root = dir.path().join("scratch");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&root).expect("scratch root");
        std::fs::create_dir(&outside).expect("external fixture folder");
        std::fs::write(outside.join("data"), "must be preserved").expect("external fixture data");
        drop(hold(&outside).expect("unlocked external marker"));
        let result = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(root.join("worker-123-abc-0"))
            .arg(&outside)
            .output()
            .expect("junction fixture command");
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        assert_eq!(sweep(&root), 0);
        assert_eq!(std::fs::read_to_string(outside.join("data")).expect("preserved data"), "must be preserved");
    }
}
