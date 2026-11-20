//! Local disk access policy shared by listing and every later artifact read.

use std::fs::{File, Metadata};
use std::io;
use std::path::Path;

pub fn metadata(path: &Path) -> io::Result<Metadata> {
    #[cfg(windows)]
    {
        check(path)?;
        std::fs::symlink_metadata(path)
    }
    #[cfg(not(windows))]
    std::fs::metadata(path)
}

pub fn open(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        check(path)?;
        // Do not follow a final reparse point swapped in after the metadata check.
        // OPEN_NO_RECALL supplements the attribute checks; it is not a sandbox.
        let file = std::fs::OpenOptions::new().read(true).custom_flags(0x0020_0000 | 0x0010_0000).open(path)?;
        check_attributes(&file.metadata()?)?;
        Ok(file)
    }
    #[cfg(not(windows))]
    File::open(path)
}

#[cfg(windows)]
fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

#[cfg(windows)]
fn check_attributes(metadata: &Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    match attribute_reason(metadata.file_attributes(), metadata.is_dir()) {
        Some(reason) => Err(denied(reason)),
        None => Ok(()),
    }
}

#[cfg(windows)]
fn attribute_reason(attributes: u32, directory: bool) -> Option<&'static str> {
    if attributes & 0x400 != 0 {
        Some("reparse points are not followed")
    } else if attributes & (0x1000 | 0x40000 | 0x400000) != 0 {
        Some("content requiring remote recall is not read")
    } else if !directory && attributes & 0x4000 != 0 {
        // An encrypted directory sets the creation default; it can contain unencrypted files.
        Some("encrypted file content is not read")
    } else {
        None
    }
}

#[cfg(windows)]
fn ordinary_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else { return false };
    let stem = name.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
    let port = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"));
    let reserved_port = port.is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"));
    !name.contains(':')
        && !name.ends_with(['.', ' '])
        && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        && !reserved_port
}

#[cfg(windows)]
pub fn check(path: &Path) -> io::Result<()> {
    use std::path::{Component, PathBuf, Prefix};
    let absolute = std::path::absolute(path)?;
    // Validate the entire namespace before querying even the root's metadata.
    for part in absolute.components() {
        match part {
            Component::Prefix(prefix) if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {
                return Err(denied("remote and device path namespaces are not read"));
            }
            Component::Normal(name) if !ordinary_name(name) => {
                return Err(denied("ambiguous Windows names and named stream paths are not read"));
            }
            _ => {}
        }
    }
    let mut current = PathBuf::new();
    for part in absolute.components() {
        current.push(part.as_os_str());
        if matches!(part, Component::Normal(_) | Component::ParentDir) {
            check_attributes(&std::fs::symlink_metadata(&current)?)?;
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn windows_attributes_and_aliases_have_explicit_boundaries() {
        for attributes in [0x400, 0x1000, 0x40000, 0x400000, 0x4000] {
            assert!(attribute_reason(attributes, false).is_some());
        }
        assert!(attribute_reason(0x4000, true).is_none());
        assert!(attribute_reason(0x800, false).is_none(), "ordinary compression is allowed");
        for name in ["CON", "nul.txt", "com1.exe", "LPT²", "x:secret", "x.", "x "] {
            assert!(!ordinary_name(name.as_ref()), "{name}");
        }
        assert!(ordinary_name("中文 file.txt".as_ref()));
        for path in [r"\\server\share\sample", r"\\.\PhysicalDrive0", r"C:\input:secret", r"C:\CON.txt"] {
            assert_eq!(
                check(Path::new(path)).expect_err("namespace must be refused before access").kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
}
