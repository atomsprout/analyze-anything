//! Toolchain markers, on synthetic bytes: no Go or Rust program is small enough to commit.

use aa_core::Confidence;
use serde_json::json;

use crate::common::{Marks, Rd};
use crate::lang::{Region, detect, go_build_id};

/// A Go 1.18+ build information block: magic, pointer size, flags (inline strings), two
/// length-prefixed strings; the module text sits between 16-byte sentinels.
fn go_block(version: &str, modinfo: &str) -> Vec<u8> {
    let mut block = b"\xff Go buildinf:".to_vec();
    block.extend([8, 2]);
    block.resize(32, 0);
    let wrapped = [&[0x30u8; 16][..], modinfo.as_bytes(), &[0x31u8; 16][..]].concat();
    for text in [version.as_bytes(), &wrapped] {
        // Lengths here fit the two-byte varint form.
        block.extend([(text.len() & 0x7f) as u8 | 0x80, (text.len() >> 7) as u8]);
        block.extend(text);
    }
    block
}

#[test]
fn go_build_information_is_parsed() {
    let modinfo = "path\texample.com/tool/cmd/tool\nmod\texample.com/tool\tv1.2.3\th1:abc=\ndep\tgolang.org/x/sys\tv0.20.0\th1:def=\n\
                   dep\tgithub.com/pkg/errors\tv0.9.1\th1:ghi=\nbuild\t-compiler=gc\nbuild\t-ldflags=\"-X main.token=hunter2\"\nbuild\tGOOS=linux\nbuild\tvcs.revision=0123abcd\n";
    let mut data = vec![0u8; 100];
    data.extend(go_block("go1.22.6", modinfo));
    data.extend([0u8; 50]);
    let found = detect(&Rd::new(&data, true), &Marks::default(), &[], &[], &[]);
    let go = found.languages.iter().find(|l| l.name == "Go").expect("Go detected");
    assert_eq!(go.confidence, Confidence::Derived);
    let (value, offset) = found.go.expect("build information");
    assert_eq!(offset, 100);
    assert_eq!(value["version"], "go1.22.6");
    assert_eq!(value["path"], "example.com/tool/cmd/tool");
    assert_eq!(value["module"], "example.com/tool");
    assert_eq!(value["module_version"], "v1.2.3");
    assert_eq!(value["deps_total"], 2);
    assert_eq!(value["deps"][0], json!({ "path": "golang.org/x/sys", "version": "v0.20.0" }));
    // Linker flags can embed arbitrary values and are not kept.
    assert_eq!(value["settings"], json!({ "-compiler": "gc", "GOOS": "linux", "vcs.revision": "0123abcd" }));
    assert!(!value.to_string().contains("hunter2"));
}

#[test]
fn go_block_with_pointers_or_garbage_yields_no_version() {
    // Before Go 1.18 the block held pointers, which are not followed.
    let mut old = b"\xff Go buildinf:".to_vec();
    old.extend([8, 0]);
    old.resize(64, 0);
    let found = detect(&Rd::new(&old, true), &Marks::default(), &[], &[], &[]);
    assert_eq!(found.go.expect("block found").0, json!({ "format": "pointer", "version": null, "module": null }));

    // An inline block whose strings run off the end, at every truncation, must not panic.
    let block = go_block("go1.22.6", "mod\tx\tv1\t\n");
    for length in 0..block.len() {
        let found = detect(&Rd::new(&block[..length], true), &Marks::default(), &[], &[], &[]);
        assert!(found.go.is_none_or(|(value, _)| value["version"] == "go1.22.6" || value["version"].is_null()));
    }
    // A version string that is not a Go version is not believed.
    assert!(detect(&Rd::new(&go_block("xx1.0", ""), true), &Marks::default(), &[], &[], &[]).go.is_none());
}

#[test]
fn go_build_id_marker() {
    let mut data = vec![0x90u8; 4096];
    data.extend(b"\xff Go build ID: \"abc/def-123\"\n \xff");
    assert_eq!(go_build_id(&data), Some(("abc/def-123".to_string(), 4096)));
    assert_eq!(go_build_id(b"\xff Go build ID: \"unterminated"), None);
}

#[test]
fn rust_markers_and_their_confidence() {
    let hash = "adf8d168af9334a8bf940824fcf4207d01e05ae5";
    let data = format!("xx/rustc/tooshort/yy/rustc/{hash}/library/core/src/fmt/mod.rs").into_bytes();
    let found = detect(&Rd::new(&data, true), &Marks::default(), &[], &[], &[]);
    assert_eq!(found.rustc_commit.as_ref().map(|(h, o)| (h.as_str(), *o)), Some((hash, 20)));
    let rust = found.languages.iter().find(|l| l.name == "Rust").expect("Rust detected");
    assert_eq!(rust.confidence, Confidence::Heuristic, "a string alone is a guess");

    // A runtime symbol or the compiler's own identification is stronger.
    let mut marks = Marks::default();
    marks.see("rust_begin_unwind", 0, false, 64);
    let found = detect(&Rd::new(b"", true), &marks, &[], &[], &[]);
    assert_eq!(found.languages[0].confidence, Confidence::Derived);
    let idents = ["rustc version 1.83.0 (90b35a623 2024-11-26)".to_string()];
    let found = detect(&Rd::new(b"", true), &Marks::default(), &[], &[], &idents);
    assert_eq!((found.languages[0].name, found.languages[0].confidence), ("Rust", Confidence::Derived));
}

#[test]
fn languages_from_libraries_and_sections() {
    let libraries = ["/usr/lib/libc++.1.dylib".to_string(), "/usr/lib/swift/libswiftCore.dylib".to_string()];
    let regions = [Region { name: "__objc_classlist".into(), offset: 0, size: 8 }];
    let found = detect(&Rd::new(&[0u8; 16], true), &Marks::default(), &libraries, &regions, &[]);
    let names: Vec<&str> = found.languages.iter().map(|l| l.name).collect();
    assert_eq!(names, ["Swift", "Objective-C", "C++"]);
    for (library, language) in [("MSVCP140.dll", "C++"), ("libstdc++.so.6", "C++"), ("libstdc++-6.dll", "C++")] {
        let found = detect(&Rd::new(b"", true), &Marks::default(), &[library.to_string()], &[], &[]);
        assert!(found.has(language), "{library}");
    }
    // Nothing recognisable: no language is claimed.
    assert!(detect(&Rd::new(b"plain C program", true), &Marks::default(), &["libc.so.6".to_string()], &[], &[]).languages.is_empty());
}

#[test]
fn symbol_markers() {
    let mut marks = Marks::default();
    for (name, skip, imported) in [
        ("___stack_chk_fail", 1, true),
        ("__memcpy_chk@GLIBC_2.3.4", 0, true),
        ("strcpy", 0, true),
        ("__stack_chk_guard", 0, true),
        ("_objc_release_x19", 1, true),
        ("_ZNSt6vectorIiE9push_backEi", 0, false),
        ("runtime.main", 0, false),
    ] {
        marks.see(name, skip, imported, 0);
    }
    assert_eq!(marks.canary.as_ref().map(|(n, _)| n.as_str()), Some("___stack_chk_fail"));
    assert_eq!(marks.fortified.iter().collect::<Vec<_>>(), ["__memcpy_chk"]);
    assert_eq!(marks.fortifiable.iter().collect::<Vec<_>>(), ["strcpy"]);
    assert!(marks.arc.is_some() && marks.cxx.is_some() && marks.go.is_some() && marks.rust.is_none());
    // A defined function with a fortifiable name is not an import of libc's.
    let mut own = Marks::default();
    own.see("memcpy", 0, false, 0);
    assert!(own.fortifiable.is_empty());
}
