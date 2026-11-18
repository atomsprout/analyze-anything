//! Field-by-field comparison with goblin, an independent parser used only by the tests.

use std::collections::BTreeSet;

use aa_core::plugin::Output;
use goblin::mach::{Mach, MachO, SingleArch};
use serde_json::Value;

use super::{fact, names};

fn set(items: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    items.into_iter().collect()
}

/// Compares everything both parsers read. Returns what kind of file it was.
pub fn check(bytes: &[u8], out: &Output) -> &'static str {
    match out.kinds.first().map(|(_, kind)| kind.as_str()) {
        Some("elf") => {
            elf(bytes, out);
            "elf"
        }
        Some("pe") => {
            pe(bytes, out);
            "pe"
        }
        Some("macho") => {
            let reference = MachO::parse(bytes, 0).expect("goblin parses the Mach-O file");
            let facts = |key: &str| fact(out, &format!("binary.{key}")).clone();
            macho(&reference, &facts);
            "macho"
        }
        Some("macho-fat") => {
            let Mach::Fat(fat) = Mach::parse(bytes).expect("goblin parses the universal file") else {
                panic!("goblin sees no universal file")
            };
            let slices = fact(out, "binary.slices").as_array().expect("slices").clone();
            assert_eq!(slices.len(), fat.narches);
            for (index, arch) in fat.iter_arches().enumerate() {
                let arch = arch.expect("fat arch");
                assert_eq!(slices[index]["offset"], arch.offset);
                assert_eq!(slices[index]["size"], arch.size);
                assert_eq!(slices[index]["cputype"], arch.cputype);
                if let SingleArch::MachO(reference) = fat.get(index).expect("slice") {
                    let slice = slices[index].clone();
                    macho(&reference, &|key: &str| slice[key].clone());
                }
            }
            "macho-fat"
        }
        other => panic!("unexpected kind {other:?}"),
    }
}

fn elf(bytes: &[u8], out: &Output) {
    let reference = goblin::elf::Elf::parse(bytes).expect("goblin parses the ELF file");
    let header = fact(out, "binary.header");
    assert_eq!(header["machine"], reference.header.e_machine);
    assert_eq!(header["elf_type"], reference.header.e_type);
    assert_eq!(header["entry"], reference.entry);
    assert_eq!(header["bits"], if reference.is_64 { 64 } else { 32 });
    assert_eq!(header["endian"], if reference.little_endian { "little" } else { "big" });

    let sections = fact(out, "binary.sections")["sections"].as_array().expect("sections").clone();
    assert_eq!(sections.len(), reference.section_headers.len());
    for (mine, theirs) in sections.iter().zip(&reference.section_headers) {
        assert_eq!(mine["name"].as_str(), reference.shdr_strtab.get_at(theirs.sh_name));
        assert_eq!(mine["address"], theirs.sh_addr);
        assert_eq!(mine["offset"], theirs.sh_offset);
        assert_eq!(mine["size"], theirs.sh_size);
        assert_eq!(mine["entsize"], theirs.sh_entsize);
    }
    let segments = fact(out, "binary.segments")["segments"].as_array().expect("segments").clone();
    assert_eq!(segments.len(), reference.program_headers.len());
    for (mine, theirs) in segments.iter().zip(&reference.program_headers) {
        assert_eq!(mine["offset"], theirs.p_offset);
        assert_eq!(mine["vaddr"], theirs.p_vaddr);
        assert_eq!(mine["filesz"], theirs.p_filesz);
        assert_eq!(mine["memsz"], theirs.p_memsz);
        let flags = mine["flags"].as_str().expect("flags");
        assert_eq!(
            (flags.contains('r'), flags.contains('w'), flags.contains('x')),
            (theirs.is_read(), theirs.is_write(), theirs.is_executable())
        );
    }

    assert_eq!(names(fact(out, "binary.libraries"), "libraries"), reference.libraries);
    let linking = fact(out, "binary.linking");
    assert_eq!(linking["soname"].as_str(), reference.soname);
    assert_eq!(linking["interp"].as_str(), reference.interpreter);
    let joined = |value: &Value| value.as_array().expect("paths").iter().filter_map(Value::as_str).collect::<Vec<_>>().join(":");
    assert_eq!(joined(&linking["rpath"]), reference.rpaths.join(":"));
    assert_eq!(joined(&linking["runpath"]), reference.runpaths.join(":"));

    if reference.dynsyms.is_empty() {
        return;
    }
    // Undefined means section index 0, as readelf shows it. (goblin's own `is_import` goes by a
    // zero value instead, which misses functions given a PLT address in non-PIE executables.)
    let dynamic_names = |import: bool| {
        set(reference
            .dynsyms
            .iter()
            .filter(|s| (s.st_shndx == 0) == import && s.st_name != 0 && matches!(s.st_bind(), 1 | 2) && !matches!(s.st_type(), 3 | 4))
            .filter(|s| import || matches!(s.st_visibility(), 0 | 3))
            .filter_map(|s| reference.dynstrtab.get_at(s.st_name).map(str::to_string))
            .filter(|n| !n.is_empty()))
    };
    // goblin sizes the dynamic symbol table from the hash tables and can stop short of its end
    // (seen on llvm-config: readelf lists 204 entries, goblin fewer). So its names must all be
    // among ours, and the sets must be equal whenever it read as many entries as the section holds.
    let section_entries = reference.section_headers.iter().find(|s| s.sh_type == 11).map(|s| s.sh_size / s.sh_entsize.max(1));
    let complete = section_entries.is_none_or(|n| n == reference.dynsyms.len() as u64);
    for (key, import) in [("binary.imports", true), ("binary.exports", false)] {
        let mine = fact(out, key);
        let theirs = dynamic_names(import);
        if mine["truncated"] == false {
            let ours = set(names(mine, "symbols"));
            assert!(theirs.is_subset(&ours), "{key}: goblin has names we lack");
            if complete {
                assert_eq!(ours, theirs, "{key}");
            }
        }
        // A name can occur more than once in the table; the count covers every entry.
        assert!(mine["count"].as_u64().expect("count") >= theirs.len() as u64);
    }
}

fn pe(bytes: &[u8], out: &Output) {
    let reference = goblin::pe::PE::parse(bytes).expect("goblin parses the PE file");
    let header = fact(out, "binary.header");
    assert_eq!(header["pe32plus"], reference.is_64);
    assert_eq!(header["file_type"] == "dll", reference.is_lib);
    assert_eq!(header["entry"], reference.entry);
    assert_eq!(header["image_base"], reference.image_base);
    assert_eq!(header["machine"], reference.header.coff_header.machine);
    assert_eq!(header["timestamp"], reference.header.coff_header.time_date_stamp);
    let optional = reference.header.optional_header.expect("optional header");
    assert_eq!(header["dll_characteristics_raw"], optional.windows_fields.dll_characteristics);
    assert_eq!(header["subsystem_raw"], optional.windows_fields.subsystem);
    assert_eq!(header["checksum"], optional.windows_fields.check_sum);
    assert_eq!(header["size_of_image"], optional.windows_fields.size_of_image);

    let sections = fact(out, "binary.sections")["sections"].as_array().expect("sections").clone();
    assert_eq!(sections.len(), reference.sections.len());
    for (mine, theirs) in sections.iter().zip(&reference.sections) {
        assert_eq!(mine["name"].as_str().expect("name"), theirs.name().expect("section name"));
        assert_eq!(mine["virtual_address"], theirs.virtual_address);
        assert_eq!(mine["virtual_size"], theirs.virtual_size);
        assert_eq!(mine["offset"], theirs.pointer_to_raw_data);
        assert_eq!(mine["size"], theirs.size_of_raw_data);
        assert_eq!(mine["characteristics"], theirs.characteristics);
    }

    // goblin lists ordinary imports only; delay-loaded libraries are compared against llvm-readobj by hand.
    let libraries = fact(out, "binary.libraries");
    let ordinary: Vec<String> = libraries["libraries"]
        .as_array()
        .expect("libraries")
        .iter()
        .filter(|l| l["kind"] == "import")
        .map(|l| l["name"].as_str().expect("name").to_string())
        .collect();
    assert_eq!(set(ordinary), set(reference.libraries.iter().map(|l| l.to_string())));
    let imports = fact(out, "binary.imports");
    if imports["truncated"] == false {
        let delay: BTreeSet<&str> = libraries["libraries"]
            .as_array()
            .expect("libraries")
            .iter()
            .filter(|l| l["kind"] == "delay-import")
            .filter_map(|l| l["name"].as_str())
            .collect();
        let mine = set(imports["symbols"]
            .as_array()
            .expect("symbols")
            .iter()
            .filter(|s| !delay.contains(s["library"].as_str().expect("library")))
            .map(|s| format!("{}!{}", s["library"].as_str().expect("library"), s["name"].as_str().expect("name"))));
        let theirs = set(reference
            .imports
            .iter()
            .map(|i| if i.name.starts_with("ORDINAL ") { format!("{}!#{}", i.dll, i.ordinal) } else { format!("{}!{}", i.dll, i.name) }));
        assert_eq!(mine, theirs);
    }
    let exports = fact(out, "binary.exports");
    if exports["truncated"] == false {
        let theirs = set(reference.exports.iter().filter_map(|e| e.name.map(str::to_string)));
        assert_eq!(set(names(exports, "symbols")), theirs);
        for symbol in exports["symbols"].as_array().expect("symbols") {
            let theirs = reference.exports.iter().find(|e| e.name == symbol["name"].as_str()).expect("export");
            assert_eq!(symbol["address"], theirs.rva, "{}", symbol["name"]);
        }
    }
    let pdb = &fact(out, "binary.debug")["pdb"];
    match reference.debug_data.and_then(|d| d.codeview_pdb70_debug_info) {
        Some(theirs) => {
            let end = theirs.filename.iter().position(|b| *b == 0).unwrap_or(theirs.filename.len());
            assert_eq!(pdb["path"].as_str().expect("pdb path").as_bytes(), &theirs.filename[..end]);
            assert_eq!(pdb["age"], theirs.age);
            // The GUID's first three fields are little-endian; undo that to compare raw bytes.
            let hex: String = pdb["guid"].as_str().expect("guid").chars().filter(|c| *c != '-').collect();
            let raw: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex")).collect();
            let s = theirs.signature;
            assert_eq!(raw, [s[3], s[2], s[1], s[0], s[5], s[4], s[7], s[6], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]]);
        }
        None => assert!(pdb.is_null()),
    }
}

fn macho(reference: &MachO, facts: &dyn Fn(&str) -> Value) {
    let header = facts("header");
    assert_eq!(header["cputype"], reference.header.cputype);
    assert_eq!(header["filetype_raw"], reference.header.filetype);
    assert_eq!(header["flags_raw"], reference.header.flags);
    assert_eq!(header["endian"], if reference.little_endian { "little" } else { "big" });
    if header["file_type"] == "executable" && !reference.old_style_entry {
        assert_eq!(header["entry"], reference.entry);
    }
    assert_eq!(facts("macho")["load_commands"].as_array().expect("commands").len(), reference.load_commands.len());

    let segments = facts("segments");
    let segments = segments["segments"].as_array().expect("segments");
    let mut sections = Vec::new();
    for (mine, theirs) in segments.iter().zip(reference.segments.iter()) {
        assert_eq!(mine["name"].as_str().expect("name"), theirs.name().expect("segment name"));
        assert_eq!(mine["vmaddr"], theirs.vmaddr);
        assert_eq!(mine["vmsize"], theirs.vmsize);
        assert_eq!(mine["fileoff"], theirs.fileoff);
        assert_eq!(mine["filesize"], theirs.filesize);
        assert_eq!(mine["nsects"], theirs.nsects);
        sections.extend(theirs.sections().expect("sections").into_iter().map(|(section, _)| section));
    }
    assert_eq!(segments.len(), reference.segments.len());
    let mine = facts("sections");
    let mine = mine["sections"].as_array().expect("sections");
    assert_eq!(mine.len(), sections.len());
    for (mine, theirs) in mine.iter().zip(&sections) {
        assert_eq!(mine["name"].as_str().expect("name"), theirs.name().expect("section name"));
        assert_eq!(mine["segment"].as_str().expect("segment"), theirs.segname().expect("segment name"));
        assert_eq!(mine["address"], theirs.addr);
        assert_eq!(mine["size"], theirs.size);
        assert_eq!(mine["offset"], theirs.offset);
        assert_eq!(mine["flags"], theirs.flags);
    }

    // goblin's list starts with a placeholder for the image itself.
    assert_eq!(names(&facts("libraries"), "libraries"), reference.libs.iter().skip(1).map(|l| l.to_string()).collect::<Vec<_>>());
    let linking = facts("linking");
    let rpaths: Vec<&str> = linking["rpaths"].as_array().expect("rpaths").iter().filter_map(Value::as_str).collect();
    assert_eq!(rpaths, reference.rpaths);
    assert_eq!(linking["install_name"].as_str(), reference.name);

    if reference.symbols.is_none() {
        return;
    }
    let undefined = set(reference
        .symbols()
        .filter_map(Result::ok)
        .filter(|(name, n)| !name.is_empty() && !n.is_stab() && n.is_undefined() && n.is_global())
        .map(|(name, _)| name.to_string()));
    let imports = facts("imports");
    if imports["truncated"] == false {
        assert_eq!(set(names(&imports, "symbols")), undefined);
    }
}
