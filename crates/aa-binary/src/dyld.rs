//! The tables dyld itself reads in a Mach-O image: the export trie, the import table of chained
//! fixups, and the classic bind opcode streams.
//!
//! These say what an image imports and exports even when its symbol table is stripped or gone.
//! The layouts follow `<mach-o/loader.h>` and `<mach-o/fixup-chains.h>`. Each parser takes the
//! bytes of one table, already cut out of the file, and calls `visit` for what it finds; what was
//! found before a defect stays found, and the defect is returned as a [`Problem`].
//!
//! All three are hostile input. Work is bounded by the size of the table: a trie node is entered
//! at most once (which also ends cycles), the bytes scanned for names are budgeted, depth is
//! capped, and nothing is allocated in proportion to a count read from the file.

use memchr::memchr;

use crate::common::{MAX_NAME, Rd, text};

/// Frames on the trie walk's stack at most. A sound trie is no deeper than its longest name.
const MAX_TRIE_DEPTH: usize = 16_384;

const EXPORT_KIND_MASK: u64 = 0x03;
const EXPORT_KIND_ABSOLUTE: u64 = 0x02;
const EXPORT_REEXPORT: u64 = 0x08;
const EXPORT_STUB_AND_RESOLVER: u64 = 0x10;

/// `BIND_SPECIAL_DYLIB_WEAK_LOOKUP`: the symbol is found by weak-definition coalescing.
pub const ORDINAL_WEAK_LOOKUP: i64 = -3;

/// Why a table was not read to its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The table contradicts itself or points outside itself.
    Malformed(&'static str),
    /// The table is sound as far as can be told, but in a form this parser does not read.
    Unsupported(&'static str),
}

/// An unsigned LEB128 number at `*pos`, which is moved past it. `None` when the number is cut off
/// or does not fit 64 bits.
pub fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos)?;
        *pos = pos.checked_add(1)?;
        let bits = u64::from(byte & 0x7f);
        if shift >= 64 || (bits << shift) >> shift != bits {
            return None;
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

/// Moves `*pos` past a signed LEB128 number. `None` when it is cut off or longer than ten bytes.
fn skip_sleb(data: &[u8], pos: &mut usize) -> Option<()> {
    for _ in 0..10 {
        let byte = *data.get(*pos)?;
        *pos = pos.checked_add(1)?;
        if byte & 0x80 == 0 {
            return Some(());
        }
    }
    None
}

/// The NUL-terminated name at `at`: its text (cut at [`MAX_NAME`] bytes) and the offset just past
/// the terminator. `None` when no terminator follows.
fn name_at(data: &[u8], at: usize) -> Option<(String, usize)> {
    let rest = data.get(at..)?;
    let end = memchr(0, rest)?;
    let name = text(rest.get(..end.min(MAX_NAME))?);
    Some((name, at.checked_add(end)?.checked_add(1)?))
}

/// One exported symbol of an export trie.
#[derive(Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    /// The raw `EXPORT_SYMBOL_FLAGS_*` bits.
    pub flags: u64,
    /// Offset from the start of the image (the mach header), or the value itself when
    /// `absolute`. `None` for a re-export.
    pub address: Option<u64>,
    pub absolute: bool,
    /// For a symbol passed on from another library: that library's ordinal, and the name it has
    /// there when it differs.
    pub reexport: Option<(u64, Option<String>)>,
    /// Offset of the symbol's node in the trie.
    pub at: u64,
}

struct Frame {
    /// Where the next child record of this node starts.
    cursor: usize,
    /// Child records not yet followed.
    left: u8,
    /// Length of the name accumulated on the way to this node.
    name_len: usize,
}

/// Walks the export trie in `trie`, calling `visit` for every exported symbol.
pub fn export_trie(trie: &[u8], mut visit: impl FnMut(Export)) -> Option<Problem> {
    walk_trie(trie, &mut visit).err().map(Problem::Malformed)
}

fn walk_trie(trie: &[u8], visit: &mut dyn FnMut(Export)) -> Result<(), &'static str> {
    const CUT: &str = "a node of the export trie is cut off";
    const OUTSIDE: &str = "a child offset in the export trie points outside the trie";
    if trie.is_empty() {
        return Ok(());
    }
    // One flag per byte of the trie; the trie is part of a file already in memory.
    let mut entered = vec![false; trie.len()];
    // Every sound trie stores each edge label once, so its labels total less than its size.
    let mut budget = trie.len().saturating_mul(4).saturating_add(64);
    let mut name: Vec<u8> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut next = Some(0usize);
    loop {
        if let Some(node) = next.take() {
            let seen = entered.get_mut(node).ok_or(OUTSIDE)?;
            if *seen {
                return Err("the export trie reaches a node twice (a cycle or a shared node)");
            }
            *seen = true;
            if stack.len() >= MAX_TRIE_DEPTH {
                return Err("the export trie is nested deeper than any symbol name is long");
            }
            let mut pos = node;
            let terminal = uleb(trie, &mut pos).ok_or(CUT)?;
            let children = usize::try_from(terminal).ok().and_then(|size| pos.checked_add(size)).ok_or(CUT)?;
            let count = *trie.get(children).ok_or(CUT)?;
            if terminal != 0 {
                let info = trie.get(pos..children).ok_or(CUT)?;
                let export = terminal_info(info, &name, node as u64).ok_or("the export information of a trie node is cut off")?;
                if !export.name.is_empty() {
                    visit(export);
                }
            }
            stack.push(Frame { cursor: children.checked_add(1).ok_or(CUT)?, left: count, name_len: name.len() });
        }
        let Some(frame) = stack.last_mut() else { return Ok(()) };
        if frame.left == 0 {
            stack.pop();
            continue;
        }
        frame.left -= 1;
        name.truncate(frame.name_len);
        let rest = trie.get(frame.cursor..).ok_or(CUT)?;
        let end = memchr(0, rest).ok_or("an edge label of the export trie is not terminated")?;
        budget = budget.checked_sub(end.saturating_add(1)).ok_or("the edge labels of the export trie overlap; reading stopped")?;
        // A name longer than the cap keeps its first bytes, as names from the symbol table do.
        let room = MAX_NAME.saturating_sub(name.len());
        name.extend_from_slice(rest.get(..end.min(room)).ok_or(CUT)?);
        let mut pos = frame.cursor.checked_add(end).and_then(|p| p.checked_add(1)).ok_or(CUT)?;
        let child = uleb(trie, &mut pos).ok_or(CUT)?;
        frame.cursor = pos;
        next = Some(usize::try_from(child).map_err(|_| OUTSIDE)?);
    }
}

/// Decodes the export information of a terminal node.
fn terminal_info(info: &[u8], name: &[u8], at: u64) -> Option<Export> {
    let mut pos = 0;
    let flags = uleb(info, &mut pos)?;
    let mut export =
        Export { name: text(name), flags, address: None, absolute: flags & EXPORT_KIND_MASK == EXPORT_KIND_ABSOLUTE, reexport: None, at };
    if flags & EXPORT_REEXPORT != 0 {
        let ordinal = uleb(info, &mut pos)?;
        let (other, _) = name_at(info, pos)?;
        export.absolute = false;
        export.reexport = Some((ordinal, (!other.is_empty()).then_some(other)));
    } else {
        export.address = Some(uleb(info, &mut pos)?);
        if flags & EXPORT_STUB_AND_RESOLVER != 0 {
            uleb(info, &mut pos)?;
        }
    }
    Some(export)
}

/// One symbol an image asks dyld to bind.
#[derive(Debug, PartialEq, Eq)]
pub struct Bind {
    pub name: String,
    /// Which library it comes from: 1-based among the image's dylib load commands, `0` for the
    /// image itself, `-1` the main executable, `-2` flat lookup, `-3` weak lookup.
    pub ordinal: i64,
    /// The symbol may be missing at run time (`weak_import`).
    pub weak: bool,
    /// Offset of the name in the table.
    pub at: u64,
}

/// The header of `LC_DYLD_CHAINED_FIXUPS` data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainedHeader {
    pub version: u32,
    pub imports_format: u32,
    pub imports_count: u32,
    pub symbols_format: u32,
}

/// Reads the import table of chained fixups (`dyld_chained_fixups_header` and the three
/// `dyld_chained_import` layouts), calling `visit` for each entry with a name.
pub fn chained_imports(blob: &[u8], le: bool, mut visit: impl FnMut(Bind)) -> (Option<ChainedHeader>, Option<Problem>) {
    let rd = Rd::new(blob, le);
    let header = (|| {
        Some((
            ChainedHeader { version: rd.u32(0)?, imports_format: rd.u32(20)?, imports_count: rd.u32(16)?, symbols_format: rd.u32(24)? },
            u64::from(rd.u32(8)?),
            u64::from(rd.u32(12)?),
        ))
    })();
    let Some((header, imports_offset, symbols_offset)) = header else {
        return (None, Some(Problem::Malformed("the chained fixups header is cut off")));
    };
    if header.imports_count == 0 {
        return (Some(header), None);
    }
    let entry_size: u64 = match header.imports_format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => return (Some(header), Some(Problem::Unsupported("the chained fixups use an unknown import table format"))),
    };
    if header.symbols_format != 0 {
        return (Some(header), Some(Problem::Unsupported("the symbol names of the chained fixups are compressed")));
    }
    if !le {
        // The import entries are C bit-fields; no big-endian toolchain has ever produced them.
        return (Some(header), Some(Problem::Unsupported("chained fixups in a big-endian image are not read")));
    }
    let mut problem = None;
    let fits = rd.len().saturating_sub(imports_offset) / entry_size;
    if u64::from(header.imports_count) > fits {
        problem = Some(Problem::Malformed("the chained fixups declare more imports than fit in their data"));
    }
    if symbols_offset >= rd.len() {
        return (Some(header), Some(Problem::Malformed("the symbol names of the chained fixups lie outside their data")));
    }
    // Sound tables store each name once; names read over and over mean entries that overlap.
    let mut budget = rd.len().saturating_mul(8).saturating_add(4096);
    for i in 0..u64::from(header.imports_count).min(fits) {
        let at = imports_offset + i * entry_size;
        let fields = if entry_size == 16 {
            rd.u64(at).map(|v| (v & 0xffff, 0xfff0, 0x1_0000, (v >> 16) & 1 != 0, v >> 32))
        } else {
            rd.u32(at).map(u64::from).map(|v| (v & 0xff, 0xf0, 0x100, (v >> 8) & 1 != 0, v >> 9))
        };
        let Some((raw_ordinal, last_plain, wrap, weak, name_offset)) = fields else { break };
        // The top values of the ordinal field are the special ordinals, as negative numbers.
        let ordinal = if raw_ordinal > last_plain { raw_ordinal as i64 - wrap } else { raw_ordinal as i64 };
        let name_at = symbols_offset.checked_add(name_offset).filter(|o| *o < rd.len());
        let Some((name_at, name)) = name_at.and_then(|o| Some((o, rd.cstr(o, rd.len())?))) else {
            problem.get_or_insert(Problem::Malformed("an import of the chained fixups has its name outside their data"));
            continue;
        };
        let Some(left) = budget.checked_sub(name.len() as u64 + 1) else {
            problem = Some(Problem::Malformed("the import names of the chained fixups overlap; reading stopped"));
            break;
        };
        budget = left;
        if !name.is_empty() {
            visit(Bind { name, ordinal, weak, at: name_at });
        }
    }
    (Some(header), problem)
}

/// Runs one bind opcode stream of `LC_DYLD_INFO` (`bind`, `weak_bind` or `lazy_bind`), calling
/// `visit` once for every symbol that is bound at least once. Where the binds apply is not
/// followed. In a lazy stream `BIND_OPCODE_DONE` only separates entries.
pub fn bind_opcodes(stream: &[u8], lazy: bool, mut visit: impl FnMut(Bind)) -> Option<Problem> {
    const CUT: Problem = Problem::Malformed("a bind opcode is cut off");
    let mut pos = 0usize;
    let mut ordinal = 0i64;
    // The symbol in force: name, offset of the name, flags, and whether it was reported.
    let mut symbol: Option<(String, u64, u8, bool)> = None;
    while let Some(byte) = stream.get(pos).copied() {
        pos += 1;
        let (opcode, immediate) = (byte & 0xf0, byte & 0x0f);
        let mut bound = false;
        match opcode {
            0x00 => {
                if !lazy {
                    break;
                }
            }
            0x10 => ordinal = i64::from(immediate),
            0x20 => match uleb(stream, &mut pos).map(i64::try_from) {
                Some(Ok(value)) => ordinal = value,
                _ => return Some(CUT),
            },
            // The immediate is the low four bits of a small negative number.
            0x30 => ordinal = if immediate == 0 { 0 } else { i64::from(immediate) - 16 },
            0x40 => {
                let Some((name, after)) = name_at(stream, pos) else {
                    return Some(Problem::Malformed("a symbol name in the bind opcodes is not terminated"));
                };
                symbol = Some((name, pos as u64, immediate, false));
                pos = after;
            }
            0x50 => {}
            0x60 => {
                if skip_sleb(stream, &mut pos).is_none() {
                    return Some(CUT);
                }
            }
            0x70 | 0x80 => {
                if uleb(stream, &mut pos).is_none() {
                    return Some(CUT);
                }
            }
            0x90 | 0xb0 => bound = true,
            0xa0 => {
                if uleb(stream, &mut pos).is_none() {
                    return Some(CUT);
                }
                bound = true;
            }
            0xc0 => {
                if uleb(stream, &mut pos).is_none() || uleb(stream, &mut pos).is_none() {
                    return Some(CUT);
                }
                bound = true;
            }
            // BIND_OPCODE_THREADED: the size of the ordinal table, or "apply".
            0xd0 => match immediate {
                0 => {
                    if uleb(stream, &mut pos).is_none() {
                        return Some(CUT);
                    }
                }
                1 => {}
                _ => return Some(Problem::Malformed("the bind opcodes hold an unknown threaded sub-opcode")),
            },
            _ => return Some(Problem::Malformed("the bind opcodes hold an unknown opcode")),
        }
        if bound
            && let Some((name, at, flags, reported)) = &mut symbol
            && !*reported
        {
            *reported = true;
            if !name.is_empty() {
                visit(Bind { name: name.clone(), ordinal, weak: *flags & 1 != 0, at: *at });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uleb_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn exports(trie: &[u8]) -> (Vec<Export>, Option<Problem>) {
        let mut found = Vec::new();
        let problem = export_trie(trie, |e| found.push(e));
        (found, problem)
    }

    fn malformed(problem: Option<Problem>, wanted: &str) {
        match problem {
            Some(Problem::Malformed(text)) => assert!(text.contains(wanted), "{text}"),
            other => panic!("expected a malformed table mentioning {wanted:?}, got {other:?}"),
        }
    }

    /// A trie node for building test tries: export information (empty when the node is not a
    /// symbol) and labelled children.
    struct Node {
        info: Vec<u8>,
        children: Vec<(&'static str, Node)>,
    }

    fn node(info: Vec<u8>, children: Vec<(&'static str, Node)>) -> Node {
        Node { info, children }
    }

    fn info(flags: u64, rest: &[&[u8]]) -> Vec<u8> {
        [uleb_bytes(flags), rest.concat()].concat()
    }

    /// Child offsets are written as two-byte ULEBs so sizes do not depend on the layout.
    fn own_size(n: &Node) -> usize {
        uleb_bytes(n.info.len() as u64).len() + n.info.len() + 1 + n.children.iter().map(|(label, _)| label.len() + 3).sum::<usize>()
    }

    fn tree_size(n: &Node) -> usize {
        own_size(n) + n.children.iter().map(|(_, child)| tree_size(child)).sum::<usize>()
    }

    fn emit(n: &Node, out: &mut Vec<u8>) {
        let mut child_at = out.len() + own_size(n);
        out.extend(uleb_bytes(n.info.len() as u64));
        out.extend(&n.info);
        out.push(n.children.len() as u8);
        for (label, child) in &n.children {
            out.extend_from_slice(label.as_bytes());
            assert!(child_at < 1 << 14);
            out.extend([0, (child_at & 0x7f) as u8 | 0x80, (child_at >> 7) as u8]);
            child_at += tree_size(child);
        }
        for (_, child) in &n.children {
            emit(child, out);
        }
    }

    /// A trie for `_main` (regular, 0x578), `_mh` (absolute 0x10), `_re` (re-export of `_orig`
    /// from library 2), `_res` (stub 0x20 with resolver 0x30) and `_w` (weak definition).
    fn sample_trie() -> Vec<u8> {
        let leaf = |flags: u64, rest: &[&[u8]]| node(info(flags, rest), Vec::new());
        let root = node(
            Vec::new(),
            vec![(
                "_",
                node(
                    Vec::new(),
                    vec![
                        ("m", node(Vec::new(), vec![("ain", leaf(0, &[&uleb_bytes(0x578)])), ("h", leaf(2, &[&uleb_bytes(0x10)]))])),
                        (
                            "re",
                            node(info(8, &[&uleb_bytes(2), b"_orig\0"]), vec![("s", leaf(0x10, &[&uleb_bytes(0x20), &uleb_bytes(0x30)]))]),
                        ),
                        ("w", leaf(4, &[&uleb_bytes(0x600)])),
                    ],
                ),
            )],
        );
        let mut trie = Vec::new();
        emit(&root, &mut trie);
        trie
    }

    #[test]
    fn uleb_reads_and_rejects() {
        for value in [0u64, 1, 127, 128, 300, 0xffff_ffff, u64::MAX] {
            let bytes = uleb_bytes(value);
            let mut pos = 0;
            assert_eq!(uleb(&bytes, &mut pos), Some(value));
            assert_eq!(pos, bytes.len());
        }
        // Cut off, too long, and too large for 64 bits.
        assert_eq!(uleb(&[0x80, 0x80], &mut 0), None);
        assert_eq!(uleb(&[], &mut 0), None);
        assert_eq!(uleb(&[0x80; 32], &mut 0), None);
        assert_eq!(uleb(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], &mut 0), None);
        assert_eq!(uleb(&[1], &mut 5), None);
    }

    #[test]
    fn trie_yields_every_kind_of_export() {
        let trie = sample_trie();
        let (found, problem) = exports(&trie);
        assert_eq!(problem, None);
        let summary: Vec<(&str, u64, Option<u64>, bool)> =
            found.iter().map(|e| (e.name.as_str(), e.flags, e.address, e.absolute)).collect();
        assert_eq!(
            summary,
            [
                ("_main", 0, Some(0x578), false),
                ("_mh", 2, Some(0x10), true),
                ("_re", 8, None, false),
                ("_res", 0x10, Some(0x20), false),
                ("_w", 4, Some(0x600), false),
            ]
        );
        assert_eq!(found[2].reexport, Some((2, Some("_orig".to_string()))));
        assert!(found.iter().all(|e| trie.get(e.at as usize).is_some()));
        assert_eq!(exports(&[]), (Vec::new(), None));
    }

    #[test]
    fn trie_truncated_anywhere_never_panics() {
        let trie = sample_trie();
        for length in 0..trie.len() {
            let (found, problem) = exports(&trie[..length]);
            assert!(found.len() <= 5);
            assert!(length == 0 || problem.is_some(), "cut at {length} went unnoticed");
        }
        // Every byte overwritten with every interesting value.
        for offset in 0..trie.len() {
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                let mut bytes = trie.clone();
                bytes[offset] = value;
                let (found, _) = exports(&bytes);
                assert!(found.len() <= 64);
            }
        }
    }

    #[test]
    fn trie_cycles_and_shared_nodes_end_the_walk() {
        // The root's only child is the root.
        malformed(exports(&[0, 1, b'a', 0, 0]).1, "twice");
        // Two nodes pointing at each other, with empty edge labels.
        malformed(exports(&[0, 1, 0, 4, 0, 1, 0, 0]).1, "twice");
        // Two children sharing one node: the first visit counts, the second is refused.
        let shared = [0, 2, b'a', 0, 8, b'b', 0, 8, 2, 0, 0x10, 0];
        let (found, problem) = exports(&shared);
        assert_eq!(found.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["a"]);
        malformed(problem, "twice");
    }

    #[test]
    fn trie_offsets_out_of_range_and_bad_nodes() {
        malformed(exports(&[0, 1, b'a', 0, 99]).1, "outside");
        // A child offset that is a cut-off ULEB, and one too large for 64 bits.
        malformed(exports(&[0, 1, b'a', 0, 0x80]).1, "cut off");
        malformed(exports(&[0, 1, b'a', 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).1, "cut off");
        // Terminal information longer than the trie; an edge label without its terminator.
        malformed(exports(&[0x7f, 0, 0]).1, "cut off");
        malformed(exports(&[0, 1, b'a', b'b']).1, "not terminated");
        // Terminal information that ends inside its address.
        malformed(exports(&[0, 1, b'a', 0, 5, 2, 0, 0x80, 0]).1, "export information");
        // A re-export whose name runs out of the terminal information.
        malformed(exports(&[0, 1, b'a', 0, 5, 3, 8, 1, b'x', 0]).1, "export information");
    }

    #[test]
    fn trie_depth_and_name_length_are_bounded() {
        // A chain of 40 000 nodes, each with one child labelled "a".
        let mut deep = Vec::new();
        for i in 0..40_000u64 {
            let next = uleb_bytes((i + 1) * 7);
            let mut node = vec![0, 1, b'a', 0];
            node.extend(&next);
            node.resize(7, 0);
            // A padded ULEB would change the value; the offsets here need at most three bytes.
            assert!(next.len() <= 3);
            deep.extend(node);
        }
        deep.extend([2, 0, 0, 0, 0, 0, 0]);
        malformed(exports(&deep).1, "deeper");
        // The same chain kept under the depth cap ends in a symbol whose name is cut at the cap.
        let nodes = 3000u64;
        let mut long = Vec::new();
        for i in 0..nodes {
            let mut node = vec![0, 1, b'a', 0];
            node.extend(uleb_bytes((i + 1) * 7));
            node.resize(7, 0);
            long.extend(node);
        }
        long.extend([2, 0, 1, 0]);
        let (found, problem) = exports(&long);
        assert_eq!(problem, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.len(), MAX_NAME);
    }

    /// A small deterministic generator, so failures reproduce.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    #[test]
    fn random_tables_end_within_their_bounds() {
        let mut random = Lcg(0x7e57);
        for round in 0..4000 {
            // Small values make most bytes plausible sizes, counts and offsets.
            let length = 1 + (random.next() % 96) as usize;
            let ceiling = [4, 16, 256][round % 3];
            let bytes: Vec<u8> = (0..length).map(|_| (random.next() % ceiling) as u8).collect();
            let (found, _) = exports(&bytes);
            assert!(found.len() <= bytes.len());
            let (found, _) = binds(&bytes, round % 2 == 0);
            assert!(found.len() <= bytes.len());
            let (found, _, _) = imports(&bytes);
            assert!(found.len() <= bytes.len());
        }
    }

    fn fixups(format: u32, entries: &[(i64, bool, &str)], addend: bool) -> Vec<u8> {
        let entry_size = match format {
            1 => 4,
            2 => 8,
            _ => 16,
        };
        let imports_offset = 28u32;
        let symbols_offset = imports_offset + (entries.len() * entry_size) as u32;
        let mut names = vec![0u8];
        let mut table = Vec::new();
        for (ordinal, weak, name) in entries {
            let name_offset = names.len() as u64;
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            if format == 3 {
                let raw = (*ordinal as u64 & 0xffff) | (u64::from(*weak) << 16) | (name_offset << 32);
                table.extend(raw.to_le_bytes());
                table.extend(7u64.to_le_bytes());
            } else {
                let raw = (*ordinal as u32 & 0xff) | (u32::from(*weak) << 8) | ((name_offset as u32) << 9);
                table.extend(raw.to_le_bytes());
                if format == 2 {
                    table.extend(if addend { 5i32 } else { 0 }.to_le_bytes());
                }
            }
        }
        let mut blob = Vec::new();
        for field in [0u32, 0, imports_offset, symbols_offset, entries.len() as u32, format, 0] {
            blob.extend(field.to_le_bytes());
        }
        blob.extend(table);
        blob.extend(names);
        blob
    }

    /// Name, ordinal and weak flag of a bound symbol.
    type Found = Vec<(String, i64, bool)>;

    fn imports(blob: &[u8]) -> (Found, Option<ChainedHeader>, Option<Problem>) {
        let mut found = Vec::new();
        let (header, problem) = chained_imports(blob, true, |b| found.push((b.name, b.ordinal, b.weak)));
        (found, header, problem)
    }

    const ENTRIES: &[(i64, bool, &str)] = &[
        (1, false, "_puts"),
        (2, true, "_optional"),
        (0, false, "_self"),
        (-1, false, "_main_exe"),
        (-2, false, "_flat"),
        (-3, false, "_weak"),
    ];

    #[test]
    fn chained_imports_in_all_three_formats() {
        let expected: Vec<(String, i64, bool)> = ENTRIES.iter().map(|(o, w, n)| (n.to_string(), *o, *w)).collect();
        for format in [1, 2, 3] {
            let blob = fixups(format, ENTRIES, true);
            let (found, header, problem) = imports(&blob);
            assert_eq!(problem, None, "format {format}");
            assert_eq!(found, expected, "format {format}");
            assert_eq!(header, Some(ChainedHeader { version: 0, imports_format: format, imports_count: 6, symbols_format: 0 }));
        }
        // A plain ordinal at the top of the range each field allows.
        assert_eq!(imports(&fixups(1, &[(0xf0, false, "_a")], false)).0, [("_a".to_string(), 0xf0, false)]);
        assert_eq!(imports(&fixups(3, &[(0xfff0, false, "_a")], false)).0, [("_a".to_string(), 0xfff0, false)]);
        assert_eq!(imports(&fixups(3, &[(300, true, "_a")], false)).0, [("_a".to_string(), 300, true)]);
    }

    #[test]
    fn chained_imports_malformed() {
        let blob = fixups(1, ENTRIES, false);
        // Truncated at every length: never a panic, and never more than was there.
        for length in 0..blob.len() {
            let (found, _, problem) = imports(&blob[..length]);
            assert!(found.len() <= ENTRIES.len());
            assert!(problem.is_some() || found.len() == ENTRIES.len() || length < 28, "cut at {length}");
        }
        malformed(imports(&blob[..20]).2, "header");
        // A count far beyond the data.
        let mut huge = blob.clone();
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        let (found, _, problem) = imports(&huge);
        assert!(found.len() <= blob.len() / 4);
        malformed(problem, "more imports");
        // Offsets outside the data.
        let mut outside = blob.clone();
        outside[12..16].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        malformed(imports(&outside).2, "outside");
        let mut outside = blob.clone();
        outside[8..12].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let (found, _, problem) = imports(&outside);
        assert!(found.is_empty());
        malformed(problem, "more imports");
        // One entry whose name offset is out of range; the others are still read.
        let mut one = blob.clone();
        one[28..32].copy_from_slice(&(1u32 | (0x3f_ffff << 9)).to_le_bytes());
        let (found, _, problem) = imports(&one);
        assert_eq!(found.len(), ENTRIES.len() - 1);
        malformed(problem, "name outside");
        // Unknown table format, compressed names, big-endian.
        let mut format = blob.clone();
        format[20..24].copy_from_slice(&9u32.to_le_bytes());
        assert!(matches!(imports(&format).2, Some(Problem::Unsupported(_))));
        let mut zlib = blob.clone();
        zlib[24..28].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(imports(&zlib).2, Some(Problem::Unsupported(_))));
        assert!(matches!(chained_imports(&blob, false, |_| {}).1, Some(Problem::Unsupported(_) | Problem::Malformed(_))));
    }

    #[test]
    fn chained_imports_sharing_one_long_name_stop() {
        // 50 000 entries all naming the same 1000-byte string.
        let count = 50_000u32;
        let mut blob = Vec::new();
        let symbols_offset = 28 + count * 4;
        for field in [0u32, 0, 28, symbols_offset, count, 1, 0] {
            blob.extend(field.to_le_bytes());
        }
        for _ in 0..count {
            blob.extend((1u32 | (1 << 9)).to_le_bytes());
        }
        blob.push(0);
        blob.extend(std::iter::repeat_n(b'n', 1000));
        blob.push(0);
        let (found, _, problem) = imports(&blob);
        assert!(found.len() < count as usize);
        malformed(problem, "overlap");
    }

    fn binds(stream: &[u8], lazy: bool) -> (Found, Option<Problem>) {
        let mut found = Vec::new();
        let problem = bind_opcodes(stream, lazy, |b| found.push((b.name, b.ordinal, b.weak)));
        (found, problem)
    }

    #[test]
    fn bind_opcodes_report_each_symbol_once() {
        let mut stream = vec![0x11]; // ordinal 1
        stream.extend_from_slice(b"\x40_puts\0");
        stream.extend([0x51, 0x72, 0x10, 0x90, 0x90, 0xa0, 0x08, 0xb3]); // type, segment, three binds
        stream.extend([0x20, 0xac, 0x02]); // ordinal 300 (ULEB)
        stream.extend_from_slice(b"\x41_optional\0");
        stream.extend([0x60, 0x7f, 0xc0, 0x03, 0x08]); // addend -1, bind 3 times skipping 8
        stream.push(0x3e); // special ordinal -2
        stream.extend_from_slice(b"\x40_flat\0");
        stream.push(0x90);
        stream.push(0x30); // special ordinal 0: this image
        stream.extend_from_slice(b"\x48_strong_override\0"); // never bound
        stream.extend_from_slice(b"\x40_self\0");
        stream.extend([0xd0, 0x04, 0x90, 0xd1]); // threaded: table size, bind, apply
        stream.push(0x00);
        stream.extend_from_slice(b"\x40_after_done\0\x90");
        let (found, problem) = binds(&stream, false);
        assert_eq!(problem, None);
        assert_eq!(
            found,
            [
                ("_puts".to_string(), 1, false),
                ("_optional".to_string(), 300, true),
                ("_flat".to_string(), -2, false),
                ("_self".to_string(), 0, false)
            ]
        );
        // In a lazy stream DONE separates entries.
        let (found, problem) = binds(&stream, true);
        assert_eq!(problem, None);
        assert_eq!(found.last(), Some(&("_after_done".to_string(), 0, false)));
        assert_eq!(binds(&[], false), (Vec::new(), None));
    }

    #[test]
    fn bind_opcodes_malformed() {
        malformed(binds(b"\x40_unterminated", false).1, "not terminated");
        malformed(binds(&[0x20, 0x80], false).1, "cut off");
        malformed(binds(&[0x70, 0xff], false).1, "cut off");
        malformed(binds(&[0x60, 0x80, 0x80], false).1, "cut off");
        malformed(binds(&[0xc0, 0x01], false).1, "cut off");
        malformed(binds(&[0xe0], false).1, "unknown opcode");
        malformed(binds(&[0xd5], false).1, "threaded");
        // A bind with no symbol in force is not a symbol.
        assert_eq!(binds(&[0x90, 0x90], false), (Vec::new(), None));
        // Every prefix of a sound stream, and every single-byte change, ends without a panic.
        let mut stream = vec![0x11];
        stream.extend_from_slice(b"\x40_puts\0\x72\x10\x90\x20\xac\x02\x40_b\0\xc0\x03\x08\x00");
        for length in 0..stream.len() {
            let (found, _) = binds(&stream[..length], true);
            assert!(found.len() <= 2);
        }
        for offset in 0..stream.len() {
            for value in [0x00, 0x40, 0x7f, 0x80, 0xff] {
                let mut bytes = stream.clone();
                bytes[offset] = value;
                let (found, _) = binds(&bytes, false);
                assert!(found.len() <= stream.len());
            }
        }
    }
}
