//! The few ELF program-header facts the Android report needs about a native library: segment
//! alignment (16 KB page support), writable-and-executable segments, text relocations.
//! Full ELF analysis belongs to the binary analyzer; this reads headers only.

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const DT_TEXTREL: u64 = 22;
const DT_FLAGS: u64 = 30;
const DF_TEXTREL: u64 = 4;
const MAX_HEADERS: usize = 512;
const MAX_DYNAMIC: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf {
    pub bits: u8,
    pub machine: u16,
    /// Smallest alignment among loadable segments. `None` when there are none.
    pub min_load_align: Option<u64>,
    /// A loadable segment is both writable and executable.
    pub rwx_segment: bool,
    pub text_relocations: bool,
    /// `Some(true)` when the stack is marked executable; `None` without a GNU_STACK header.
    pub executable_stack: Option<bool>,
}

impl Elf {
    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            3 => "x86",
            40 => "ARM",
            62 => "x86-64",
            183 => "AArch64",
            243 => "RISC-V",
            8 => "MIPS",
            _ => "other",
        }
    }
}

pub fn parse(data: &[u8]) -> Option<Elf> {
    if data.get(..4)? != b"\x7fELF" {
        return None;
    }
    let is64 = match *data.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match *data.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let b: [u8; 2] = data.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if little { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let b: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    };
    let u64_at = |at: usize| -> Option<u64> {
        let b: [u8; 8] = data.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if little { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
    };
    let word = |at: usize| -> Option<u64> { if is64 { u64_at(at) } else { u32_at(at).map(u64::from) } };
    let machine = u16_at(18)?;
    let (ph_offset, ph_entry_size, ph_count) = if is64 {
        (usize::try_from(u64_at(32)?).ok()?, usize::from(u16_at(54)?), usize::from(u16_at(56)?))
    } else {
        (u32_at(28)? as usize, usize::from(u16_at(42)?), usize::from(u16_at(44)?))
    };
    let mut elf = Elf { bits: if is64 { 64 } else { 32 }, machine, min_load_align: None, rwx_segment: false, text_relocations: false, executable_stack: None };
    if ph_entry_size < if is64 { 56 } else { 32 } {
        return Some(elf);
    }
    for i in 0..ph_count.min(MAX_HEADERS) {
        let at = ph_offset.checked_add(i.checked_mul(ph_entry_size)?)?;
        let Some(kind) = u32_at(at) else { break };
        // (flags, offset, file size, align) sit at different places in the two layouts.
        let fields = if is64 {
            (u32_at(at + 4), u64_at(at + 8), u64_at(at + 32), u64_at(at + 48))
        } else {
            (u32_at(at + 24), u32_at(at + 4).map(u64::from), u32_at(at + 16).map(u64::from), u32_at(at + 28).map(u64::from))
        };
        let (Some(flags), Some(offset), Some(file_size), Some(align)) = fields else { break };
        match kind {
            PT_LOAD => {
                elf.min_load_align = Some(elf.min_load_align.map_or(align, |a| a.min(align)));
                if flags & 0x1 != 0 && flags & 0x2 != 0 {
                    elf.rwx_segment = true;
                }
            }
            PT_GNU_STACK => elf.executable_stack = Some(flags & 0x1 != 0),
            PT_DYNAMIC => {
                let entry = if is64 { 16 } else { 8 };
                let count = (usize::try_from(file_size).unwrap_or(0) / entry).min(MAX_DYNAMIC);
                let Ok(base) = usize::try_from(offset) else { continue };
                for j in 0..count {
                    let Some(entry_at) = base.checked_add(j * entry) else { break };
                    let (Some(tag), Some(value)) = (word(entry_at), word(entry_at + entry / 2)) else { break };
                    match tag {
                        0 => break,
                        DT_TEXTREL => elf.text_relocations = true,
                        DT_FLAGS if value & DF_TEXTREL != 0 => elf.text_relocations = true,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some(elf)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A 64-bit little-endian ELF with one LOAD segment of the given alignment and flags, and a
    /// DYNAMIC segment that may carry DT_TEXTREL.
    pub fn sample(align: u64, flags: u32, textrel: bool) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[..6].copy_from_slice(b"\x7fELF\x02\x01");
        out[18..20].copy_from_slice(&183u16.to_le_bytes());
        out[32..40].copy_from_slice(&64u64.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&2u16.to_le_bytes());
        let dynamic_offset = 64 + 2 * 56;
        let mut header = |kind: u32, flags: u32, offset: u64, size: u64, align: u64| {
            let mut h = Vec::new();
            h.extend_from_slice(&kind.to_le_bytes());
            h.extend_from_slice(&flags.to_le_bytes());
            h.extend_from_slice(&offset.to_le_bytes());
            h.extend_from_slice(&[0; 16]);
            h.extend_from_slice(&size.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
            h.extend_from_slice(&align.to_le_bytes());
            out.extend(h);
        };
        header(PT_LOAD, flags, 0, 0x100, align);
        header(PT_DYNAMIC, 6, dynamic_offset as u64, 32, 8);
        let tag = if textrel { DT_TEXTREL } else { 1 };
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&[0; 16]);
        out
    }

    #[test]
    fn reads_alignment_flags_and_textrel() {
        let elf = parse(&sample(0x4000, 5, false)).expect("elf");
        assert_eq!((elf.bits, elf.machine_name()), (64, "AArch64"));
        assert_eq!(elf.min_load_align, Some(0x4000));
        assert!(!elf.rwx_segment && !elf.text_relocations);
        let elf = parse(&sample(0x1000, 7, true)).expect("elf");
        assert_eq!(elf.min_load_align, Some(0x1000));
        assert!(elf.rwx_segment && elf.text_relocations);
    }

    #[test]
    fn malformed_input_does_not_panic() {
        let data = sample(0x4000, 5, true);
        for cut in 0..data.len() {
            let _ = parse(&data[..cut]);
        }
        for i in 0..data.len() {
            for v in [0u8, 0xff] {
                let mut bad = data.clone();
                bad[i] = v;
                let _ = parse(&bad);
            }
        }
        assert!(parse(b"not an elf").is_none());
    }
}
