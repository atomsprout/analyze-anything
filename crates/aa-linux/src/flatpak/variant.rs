//! The bounded GVariant subset used by OSTree, preserving original byte spans.
//!
//! Framing offsets are little-endian independently of the scalar byte order.
//! Invalid framing is rejected, never replaced with GVariant's default values.

use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Type {
    Basic(u8),
    Array(Box<Type>),
    Tuple(Vec<Type>),
    Dict(Box<Type>, Box<Type>),
    Variant,
    Maybe(Box<Type>),
}

impl Type {
    fn weight(&self) -> usize {
        match self {
            Self::Array(child) | Self::Maybe(child) => 1 + child.weight(),
            Self::Tuple(fields) => 1 + fields.iter().map(Self::weight).sum::<usize>(),
            Self::Dict(key, value) => 1 + key.weight() + value.weight(),
            _ => 1,
        }
    }

    fn alignment(&self) -> usize {
        match self {
            Self::Basic(b'y' | b'b' | b's' | b'o' | b'g') => 1,
            Self::Basic(b'n' | b'q') => 2,
            Self::Basic(b'i' | b'u' | b'h') => 4,
            Self::Basic(_) | Self::Variant => 8,
            Self::Array(child) | Self::Maybe(child) => child.alignment(),
            Self::Tuple(children) => children.iter().map(Self::alignment).max().unwrap_or(1),
            Self::Dict(key, value) => key.alignment().max(value.alignment()),
        }
    }

    fn fixed(&self) -> Option<usize> {
        match self {
            Self::Basic(b'y' | b'b') => Some(1),
            Self::Basic(b'n' | b'q') => Some(2),
            Self::Basic(b'i' | b'u' | b'h') => Some(4),
            Self::Basic(b'x' | b't' | b'd') => Some(8),
            Self::Tuple(children) => {
                if children.is_empty() {
                    return Some(1);
                }
                let mut offset = 0;
                for child in children {
                    offset = crate::align(offset, child.alignment()).ok()?.checked_add(child.fixed()?)?;
                }
                crate::align(offset, self.alignment()).ok()
            }
            Self::Dict(key, value) => Self::Tuple(vec![(**key).clone(), (**value).clone()]).fixed(),
            _ => None,
        }
    }
}

pub(super) fn signature(text: &str) -> Result<Type> {
    if text.is_empty() || text.len() > 255 {
        return Err("GVariant signature length is outside the profile".into());
    }
    fn read(bytes: &[u8], at: &mut usize, depth: usize) -> Result<Type> {
        if depth >= 32 {
            return Err("GVariant type nesting budget exhausted".into());
        }
        let byte = *bytes.get(*at).ok_or("GVariant signature cut short")?;
        *at += 1;
        Ok(match byte {
            b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' | b'h' => Type::Basic(byte),
            b'v' => Type::Variant,
            b'a' => Type::Array(Box::new(read(bytes, at, depth + 1)?)),
            b'm' => Type::Maybe(Box::new(read(bytes, at, depth + 1)?)),
            b'(' => {
                let mut children = Vec::new();
                while bytes.get(*at) != Some(&b')') {
                    if children.len() >= 64 {
                        return Err("GVariant tuple field budget exhausted".into());
                    }
                    children.push(read(bytes, at, depth + 1)?);
                }
                *at += 1;
                Type::Tuple(children)
            }
            b'{' => {
                let key = read(bytes, at, depth + 1)?;
                if !matches!(key, Type::Basic(_)) {
                    return Err("GVariant dictionary key is not basic".into());
                }
                let value = read(bytes, at, depth + 1)?;
                if bytes.get(*at) != Some(&b'}') {
                    return Err("GVariant dictionary signature is not terminated".into());
                }
                *at += 1;
                Type::Dict(Box::new(key), Box::new(value))
            }
            _ => return Err("unsupported GVariant type signature".into()),
        })
    }
    let mut at = 0;
    let ty = read(text.as_bytes(), &mut at, 0)?;
    if at != text.len() {
        return Err("GVariant signature contains more than one type".into());
    }
    Ok(ty)
}

fn width(length: usize) -> usize {
    if length <= 0xff {
        1
    } else if length <= 0xffff {
        2
    } else if length <= 0xffff_ffff {
        4
    } else {
        8
    }
}

fn offset(bytes: &[u8]) -> Result<usize> {
    if !matches!(bytes.len(), 1 | 2 | 4 | 8) {
        return Err("invalid GVariant framing offset width".into());
    }
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    usize::try_from(value).map_err(|_| "GVariant framing offset exceeds the address space".into())
}

#[derive(Clone, Debug)]
pub(super) struct Node<'a> {
    pub data: &'a [u8],
    pub offset: usize,
    pub ty: Type,
}

impl<'a> Node<'a> {
    pub fn new(data: &'a [u8], text: &str) -> Result<Self> {
        Ok(Self { data, offset: 0, ty: signature(text)? })
    }

    fn slice(&self, start: usize, end: usize, ty: Type) -> Result<Self> {
        let data = self.data.get(start..end).ok_or("GVariant child range is invalid")?;
        Ok(Self { data, offset: self.offset.checked_add(start).ok_or("GVariant source offset overflow")?, ty })
    }

    pub fn bytes(&self) -> Result<&'a [u8]> {
        if self.ty != Type::Array(Box::new(Type::Basic(b'y'))) {
            return Err("expected GVariant byte array".into());
        }
        Ok(self.data)
    }

    pub fn string(&self) -> Result<&'a str> {
        if !matches!(self.ty, Type::Basic(b's' | b'o' | b'g')) {
            return Err("expected GVariant string".into());
        }
        let text = self.data.strip_suffix(&[0]).ok_or("GVariant string is not NUL-terminated")?;
        if text.contains(&0) {
            return Err("GVariant string has an embedded NUL".into());
        }
        std::str::from_utf8(text).map_err(|_| "GVariant string is not UTF-8".into())
    }

    pub fn number(&self, little: bool) -> Result<u64> {
        let size = self.ty.fixed().ok_or("expected GVariant fixed scalar")?;
        if !matches!(self.ty, Type::Basic(_)) || self.data.len() != size {
            return Err("invalid GVariant scalar size".into());
        }
        let mut value = 0u64;
        for (index, byte) in self.data.iter().enumerate() {
            let shift = if little { index * 8 } else { (size - index - 1) * 8 };
            value |= u64::from(*byte) << shift;
        }
        Ok(value)
    }

    pub fn variant(&self) -> Result<Self> {
        if self.ty != Type::Variant {
            return Err("expected GVariant variant".into());
        }
        let separator = self.data.iter().rposition(|byte| *byte == 0).ok_or("GVariant variant lacks a type separator")?;
        let text = std::str::from_utf8(self.data.get(separator + 1..).ok_or("GVariant variant type missing")?)
            .map_err(|_| "GVariant variant type is not ASCII")?;
        self.slice(0, separator, signature(text)?)
    }

    fn tuple(&self, fields: &[Type]) -> Result<Vec<Self>> {
        if fields.is_empty() {
            return if self.data == [0] { Ok(Vec::new()) } else { Err("invalid GVariant unit tuple".into()) };
        }
        let fixed = self.ty.fixed();
        if fixed.is_some_and(|size| size != self.data.len()) {
            return Err("GVariant fixed tuple has the wrong size".into());
        }
        let offsets = fields.iter().enumerate().filter(|(index, ty)| ty.fixed().is_none() && index + 1 != fields.len()).count();
        let framing = offsets.checked_mul(width(self.data.len())).ok_or("GVariant tuple framing overflow")?;
        let end = self.data.len().checked_sub(framing).ok_or("GVariant tuple framing cut short")?;
        let mut at = 0usize;
        let mut index = 0usize;
        let mut children = Vec::with_capacity(fields.len());
        for (position, ty) in fields.iter().enumerate() {
            let start = crate::align(at, ty.alignment())?;
            if self.data.get(at..start).is_none_or(|padding| padding.iter().any(|byte| *byte != 0)) {
                return Err("GVariant tuple has invalid alignment padding".into());
            }
            let stop = if let Some(size) = ty.fixed() {
                start.checked_add(size).ok_or("GVariant tuple child overflow")?
            } else if position + 1 == fields.len() {
                end
            } else {
                index += 1;
                let start = self.data.len().checked_sub(index * width(self.data.len())).ok_or("GVariant tuple offset cut short")?;
                offset(self.data.get(start..start + width(self.data.len())).ok_or("GVariant tuple offset cut short")?)?
            };
            if stop > end || stop < start {
                return Err("GVariant tuple child framing is out of order".into());
            }
            children.push(self.slice(start, stop, ty.clone())?);
            at = stop;
        }
        if (fixed.is_none() && at != end) || at > end || self.data.get(at..end).is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
        {
            return Err("GVariant tuple has trailing non-padding data".into());
        }
        Ok(children)
    }

    pub fn children(&self, max: usize) -> Result<Vec<Self>> {
        match &self.ty {
            Type::Tuple(fields) => self.tuple(fields),
            Type::Dict(key, value) => self.tuple(&[(**key).clone(), (**value).clone()]),
            Type::Array(ty) => {
                if self.data.is_empty() {
                    return Ok(Vec::new());
                }
                let (count, end, step) = if let Some(size) = ty.fixed() {
                    if !self.data.len().is_multiple_of(size) {
                        return Err("GVariant fixed array is not a multiple of its element size".into());
                    }
                    (self.data.len() / size, self.data.len(), Some(size))
                } else {
                    let w = width(self.data.len());
                    let last = self.data.len().checked_sub(w).ok_or("GVariant array offset cut short")?;
                    let end = offset(&self.data[last..])?;
                    let framing = self.data.len().checked_sub(end).ok_or("GVariant array offset is outside its bytes")?;
                    if framing == 0 || framing % w != 0 {
                        return Err("invalid GVariant variable-array framing".into());
                    }
                    (framing / w, end, None)
                };
                if count > max || count.saturating_mul(ty.weight()) > 1_000_000 {
                    return Err("GVariant array element budget exhausted".into());
                }
                let mut result = Vec::with_capacity(count);
                let mut at = 0usize;
                for index in 0..count {
                    let start = crate::align(at, ty.alignment())?;
                    if self.data.get(at..start).is_none_or(|padding| padding.iter().any(|byte| *byte != 0)) {
                        return Err("GVariant array alignment padding is invalid".into());
                    }
                    let stop = if let Some(size) = step {
                        start.checked_add(size).ok_or("GVariant array element overflow")?
                    } else {
                        let base = end.checked_add(index * width(self.data.len())).ok_or("GVariant array offset overflow")?;
                        offset(self.data.get(base..base + width(self.data.len())).ok_or("GVariant array offset cut short")?)?
                    };
                    if stop < start || stop > end {
                        return Err("GVariant array offsets are out of order".into());
                    }
                    result.push(self.slice(start, stop, (**ty).clone())?);
                    at = stop;
                }
                if at != end {
                    return Err("GVariant array leaves unclaimed data".into());
                }
                Ok(result)
            }
            _ => Err("expected GVariant tuple or array".into()),
        }
    }

    pub fn validate(&self, budget: &mut Budget, depth: usize) -> Result<()> {
        if depth > 32 || budget.nodes == 0 {
            return Err("GVariant nesting or node budget exhausted".into());
        }
        budget.nodes -= 1;
        match &self.ty {
            Type::Basic(b'o' | b'g') => return Err("GVariant object-path/signature scalars are outside this bounded profile".into()),
            Type::Basic(b's') => {
                let text = self.string()?;
                budget.strings = budget.strings.checked_sub(text.len()).ok_or("GVariant string budget exhausted")?;
                if text.len() > 1024 * 1024 {
                    return Err("GVariant string exceeds the 1 MiB profile".into());
                }
            }
            Type::Basic(b'b') if self.data != [0] && self.data != [1] => return Err("invalid GVariant boolean".into()),
            Type::Basic(_) => {
                self.number(true)?;
            }
            Type::Variant => self.variant()?.validate(budget, depth + 1)?,
            Type::Array(ty) if **ty == Type::Basic(b'y') => {}
            Type::Maybe(ty) => {
                if !self.data.is_empty() {
                    let end = if ty.fixed().is_some() {
                        self.data.len()
                    } else {
                        if self.data.last() != Some(&0) {
                            return Err("invalid GVariant maybe terminator".into());
                        }
                        self.data.len() - 1
                    };
                    self.slice(0, end, (**ty).clone())?.validate(budget, depth + 1)?;
                }
            }
            _ => {
                for child in self.children(100_000)? {
                    child.validate(budget, depth + 1)?;
                }
            }
        }
        Ok(())
    }
}

pub(super) struct Budget {
    pub nodes: usize,
    pub strings: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self { nodes: 1_000_000, strings: 16 * 1024 * 1024 }
    }
}

fn append_offsets(data: &mut Vec<u8>, offsets: &[usize]) -> Result<()> {
    let mut w = 1;
    while width(
        data.len().checked_add(offsets.len().checked_mul(w).ok_or("GVariant encoding overflow")?).ok_or("GVariant encoding overflow")?,
    ) != w
    {
        w *= 2;
    }
    for offset in offsets {
        let bytes = (*offset as u64).to_le_bytes();
        data.extend_from_slice(bytes.get(..w).ok_or("GVariant encoding offset width overflow")?);
    }
    Ok(())
}

/// Canonical framing for newly constructed OSTree checksum headers and tests.
pub(super) fn encode_tuple(fields: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    let mut alignment = 1;
    let mut fixed = true;
    for (index, (text, bytes)) in fields.iter().enumerate() {
        let ty = signature(text)?;
        alignment = alignment.max(ty.alignment());
        fixed &= ty.fixed().is_some();
        data.resize(crate::align(data.len(), ty.alignment())?, 0);
        data.extend_from_slice(bytes);
        if ty.fixed().is_none() && index + 1 != fields.len() {
            offsets.push(data.len());
        }
    }
    if fields.is_empty() {
        data.push(0);
    }
    if fixed {
        data.resize(crate::align(data.len(), alignment)?, 0);
    }
    offsets.reverse();
    append_offsets(&mut data, &offsets)?;
    Ok(data)
}

pub(super) fn encode_array(text: &str, values: &[&[u8]]) -> Result<Vec<u8>> {
    let ty = signature(text)?;
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for value in values {
        data.resize(crate::align(data.len(), ty.alignment())?, 0);
        data.extend_from_slice(value);
        if ty.fixed().is_none() {
            offsets.push(data.len());
        }
    }
    append_offsets(&mut data, &offsets)?;
    Ok(data)
}
