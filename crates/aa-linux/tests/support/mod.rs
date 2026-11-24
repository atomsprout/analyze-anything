#![allow(dead_code)]

use std::io::Write;

pub fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, name, *bytes).expect("append fixture member");
    }
    archive.into_inner().expect("finish fixture tar")
}

pub fn ar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut result = b"!<arch>\n".to_vec();
    for (name, data) in members {
        result.extend(format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, "100644", data.len()).bytes());
        result.extend(*data);
        if data.len() % 2 != 0 {
            result.push(b'\n');
        }
    }
    result
}

pub fn deb(control: &[u8], payload: &[u8]) -> Vec<u8> {
    let control = tar(&[("./control", control), ("./postinst", b"#!/bin/sh\nprintf 'fixture only\\n'\n")]);
    let payload = tar(&[("usr/share/fixture/data.txt", payload)]);
    ar(&[("debian-binary", b"2.0\n"), ("control.tar", &control), ("data.tar", &payload)])
}

pub const CONTROL: &[u8] = b"Package: aa-fixture\nVersion: 1.2-3\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Read-only fixture\n continuation\nDepends: alternative-a (>= 1) | alternative-b, libc6\n";

pub fn cpio_entry(result: &mut Vec<u8>, name: &str, bytes: &[u8], mode: u32, inode: u32, links: u32, crc: bool) {
    let sum = if crc { bytes.iter().fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte))) } else { 0 };
    result.extend(if crc { b"070702" } else { b"070701" });
    for field in [inode, mode, 0, 0, links, 0, bytes.len() as u32, 0, 0, 0, 0, name.len() as u32 + 1, sum] {
        result.extend(format!("{field:08x}").bytes());
    }
    result.extend(name.as_bytes());
    result.push(0);
    while !result.len().is_multiple_of(4) {
        result.push(0);
    }
    result.extend(bytes);
    while !result.len().is_multiple_of(4) {
        result.push(0);
    }
}

pub fn cpio() -> Vec<u8> {
    let mut result = Vec::new();
    cpio_entry(&mut result, "./usr/share/fixture/data.txt", b"https://example.invalid/cpio\n", 0o100644, 1, 1, false);
    cpio_entry(&mut result, "TRAILER!!!", b"", 0, 0, 1, false);
    result
}

pub fn header(mut fields: Vec<(u32, u32, Vec<u8>, u32)>) -> Vec<u8> {
    fields.sort_by_key(|field| field.0);
    let mut index = Vec::new();
    let mut data = Vec::new();
    for (tag, kind, value, count) in fields {
        let width = match kind {
            3 => 2,
            4 => 4,
            5 => 8,
            _ => 1,
        };
        while !data.len().is_multiple_of(width) {
            data.push(0);
        }
        for number in [tag, kind, data.len() as u32, count] {
            index.extend(number.to_be_bytes());
        }
        data.extend(value);
    }
    let mut result = b"\x8e\xad\xe8\x01\0\0\0\0".to_vec();
    result.extend((index.len() as u32 / 16).to_be_bytes());
    result.extend((data.len() as u32).to_be_bytes());
    result.extend(index);
    result.extend(data);
    result
}

pub fn rpm(compressor: &str, extra: Vec<(u32, u32, Vec<u8>, u32)>) -> Vec<u8> {
    let mut result = vec![0; 96];
    result[..6].copy_from_slice(b"\xed\xab\xee\xdb\x03\0");
    result[79] = 5;
    result.extend(header(Vec::new()));
    let mut fields = Vec::new();
    for (tag, text) in [
        (1000, "aa-fixture"),
        (1001, "1.2"),
        (1002, "3"),
        (1014, "Apache-2.0"),
        (1022, "noarch"),
        (1024, "printf 'fixture only\\n'"),
        (1124, "cpio"),
        (1125, compressor),
    ] {
        fields.push((tag, 6, format!("{text}\0").into_bytes(), 1));
    }
    fields.push((1049, 8, b"libc.so.6\0/bin/sh\0".to_vec(), 2));
    fields.push((1050, 8, b"\0\0".to_vec(), 2));
    fields.push((1048, 4, [0u32.to_be_bytes(), 0u32.to_be_bytes()].concat(), 2));
    fields.push((1086, 8, b"/bin/sh\0".to_vec(), 1));
    fields.extend(extra);
    result.extend(header(fields));
    let body = cpio();
    if compressor == "gzip" {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&body).expect("compress fixture payload");
        result.extend(encoder.finish().expect("finish gzip"));
    } else {
        result.extend(body);
    }
    result
}
