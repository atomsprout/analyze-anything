#!/usr/bin/env python3
"""Builds tiny.dmg: a 1 MiB HFS+ volume holding a few files, wrapped as a UDIF image whose
chunks use every method the Python standard library can write.

The empty volume comes from `mkfs.hfsplus` (hfsprogs), so the volume header and B-tree
layout are not this project's own idea of the format. This script then adds catalog records
to the single leaf node mkfs wrote and wraps the result. Nothing is mounted.

    python3 make_dmg.py tiny.dmg            # needs mkfs.hfsplus on PATH
    python3 make_dmg.py --raw volume.hfs    # the bare volume, for checking with other tools
    python3 make_dmg.py --wrap disk.img out.dmg "name (Apple_APFS : 0)"
                                            # wraps any raw image, in 1 MiB chunks

apfs-empty.dmg was made with the last form from `truncate -s 128M a.img; mkapfs -L TinyAPFS a.img`
(apfsprogs): an APFS container with one empty volume, 128 MiB being the smallest mkapfs accepts.
"""
import bz2, lzma, plistlib, struct, subprocess, sys, tempfile, zlib, os

BLOCK = 4096
SIZE = 1024 * 1024


def name16(name):
    return name.encode("utf-16-be")


def key(parent, name):
    body = struct.pack(">IH", parent, len(name)) + name16(name)
    return struct.pack(">H", len(body)) + body


def folder(cnid, valence):
    return struct.pack(">hHII", 1, 0, valence, cnid) + b"\0" * 20 + struct.pack(">IIBBHI", 0, 0, 0, 0, 0o040755, 0) + b"\0" * 40


def fork(size, extents):
    blocks = sum(count for _, count in extents)
    out = struct.pack(">QII", size, 0, blocks)
    for start, count in extents + [(0, 0)] * (8 - len(extents)):
        out += struct.pack(">II", start, count)
    return out


def file(cnid, mode, size, extents, kind=b"\0" * 8, special=0):
    out = struct.pack(">hHII", 2, 0, 0, cnid) + b"\0" * 20
    out += struct.pack(">IIBBHI", 0, 0, 0, 0, mode, special)
    out += kind + b"\0" * 8 + b"\0" * 16 + struct.pack(">II", 0, 0)
    out += fork(size, extents) + fork(0, [])
    assert len(out) == 248
    return out


def thread(kind, parent, name):
    return struct.pack(">hhIH", kind, 0, parent, len(name)) + name16(name)


def build_volume():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "v.img")
        with open(path, "wb") as f:
            f.write(b"\0" * SIZE)
        subprocess.run(["mkfs.hfsplus", "-v", "Tiny", path], check=True, capture_output=True)
        image = bytearray(open(path, "rb").read())

    header = 1024
    catalog_block = struct.unpack(">I", image[header + 272 + 16:header + 272 + 20])[0]
    catalog = catalog_block * BLOCK
    node_size = struct.unpack(">H", image[catalog + 32:catalog + 34])[0]
    leaf = catalog + node_size  # mkfs puts the only leaf in node 1
    count = struct.unpack(">H", image[leaf + 10:leaf + 12])[0]
    offsets = [struct.unpack(">H", image[leaf + node_size - 2 * (i + 1):leaf + node_size - 2 * i])[0] for i in range(count + 1)]
    existing = [bytes(image[leaf + offsets[i]:leaf + offsets[i + 1]]) for i in range(count)]
    root_record, root_thread = existing

    # File contents, placed in blocks mkfs left free (well past its own structures).
    data = {}

    def place(content, blocks):
        for index, block in enumerate(blocks):
            part = content[index * BLOCK:(index + 1) * BLOCK]
            image[block * BLOCK:block * BLOCK + len(part)] = part

    plist = b'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.tiny</string></dict></plist>\n'
    hello = b"hello\n"
    big = bytes((i * 31 + 7) % 251 for i in range(10000))
    linked = b"linked\n"
    place(plist, [100])
    place(hello, [101])
    place(big, [110, 111, 120])  # two extents: blocks 110-111 and 120
    place(b"hello.txt", [102])
    place(linked, [103])

    private = "\0\0\0\0HFS+ Private Data"
    records = [
        # (parent, name) -> record, sorted below by key.
        ((1, "Tiny"), root_record[len(key(1, "Tiny")):]),
        ((2, ""), root_thread[len(key(2, "")):]),
        ((2, "App.app"), folder(16, 1)),
        ((2, "big.bin"), file(20, 0o100644, len(big), [(110, 2), (120, 1)])),
        ((2, "hard"), file(22, 0o100644, 0, [], kind=b"hlnkhfs+", special=30)),
        ((2, "hello.txt"), file(19, 0o100644, len(hello), [(101, 1)])),
        ((2, "link"), file(21, 0o120777, 9, [(102, 1)], kind=b"slnkrhap")),
        ((2, private), folder(23, 1)),
        ((16, ""), thread(3, 2, "App.app")),
        ((16, "Contents"), folder(17, 1)),
        ((17, ""), thread(3, 16, "Contents")),
        ((17, "Info.plist"), file(18, 0o100644, len(plist), [(100, 1)])),
        ((18, ""), thread(4, 17, "Info.plist")),
        ((19, ""), thread(4, 2, "hello.txt")),
        ((20, ""), thread(4, 2, "big.bin")),
        ((21, ""), thread(4, 2, "link")),
        ((22, ""), thread(4, 2, "hard")),
        ((23, ""), thread(3, 2, private)),
        ((23, "iNode30"), file(24, 0o100644, len(linked), [(103, 1)])),
        ((24, ""), thread(4, 23, "iNode30")),
    ]
    # The private folder's name starts with NULs, which HFS+ orders after everything else.
    records.sort(key=lambda r: (r[0][0], r[0][1].lower().replace("\0", "￿")))
    body = b""
    new_offsets = [14]
    for (parent, name), record in records:
        entry = key(parent, name)
        if len(entry) % 2:
            entry += b"\0"
        entry += record
        if len(entry) % 2:
            entry += b"\0"
        body += entry
        new_offsets.append(14 + len(body))
    assert 14 + len(body) + 2 * len(new_offsets) <= node_size
    image[leaf + 14:leaf + node_size] = b"\0" * (node_size - 14)
    image[leaf + 14:leaf + 14 + len(body)] = body
    for index, offset in enumerate(new_offsets):
        at = leaf + node_size - 2 * (index + 1)
        image[at:at + 2] = struct.pack(">H", offset)
    image[leaf + 10:leaf + 12] = struct.pack(">H", len(records))
    # B-tree header record: number of leaf records.
    image[catalog + 14 + 6:catalog + 14 + 10] = struct.pack(">I", len(records))
    # Volume header: file and folder counts, next catalog id.
    image[header + 32:header + 40] = struct.pack(">II", 6, 3)
    image[header + 64:header + 68] = struct.pack(">I", 31)
    # The alternate volume header mirrors the primary one.
    image[SIZE - 1024:SIZE - 512] = image[header:header + 512]
    return bytes(image)


def adc_literals(data):
    """Apple Data Compression using only literal runs: valid, if not compressing."""
    out = b""
    for at in range(0, len(data), 128):
        part = data[at:at + 128]
        out += bytes([0x80 | (len(part) - 1)]) + part
    return out


def wrap(volume, name="whole disk (Apple_HFS : 0)", chunk_sectors=128):
    sectors = len(volume) // 512
    methods = [
        (0x80000005, lambda d: zlib.compress(d, 9)),
        (0x80000006, lambda d: bz2.compress(d, 9)),
        (0x80000008, lambda d: lzma.compress(d, format=lzma.FORMAT_XZ)),
        (0x80000004, adc_literals),
        (0x00000001, lambda d: d),
    ]
    data = b""
    chunks = []
    used = 0
    for index, sector in enumerate(range(0, sectors, chunk_sectors)):
        part = volume[sector * 512:(sector + chunk_sectors) * 512]
        if not any(part):
            chunks.append((0x00000002, sector, len(part) // 512, len(data), 0))
            continue
        kind, pack = methods[used % len(methods)]
        used += 1
        packed = pack(part)
        chunks.append((kind, sector, len(part) // 512, len(data), len(packed)))
        data += packed
    chunks.append((0xFFFFFFFF, sectors, 0, len(data), 0))
    mish = b"mish" + struct.pack(">IQQQIII", 1, 0, sectors, 0, 0, 0, 0) + b"\0" * 20
    mish += struct.pack(">II", 0, 0) + b"\0" * 128
    mish += struct.pack(">I", len(chunks))
    assert len(mish) == 204
    for kind, sector, count, offset, length in chunks:
        mish += struct.pack(">IIQQQQ", kind, 0, sector, count, offset, length)
    plist = plistlib.dumps({"resource-fork": {"blkx": [{"Attributes": "0x0050", "CFName": name, "Data": mish, "ID": "0", "Name": name}]}})
    koly = b"koly" + struct.pack(">IIIQQQQQII", 4, 512, 1, 0, 0, len(data), 0, 0, 1, 1) + b"\x11" * 16
    koly += struct.pack(">II", 0, 0) + b"\0" * 128
    koly += struct.pack(">QQ", len(data), len(plist)) + b"\0" * 120
    koly += struct.pack(">II", 0, 0) + b"\0" * 128
    koly += struct.pack(">IQ", 1, sectors) + b"\0" * 12
    assert len(koly) == 512, len(koly)
    return data + plist + koly


if __name__ == "__main__":
    if sys.argv[1] == "--wrap":
        open(sys.argv[3], "wb").write(wrap(open(sys.argv[2], "rb").read(), sys.argv[4], 2048))
    elif sys.argv[1] == "--raw":
        open(sys.argv[2], "wb").write(build_volume())
    else:
        open(sys.argv[1], "wb").write(wrap(build_volume()))
