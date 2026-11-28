"""Hostile metadata/archive checks for verify-published.py; no network or execution."""

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile


SPEC = importlib.util.spec_from_file_location("verify_published", Path(__file__).with_name("verify-published.py"))
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aa-release-verifier-test-")
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def zip(self, extra=None):
        path = self.folder / "analyze-anything-v9.8.7-x86_64-pc-windows-msvc.zip"
        _, expected = VERIFIER.archive_layout(path.name)
        with zipfile.ZipFile(path, "w") as archive:
            for name in sorted(expected):
                archive.writestr(name, b"inert bytes")
            if extra:
                archive.writestr(*extra)
        return path

    def tar(self, extra=None):
        path = self.folder / "analyze-anything-v9.8.7-aarch64-apple-darwin.tar.gz"
        _, expected = VERIFIER.archive_layout(path.name)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(expected):
                header = tarfile.TarInfo(name)
                header.size = 11
                archive.addfile(header, io.BytesIO(b"inert bytes"))
            if extra:
                archive.addfile(extra)
        path.write_bytes(gzip.compress(output.getvalue(), mtime=0))
        return path

    def test_exact_asset_contract_and_checksum_target_authority(self):
        names, archives, desktop = VERIFIER.expected_assets("v9.8.7", "9.8.7")
        self.assertEqual((len(names), len(archives), len(desktop)), (11, 4, 2))
        release = {"assets": [{"name": name, "size": 1, "state": "uploaded"} for name in sorted(names)]}
        self.assertEqual(set(VERIFIER.metadata_assets(release, names)), names)
        release["assets"].append(dict(release["assets"][0]))
        with self.assertRaises(ValueError):
            VERIFIER.metadata_assets(release, names)
        manifest = self.folder / "SHA256SUMS"
        digest = "a" * 64
        manifest.write_text(digest.upper() + " *one.zip\n", encoding="ascii")
        self.assertEqual(VERIFIER.checksum_entries(manifest, {"one.zip"}), {"one.zip": digest})
        for text in [digest + "  ../one.zip\n", (digest + "  one.zip\n") * 2, "", "bad  one.zip\n"]:
            manifest.write_text(text, encoding="ascii")
            with self.assertRaises(ValueError):
                VERIFIER.checksum_entries(manifest, {"one.zip"})

    def test_github_digest_is_independently_checked(self):
        path = self.folder / "one.zip"
        path.write_bytes(b"inert asset")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        metadata = {path.name: {"id": 1, "size": path.stat().st_size, "digest": "sha256:" + digest}}
        self.assertTrue(VERIFIER.check_asset_bytes(self.folder, metadata)[0]["github_digest_verified"])
        path.write_bytes(b"other asset")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            VERIFIER.check_asset_bytes(self.folder, metadata)

    def test_archive_path_aliases_and_special_files_are_rejected(self):
        for path in ["../outside", "/absolute", "C:/drive", "root\\name", "root//name", "root/./name", "root/name.", "root/NUL.exe"]:
            with self.assertRaises(ValueError, msg=path):
                VERIFIER.sane_name(path)
        self.assertEqual(len(VERIFIER.check_zip(self.zip())["members"]), 4)
        with self.assertRaises(ValueError):
            VERIFIER.check_zip(self.zip(("../outside", b"inert")))
        root = "analyze-anything-v9.8.7-x86_64-pc-windows-msvc"
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            VERIFIER.check_zip(self.zip((root + "/license", b"inert")))
        link = zipfile.ZipInfo(root + "/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, "special ZIP"):
            VERIFIER.check_zip(self.zip((link, b"../outside")))

    def test_zip_crc_and_small_input_large_declared_size_are_checked(self):
        path = self.zip()
        data = bytearray(path.read_bytes())
        at = 30 + int.from_bytes(data[26:28], "little") + int.from_bytes(data[28:30], "little")
        data[at] ^= 1
        path.write_bytes(data)
        with self.assertRaises(zipfile.BadZipFile):
            VERIFIER.check_zip(path)
        path = self.zip()
        data = bytearray(path.read_bytes())
        central = data.index(b"PK\x01\x02")
        data[central + 24:central + 28] = (VERIFIER.MAX_EXPANDED + 1).to_bytes(4, "little")
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "budget"):
            VERIFIER.check_zip(path)

    def test_tar_crc_trailing_bytes_special_files_and_declared_sizes(self):
        path = self.tar()
        self.assertTrue(VERIFIER.check_tar_gzip(path)["gzip_crc_and_size_checked"])
        data = bytearray(path.read_bytes())
        data[-8] ^= 1
        path.write_bytes(data)
        with self.assertRaises(gzip.BadGzipFile):
            VERIFIER.check_tar_gzip(path)
        path = self.tar()
        path.write_bytes(gzip.compress(gzip.decompress(path.read_bytes()) + b"hidden", mtime=0))
        with self.assertRaisesRegex(ValueError, "unread data"):
            VERIFIER.check_tar_gzip(path)
        link = tarfile.TarInfo("root/link")
        link.type, link.linkname = tarfile.SYMTYPE, "../outside"
        with self.assertRaisesRegex(ValueError, "special"):
            VERIFIER.check_tar_gzip(self.tar(link))
        huge = tarfile.TarInfo("root/huge")
        huge.size = VERIFIER.MAX_EXPANDED + 1
        path.write_bytes(gzip.compress(huge.tobuf(format=tarfile.USTAR_FORMAT), mtime=0))
        with self.assertRaisesRegex(ValueError, "size exceeds"):
            VERIFIER.check_tar_gzip(path)

    def test_pax_effective_paths_are_checked_and_planned_aliases_are_not_counted(self):
        with self.assertRaises(ValueError):
            VERIFIER.sane_name(VERIFIER.pax_path(b"19 path=../outside\n"))
        catalogue = {"schema_version": 1, "counts": {"primary": 1, "compression": 1},
                     "primary_total_including_compression": 2, "formats": [
                         {"id": "one", "group": "primary", "state": "implemented", "aliases": ["a", "b"]},
                         {"id": "two", "group": "compression", "state": "implemented"},
                         {"id": "later", "group": "primary", "state": "planned"},
                     ]}
        self.assertEqual(VERIFIER.check_catalogue(catalogue, 2)["primary_total_including_compression"], 2)
        with self.assertRaisesRegex(ValueError, "count"):
            VERIFIER.check_catalogue(catalogue, 3)
        catalogue["formats"].append(dict(catalogue["formats"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            VERIFIER.check_catalogue(catalogue, 2)


if __name__ == "__main__":
    unittest.main()
