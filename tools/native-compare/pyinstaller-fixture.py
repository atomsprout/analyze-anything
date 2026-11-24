"""Build a tiny data-only fixture with the external PyInstaller CArchive writer."""
import argparse
from pathlib import Path
import sys

from PyInstaller.archive.writers import CArchiveWriter

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output")
args = parser.parse_args()
source = Path(__file__).resolve().parents[1] / "fixtures" / "executable-bundles" / "data.txt"
CArchiveWriter(args.output, [("data.txt", str(source), True, "x")], f"python{sys.version_info.major}{sys.version_info.minor}.dll")
