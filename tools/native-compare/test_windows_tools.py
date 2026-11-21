"""Reference-tool discovery and literal path transport, without running an input."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from windows_tools import find_signtool, native_signature


class WindowsToolsTests(unittest.TestCase):
    def test_discovers_newest_numeric_x64_sdk(self):
        with tempfile.TemporaryDirectory() as folder:
            for version, architecture in [("10.0.9.0", "x64"), ("10.0.10.0", "x64"), ("10.0.99.0", "arm64")]:
                tool = Path(folder, version, architecture, "signtool.exe")
                tool.parent.mkdir(parents=True)
                tool.touch()
            with patch("windows_tools.shutil.which", return_value=None):
                self.assertEqual(find_signtool(folder), str(Path(folder, "10.0.10.0", "x64", "signtool.exe")))
                self.assertIsNone(find_signtool(str(Path(folder, "missing"))))

    def test_path_is_environment_data_and_not_powershell_source(self):
        path = "sample's $(not-a-command); 中文.exe"
        expected = {"Status": "NotSigned", "Type": "None"}
        with patch("windows_tools.subprocess.run", return_value=SimpleNamespace(stdout=json.dumps(expected))) as run:
            self.assertEqual(native_signature(path), expected)
        args, kwargs = run.call_args
        self.assertNotIn(path, args[0][-1])
        self.assertEqual(kwargs["env"]["AA_COMPARE_INPUT"], os.path.abspath(path))
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 120)


if __name__ == "__main__":
    unittest.main()
