import importlib.util
import os
import pathlib
import subprocess
import sys
import typing
import unittest

from gesher.security import SecurityLayer

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestTypes(unittest.TestCase):
    def test_verify_signature_declares_the_pair_it_returns(self):
        hints = typing.get_type_hints(SecurityLayer.verify_signature)
        self.assertIs(typing.get_origin(hints["return"]), tuple)

    @unittest.skipUnless(importlib.util.find_spec("mypy"), "mypy missing")
    def test_mypy_reports_no_errors(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--ignore-missing-imports",
                "--disable-error-code",
                "import-untyped",
                "--cache-dir",
                os.devnull,
                "src",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
