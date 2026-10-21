import contextlib
import io
import pathlib
import re
import unittest
from unittest.mock import patch

import gesher
from gesher import cli

PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"


class TestVersionFlag(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with patch("sys.argv", ["gesher", *args]):
            with contextlib.redirect_stdout(out):
                try:
                    cli.main()
                    code = 0
                except SystemExit as exc:
                    code = exc.code
        return code, out.getvalue()

    def test_version_flag_prints_the_package_version(self):
        code, output = self.run_cli("--version")
        self.assertEqual(code, 0)
        self.assertEqual(output.strip(), f"gesher {gesher.__version__}")

    def test_version_flag_does_not_need_a_mode(self):
        with patch("gesher.cli.run_server") as run_server:
            self.run_cli("--version")
        run_server.assert_not_called()

    def test_a_mode_is_still_required_without_the_flag(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = self.run_cli()
        self.assertEqual(code, 2)

    def test_package_version_matches_pyproject(self):
        text = PYPROJECT.read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), gesher.__version__)


if __name__ == "__main__":
    unittest.main()
