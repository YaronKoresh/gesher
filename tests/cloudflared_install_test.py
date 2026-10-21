import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gesher import cli


class TestCloudflaredInstallRobustness(unittest.TestCase):
    def setUp(self):
        self.old_cwd = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(os.chdir, self.old_cwd)

    def test_windows_uses_the_downloaded_file_instead_of_downloading_again(self):
        calls = []

        def run(cmd, **kwargs):
            calls.append(cmd[0])
            if cmd[0] != cli.WIN_CF_PATH:
                raise FileNotFoundError()
            return MagicMock()

        with patch("gesher.cli.platform.system", return_value="Windows"), patch(
            "gesher.cli.platform.machine", return_value="AMD64"
        ), patch("gesher.cli.subprocess.run", side_effect=run), patch(
            "gesher.cli.os.path.exists", return_value=True
        ), patch("gesher.cli.urllib.request.urlretrieve") as retrieve:
            cli.install_cloudflared()

        retrieve.assert_not_called()
        self.assertEqual(calls, [cli.WIN_CF_PATH])

    def test_windows_download_failure_is_reported_not_raised(self):
        with patch("gesher.cli.platform.system", return_value="Windows"), patch(
            "gesher.cli.platform.machine", return_value="AMD64"
        ), patch(
            "gesher.cli.subprocess.run", side_effect=FileNotFoundError()
        ), patch(
            "gesher.cli.urllib.request.urlretrieve",
            side_effect=OSError("network down"),
        ), patch("builtins.print") as out:
            cli.install_cloudflared()

        text = " ".join(str(c.args[0]) for c in out.call_args_list)
        self.assertIn("network down", text)

    def test_macos_download_failure_is_reported_and_leaves_no_files(self):
        with patch("gesher.cli.platform.system", return_value="Darwin"), patch(
            "gesher.cli.platform.machine", return_value="arm64"
        ), patch(
            "gesher.cli.subprocess.run", side_effect=FileNotFoundError()
        ), patch(
            "gesher.cli.urllib.request.urlretrieve",
            side_effect=OSError("network down"),
        ), patch("builtins.print") as out:
            cli.install_cloudflared()

        text = " ".join(str(c.args[0]) for c in out.call_args_list)
        self.assertIn("network down", text)
        self.assertEqual(os.listdir("."), [])

    def test_linux_package_is_removed_when_dpkg_fails(self):
        def retrieve(url, path):
            open(path, "w").close()

        def run(cmd, **kwargs):
            if cmd[0] == "sudo":
                raise OSError("dpkg failed")
            raise FileNotFoundError()

        with patch("gesher.cli.platform.system", return_value="Linux"), patch(
            "gesher.cli.platform.machine", return_value="x86_64"
        ), patch("gesher.cli.subprocess.run", side_effect=run), patch(
            "gesher.cli.urllib.request.urlretrieve", side_effect=retrieve
        ):
            cli.install_cloudflared()

        self.assertEqual(os.listdir("."), [])

    def test_tunnel_start_failure_returns_no_url_instead_of_raising(self):
        with patch(
            "gesher.cli.subprocess.Popen",
            side_effect=FileNotFoundError("cloudflared"),
        ), patch("builtins.print") as out:
            proc, url = cli.start_cloudflared_tunnel(8000)

        self.assertIsNone(proc)
        self.assertIsNone(url)
        text = " ".join(str(c.args[0]) for c in out.call_args_list)
        self.assertIn("cloudflared", text)
        self.assertIsNone(cli.stop_tunnel(proc))


if __name__ == "__main__":
    unittest.main()
