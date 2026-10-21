import argparse
import os
import platform
import re
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

from .client import start_connector
from .server import run_server

WIN_CF_PATH = os.path.join(
    os.environ.get("LOCALAPPDATA", ""), "cloudflared.exe"
)


LINUX_PACKAGE_ARCH = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armhf",
    "armv6l": "armhf",
    "armhf": "armhf",
    "i386": "386",
    "i686": "386",
}

TUNNEL_WAIT_SECONDS = 30
TUNNEL_POLL_INTERVAL = 0.5


def linux_package_arch(machine):
    return LINUX_PACKAGE_ARCH.get(machine.lower())


def install_cloudflared():
    print(">> Checking for cloudflared (for public URL)...")
    try:
        subprocess.run(
            ["cloudflared", "--version"], check=True, capture_output=True
        )
        return
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("⬇️  cloudflared not found. Installing...")

    system = platform.system()
    machine = platform.machine().lower()

    is_arm = "arm" in machine or "aarch64" in machine

    if system == "Linux":
        arch = linux_package_arch(machine)
        if arch is None:
            print(f"❌ No cloudflared package for the CPU type '{machine}'.")
            return
        package = f"cloudflared-linux-{arch}.deb"
        url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/{package}"
        print("Downloading cloudflared for Linux...")
        try:
            urllib.request.urlretrieve(url, package)
            subprocess.run(["sudo", "dpkg", "-i", package], check=True)
            os.remove(package)
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            return

    elif system == "Windows":
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        print(f"Downloading for Windows to {WIN_CF_PATH}...")
        urllib.request.urlretrieve(url, WIN_CF_PATH)
        print("✅ cloudflared downloaded successfully.")

    elif system == "Darwin":
        if is_arm:
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz"
        else:
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz"

        print("Downloading for macOS...")
        urllib.request.urlretrieve(url, "cf.tgz")
        with tarfile.open("cf.tgz", "r:gz") as tar:
            member = next(
                (m for m in tar.getmembers() if m.name == "cloudflared"), None
            )
            if member is None or not member.isfile():
                print("❌ The cloudflared archive has no cloudflared file.")
                return
            if hasattr(tarfile, "data_filter"):
                tar.extract(member, filter="data")
            else:
                tar.extract(member)

        os.chmod("cloudflared", 0o755)
        subprocess.run(
            ["sudo", "mv", "cloudflared", "/usr/local/bin/"], check=True
        )
        os.remove("cf.tgz")


def start_cloudflared_tunnel(port):
    cf_bin = "cloudflared"
    if platform.system() == "Windows" and os.path.exists(WIN_CF_PATH):
        cf_bin = WIN_CF_PATH

    with open("tunnel.log", "w") as log_file:
        proc = subprocess.Popen(
            [cf_bin, "tunnel", "--url", f"http://localhost:{port}"],
            stdout=log_file,
            stderr=log_file,
        )
        deadline = time.time() + TUNNEL_WAIT_SECONDS
        while True:
            time.sleep(TUNNEL_POLL_INTERVAL)
            with open("tunnel.log") as f:
                content = f.read()
            match = re.search(r"https://[\w-]+\.trycloudflare\.com", content)
            if match:
                return proc, match.group(0)
            if proc.poll() is not None or time.time() >= deadline:
                return proc, None


def stop_tunnel(proc):
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    except OSError:
        pass


def port_number(value):
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a port number"
        ) from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            f"{port} is outside the port range 1-65535"
        )
    return port


def non_empty(value):
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def http_url(value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise argparse.ArgumentTypeError(
            f"'{value}' must start with http:// or https:// and name a host"
        )
    return value


def main():
    parser = argparse.ArgumentParser(
        prog="gesher", description="Gesher: Secure HTTP Tunneling"
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_p = subparsers.add_parser(
        "server", help="Run the Remote Bridge Server"
    )
    server_p.add_argument(
        "--secret", type=non_empty, required=True, help="Auth secret"
    )
    server_p.add_argument("--port", type=port_number, default=8000)
    server_p.add_argument(
        "--public", action="store_true", help="Auto-start Cloudflare tunnel"
    )

    client_p = subparsers.add_parser("client", help="Run the Local Connector")
    client_p.add_argument(
        "--gateway", type=http_url, required=True, help="The public Bridge URL"
    )
    client_p.add_argument(
        "--secret", type=non_empty, required=True, help="The Auth Secret"
    )
    client_p.add_argument(
        "--pin",
        type=non_empty,
        required=True,
        help="The Gatekeeper PIN shown on the server",
    )
    client_p.add_argument(
        "--target",
        type=http_url,
        default="http://localhost:8080",
        help="Local service URL",
    )
    client_p.add_argument(
        "--dashboard-port",
        type=port_number,
        default=9000,
        help="Port for local stats dashboard",
    )

    args = parser.parse_args()

    if args.mode == "server":
        tunnel = None
        try:
            if args.public:
                install_cloudflared()
                tunnel, url = start_cloudflared_tunnel(args.port)
                if url:
                    print(f"\n✅ GESHER LIVE\n🔗 URL: {url}\n")
                else:
                    print(
                        "\n❌ The public URL did not appear. "
                        "See tunnel.log for the cloudflared output.\n"
                    )
            run_server(args.port, args.secret)
        finally:
            stop_tunnel(tunnel)
    elif args.mode == "client":
        accepted = start_connector(
            args.gateway,
            args.secret,
            args.target,
            args.pin,
            args.dashboard_port,
        )
        if accepted is False:
            sys.exit(1)


if __name__ == "__main__":
    main()
