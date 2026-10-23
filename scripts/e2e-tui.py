#!/usr/bin/env python3
"""Automated real-terminal smoke test for the OpenCode TUI through OCT.

This starts an isolated OpenCode server (temporary HOME/XDG roots), an OCT
relay and host, then runs `oct tui` inside a real PTY. It asserts that the
unmodified OpenCode TUI rendered and that no tunnel/password error was shown.

The test never reads the user's auth.json, opencode.db, or provider files.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import os
import pty
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("OCT_BIN", os.path.join(ROOT, "target", "debug", "oct"))
ROOM = "0123456789abcdef0123456789abcdef"
TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PASSWORD = "oct-e2e-tui-password"
MARKER = "OpenCode"
FORBIDDEN = (
    "HOST_OFFLINE",
    "host is offline",
    "requires a password",
    "Connection refused",
    "WebSocket forwarding is not enabled",
    "UNAVAILABLE",
    "x-oct-error",
)
ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|P.*?\x1b\\|_.*?\x1b\\)",
    re.DOTALL,
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def redact(text: str) -> str:
    return text.replace(PASSWORD, "<redacted>").replace(TOKEN, "<redacted>")


def wait_http(url: str, password: str, timeout: float = 20.0) -> None:
    auth = base64.b64encode(f"opencode:{password}".encode()).decode()
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            url, headers={"Authorization": f"Basic {auth}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as error:  # noqa: BLE001 - retry all startup races
            last = error
        time.sleep(0.2)
    raise RuntimeError(f"server did not become ready at {url}: {last}")


def start_process(args: list[str], env: dict[str, str], cwd: str, log: str):
    handle = open(log, "ab", buffering=0)
    process = subprocess.Popen(
        args,
        env=env,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=handle,
        stderr=handle,
        start_new_session=True,
    )
    process._oct_log = handle  # type: ignore[attr-defined]
    return process


def terminate(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    log = getattr(process, "_oct_log", None)
    if log is not None:
        log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--e2ee",
        action="store_true",
        help="pair a device through the CLI and run the TUI over Noise E2EE",
    )
    args = parser.parse_args()
    base = tempfile.mkdtemp(prefix="oct-e2e-tui.")
    server = relay = host = tui = None
    shared = dict(os.environ)
    shared.update(
        {
            "HOME": os.path.join(base, "home"),
            "XDG_DATA_HOME": os.path.join(base, "data"),
            "XDG_CONFIG_HOME": os.path.join(base, "config"),
            "XDG_CACHE_HOME": os.path.join(base, "cache"),
            "XDG_STATE_HOME": os.path.join(base, "state"),
            "OCT_ROOM": ROOM,
            "OCT_TOKEN": TOKEN,
            "OPENCODE_PASSWORD": PASSWORD,
            "TERM": "xterm-256color",
        }
    )
    for name in ("home", "data", "config", "cache", "state", "work", "host", "client"):
        os.makedirs(os.path.join(base, name), exist_ok=True)

    if "OCT_BIN" not in os.environ and os.environ.get("OCT_SKIP_BUILD") != "1":
        print("building oct CLI", file=sys.stderr)
        build = subprocess.run(
            ["cargo", "build", "-p", "oct-cli"],
            cwd=ROOT,
            stdout=sys.stderr,
            stderr=sys.stderr,
            check=False,
        )
        if build.returncode != 0:
            print("FAIL: cannot build oct CLI", file=sys.stderr)
            shutil.rmtree(base, ignore_errors=True)
            return 1

    if not os.path.exists(BIN):
        print(f"FAIL: oct binary not found at {BIN}", file=sys.stderr)
        shutil.rmtree(base, ignore_errors=True)
        return 1

    server_port, relay_port = free_port(), free_port()
    upstream = f"http://127.0.0.1:{server_port}"
    relay_url = f"ws://127.0.0.1:{relay_port}/oct/v1"
    try:
        server = start_process(
            [
                "opencode",
                "serve",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(server_port),
            ],
            shared,
            os.path.join(base, "work"),
            os.path.join(base, "server.log"),
        )
        wait_http(f"{upstream}/api/info", PASSWORD)

        relay = start_process(
            [BIN, "relay", "--listen", f"127.0.0.1:{relay_port}"],
            shared,
            os.path.join(base, "work"),
            os.path.join(base, "relay.log"),
        )
        time.sleep(0.2)
        host_args = [BIN, "host", "--relay", relay_url, "--upstream", upstream]
        if args.e2ee:
            host_args += ["--e2ee", "--state-dir", os.path.join(base, "host")]
        else:
            host_args += ["--no-e2ee"]
        host = start_process(
            host_args,
            shared,
            os.path.join(base, "work"),
            os.path.join(base, "host.log"),
        )
        time.sleep(0.5)

        if args.e2ee:
            invite = subprocess.run(
                [
                    BIN,
                    "invite",
                    "--state-dir",
                    os.path.join(base, "host"),
                    "--relay",
                    relay_url,
                    "--room",
                    ROOM,
                    "--token",
                    TOKEN,
                ],
                env=shared,
                cwd=os.path.join(base, "work"),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if invite.returncode != 0:
                raise RuntimeError(
                    "oct invite failed: " + redact(invite.stderr[-500:])
                )
            uri = next(
                (
                    line.split("=", 1)[1]
                    for line in invite.stdout.splitlines()
                    if line.startswith("pairing_uri=")
                ),
                None,
            )
            if not uri:
                raise RuntimeError("oct invite produced no pairing URI")
            pair = subprocess.run(
                [
                    BIN,
                    "pair",
                    "--invite-stdin",
                    "--state-dir",
                    os.path.join(base, "client"),
                    "--name",
                    "tui-e2ee",
                ],
                env=shared,
                cwd=os.path.join(base, "work"),
                input=uri,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            if pair.returncode != 0:
                raise RuntimeError(
                    "oct pair failed: " + redact(pair.stderr[-500:])
                )

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        tui_args = [BIN, "tui", "--relay", relay_url, "--opencode", "opencode"]
        if args.e2ee:
            tui_args += ["--e2ee", "--state-dir", os.path.join(base, "client")]
        else:
            tui_args += ["--no-e2ee"]
        tui = subprocess.Popen(
            tui_args,
            env=shared,
            cwd=os.path.join(base, "work"),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
        )
        os.close(slave)
        os.set_blocking(master, False)

        captured = bytearray()
        marker_seen = False
        stabilize_until = None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            try:
                chunk = os.read(master, 65536)
            except BlockingIOError:
                chunk = b""
            except OSError:
                break
            if chunk:
                captured.extend(chunk)
                text = ANSI.sub("", captured.decode("utf-8", "replace"))
                if not marker_seen and (MARKER in text or b"OpenCode" in captured):
                    marker_seen = True
                    # Let the TUI attempt its first API/WS work; a banner alone
                    # must not count as a healthy tunnel.
                    stabilize_until = time.monotonic() + 1.5
            if marker_seen and stabilize_until is not None:
                if time.monotonic() >= stabilize_until:
                    break
            if tui.poll() is not None:
                break
            time.sleep(0.05)

        if not marker_seen:
            # Read whatever the TUI wrote before exiting.
            try:
                while True:
                    chunk = os.read(master, 65536)
                    if not chunk:
                        break
                    captured.extend(chunk)
            except (BlockingIOError, OSError):
                pass

        early_exit = tui.poll()
        try:
            os.write(master, b"\x03")
        except OSError:
            pass
        try:
            tui.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(tui.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                tui.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(tui.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                tui.wait(timeout=3)
        os.close(master)

        raw = bytes(captured)
        screen = ANSI.sub("", raw.decode("utf-8", "replace"))
        if not raw:
            print("FAIL: TUI produced no terminal output", file=sys.stderr)
            return 1
        if b"\x1b" not in raw:
            print("FAIL: TUI output had no terminal control sequences", file=sys.stderr)
            return 1
        if not marker_seen:
            print("FAIL: TUI did not render the OpenCode marker", file=sys.stderr)
            print(redact(screen[-2000:]), file=sys.stderr)
            return 1
        if early_exit is not None:
            print(f"FAIL: TUI exited early with code {early_exit}", file=sys.stderr)
            print(redact(screen[-2000:]), file=sys.stderr)
            return 1
        lowered = screen.lower()
        for forbidden in FORBIDDEN:
            if forbidden.lower() in lowered:
                print(f"FAIL: TUI reported {forbidden!r}", file=sys.stderr)
                print(redact(screen[-2000:]), file=sys.stderr)
                return 1
        print("TUI E2E OK: OpenCode rendered through oct tui")
        return 0
    except Exception as error:  # noqa: BLE001 - report one actionable line
        print(f"FAIL: {redact(str(error))}", file=sys.stderr)
        for name, process in (
            ("tui", tui),
            ("host", host),
            ("relay", relay),
            ("server", server),
        ):
            if process is not None and process.poll() is not None:
                print(f"{name} exit={process.returncode}", file=sys.stderr)
        return 1
    finally:
        for process in (tui, host, relay, server):
            terminate(process)
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
