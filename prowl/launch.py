"""Launch a native client against a discovered service — SSH, RDP, VNC, Telnet, SMB, web.

Security model (this runs behind the loopback-only API, but defends in depth anyway):
  * `build()` is pure and does the validation: protocol allow-list, IPv4-only targets,
    port range, and a strict username pattern. It returns a plan; it touches nothing.
  * `execute()` performs the side effect. Commands are always built as an argv **list** and
    spawned without a shell, so target/username values can never be interpreted as shell
    syntax.
  * Passwords are never placed on the command line (visible in `ps`) and never logged. The
    only auto-fill path is SSH via `sshpass -e`, which reads the password from an environment
    variable. For every other protocol the native client prompts for it.

The caller is responsible for checking the target is a host Prowl actually discovered.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile

log = logging.getLogger("prowl.launch")

WINDOWS = platform.system() == "Windows"
MACOS = platform.system() == "Darwin"

# domain\user, user@realm, plain user — but nothing that could be shell/metacharacters.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@\\-]{1,64}$")

DEFAULT_PORTS = {"ssh": 22, "rdp": 3389, "vnc": 5900, "telnet": 23, "smb": 445,
                 "http": 80, "https": 443}
SUPPORTED = set(DEFAULT_PORTS)


class LaunchError(Exception):
    """A launch request that fails validation."""


def validate(proto: str, ip: str, port: int, username: str | None) -> None:
    if proto not in SUPPORTED:
        raise LaunchError(f"unsupported protocol: {proto}")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        raise LaunchError("target must be an IPv4 address")
    if not (1 <= int(port) <= 65535):
        raise LaunchError("port out of range")
    if username and not USERNAME_RE.match(username):
        raise LaunchError("username has invalid characters")


def build(proto: str, ip: str, port: int, username: str | None = None,
          password: str | None = None) -> dict:
    """Pure: validate and return a launch plan. No processes are started here.

    Plan shapes: {"mode": "terminal", "argv": [...], "env": {...}, "note": str}
                 {"mode": "uri", "uri": str, "note": str}
                 {"mode": "rdp-win", "ip", "port", "username", "note"}
    """
    validate(proto, ip, port, username)
    port = int(port)
    have_sshpass = bool(shutil.which("sshpass"))

    if proto == "ssh":
        target = f"{username + '@' if username else ''}{ip}"
        argv = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", str(port), target]
        env: dict[str, str] = {}
        note = "Host key accepted on first use."
        if password and have_sshpass:
            argv = ["sshpass", "-e"] + argv
            env = {"SSHPASS": password}
            note = "Password passed via sshpass env (kept out of the process list)."
        elif password:
            note = "Install 'sshpass' to auto-fill the password; otherwise ssh prompts for it."
        return {"mode": "terminal", "argv": argv, "env": env, "note": note}

    if proto == "telnet":
        return {"mode": "terminal", "argv": ["telnet", ip, str(port)], "env": {},
                "note": "Telnet is cleartext — credentials travel unencrypted."}

    if proto == "rdp":
        if WINDOWS:
            return {"mode": "rdp-win", "ip": ip, "port": port, "username": username, "env": {},
                    "note": "Opens mstsc; it prompts for the password."}
        argv = ["xfreerdp", f"/v:{ip}:{port}"]
        if username:
            argv.append(f"/u:{username}")
        return {"mode": "terminal", "argv": argv, "env": {},
                "note": "xfreerdp prompts for the password (install freerdp2-x11 if missing)."}

    if proto == "vnc":
        return {"mode": "terminal", "argv": ["vncviewer", f"{ip}::{port}"], "env": {},
                "note": "The VNC client prompts for the password."}

    if proto == "smb":
        uri = f"\\\\{ip}" if WINDOWS else f"smb://{ip}"
        return {"mode": "uri", "uri": uri, "env": {}, "note": "Opens the file manager to the share."}

    # http / https
    scheme = "https" if proto == "https" or port in (443, 8443) else "http"
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    uri = f"{scheme}://{ip}{'' if default else ':' + str(port)}/"
    return {"mode": "uri", "uri": uri, "env": {}, "note": ""}


def _terminal_wrapper(argv: list[str]) -> list[str] | None:
    """Wrap argv so it runs inside a new terminal window, or None if no terminal is available."""
    if WINDOWS:
        wt = shutil.which("wt")
        return [wt, *argv] if wt else ["cmd", "/c", "start", "", "cmd", "/k", *argv]
    if MACOS:
        inner = shlex.join(argv)
        return ["osascript", "-e", f'tell application "Terminal" to do script {shlex.quote(inner)}']
    for term, flag in [("x-terminal-emulator", "-e"), ("gnome-terminal", "--"),
                       ("konsole", "-e"), ("xfce4-terminal", "-x"), ("xterm", "-e")]:
        if shutil.which(term):
            return [term, flag, *argv]
    return None


def _open_uri(uri: str) -> None:
    if uri.startswith("http"):
        import webbrowser
        webbrowser.open(uri)
    elif WINDOWS:
        subprocess.Popen(["explorer", uri])
    elif MACOS:
        subprocess.Popen(["open", uri])
    else:
        subprocess.Popen(["xdg-open", uri])


def execute(plan: dict) -> dict:
    """Perform the plan's side effect. Returns {launched, how, command?, note}.

    The returned `command` (when present) is safe to show: it never contains the password,
    because the only password path is the SSHPASS environment variable.
    """
    mode = plan["mode"]

    if mode == "uri":
        try:
            _open_uri(plan["uri"])
            return {"launched": True, "how": f"opened {plan['uri']}", "note": plan.get("note", "")}
        except OSError as e:
            return {"launched": False, "how": f"could not open {plan['uri']}: {e}", "note": plan.get("note", "")}

    if mode == "rdp-win":
        try:
            content = f"full address:s:{plan['ip']}:{plan['port']}\r\n"
            if plan.get("username"):
                content += f"username:s:{plan['username']}\r\n"
            tf = tempfile.NamedTemporaryFile("w", suffix=".rdp", delete=False, encoding="utf-8")
            tf.write(content)
            tf.close()
            subprocess.Popen(["mstsc", tf.name])
            return {"launched": True, "how": "opened mstsc", "note": plan.get("note", "")}
        except OSError as e:
            return {"launched": False, "how": f"could not start mstsc: {e}", "note": plan.get("note", "")}

    # terminal
    argv = plan["argv"]
    command = shlex.join(argv)
    wrapper = _terminal_wrapper(argv)
    can_spawn = WINDOWS or MACOS or bool(os.environ.get("DISPLAY"))
    if wrapper and can_spawn:
        env = dict(os.environ)
        env.update(plan.get("env") or {})
        try:
            subprocess.Popen(wrapper, env=env, start_new_session=not WINDOWS)
            return {"launched": True, "how": "opened a terminal", "command": command, "note": plan.get("note", "")}
        except OSError as e:
            return {"launched": False, "how": f"could not launch: {e}", "command": command, "note": plan.get("note", "")}
    return {"launched": False, "how": "no graphical terminal on this machine",
            "command": command, "note": "Run the command yourself. " + (plan.get("note") or "")}
