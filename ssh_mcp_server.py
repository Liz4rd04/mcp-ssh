#!/usr/bin/env python3
"""mcp-ssh-server

A Model Context Protocol (MCP) server that exposes a small, practical set of tools
for remote control of a Linux host over SSH.

Originally built for a Raspberry Pi wardriving workflow, but designed to work on
*any* Linux box you can SSH into (Pi, NUC, VM, cloud box, etc.).

Security model: this server is intentionally powerful. Treat access to this MCP
server as equivalent to SSH access to the target host.

Environment variables:
- SSH_HOST: hostname/IP of target (default: localhost)
- SSH_PORT: SSH port (default: 22)
- SSH_USER: username (default: $USER or "root")
- SSH_KEY: private key content (PEM or OpenSSH) (optional)
- SSH_KEY_PATH: path to a private key already present in the container (optional)
- SSH_CONNECT_TIMEOUT: seconds (default: 10)
- SSH_CMD_TIMEOUT: seconds (default: 30)

Backwards-compatible aliases (from the original Pi-focused version):
- PI_HOST -> SSH_HOST
- PI_PORT -> SSH_PORT
- PI_USER -> SSH_USER
- PI_SSH_KEY -> SSH_KEY
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import asyncssh
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("mcp-ssh-server")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

mcp = FastMCP("SSH MCP Server")

DEFAULT_KEY_PATH = Path.home() / ".ssh" / "mcp_ssh_key"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)).strip())
    except Exception:
        return default


@dataclass(frozen=True)
class SSHConfig:
    host: str
    port: int
    user: str
    key: str
    key_path: str
    connect_timeout: int
    cmd_timeout: int

    @staticmethod
    def from_env() -> "SSHConfig":
        # Back-compat envs
        host = _env("SSH_HOST") or _env("PI_HOST") or "localhost"
        port = _env_int("SSH_PORT", 22) if _env("SSH_PORT") else _env_int("PI_PORT", 22)
        user = _env("SSH_USER") or _env("PI_USER") or (_env("USER") or "root")
        key = _env("SSH_KEY") or _env("PI_SSH_KEY") or ""
        key_path = _env("SSH_KEY_PATH") or ""
        connect_timeout = _env_int("SSH_CONNECT_TIMEOUT", 10)
        cmd_timeout = _env_int("SSH_CMD_TIMEOUT", 30)
        return SSHConfig(
            host=host,
            port=port,
            user=user,
            key=key,
            key_path=key_path,
            connect_timeout=connect_timeout,
            cmd_timeout=cmd_timeout,
        )


def _ensure_key_file(cfg: SSHConfig) -> Optional[str]:
    """If SSH_KEY is provided, write it to DEFAULT_KEY_PATH and return that path.

    If SSH_KEY_PATH is provided, return it.
    If neither is provided, return None (asyncssh may use ssh-agent).
    """
    if cfg.key_path.strip():
        return cfg.key_path.strip()

    if not cfg.key.strip():
        return None

    DEFAULT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_KEY_PATH.write_text(cfg.key.strip() + "\n", encoding="utf-8")
    os.chmod(DEFAULT_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return str(DEFAULT_KEY_PATH)


async def _run_ssh(command: str, timeout: Optional[int] = None) -> Tuple[Optional[tuple], Optional[str]]:
    """Run a command over SSH and return (stdout, stderr, exit_status)."""
    cfg = SSHConfig.from_env()

    if not command or not command.strip():
        return None, "No command provided"

    key_file = _ensure_key_file(cfg)

    connect_kwargs = dict(
        host=cfg.host,
        port=cfg.port,
        username=cfg.user,
        known_hosts=None,  # user-managed trust; keeps container friction low
        connect_timeout=cfg.connect_timeout,
    )
    if key_file:
        connect_kwargs["client_keys"] = [key_file]

    cmd_timeout = timeout if timeout is not None else cfg.cmd_timeout

    try:
        async with asyncssh.connect(**connect_kwargs) as conn:
            result = await asyncio.wait_for(conn.run(command), timeout=cmd_timeout)
            return (result.stdout, result.stderr, result.exit_status), None
    except asyncio.TimeoutError:
        return None, f"Command timed out after {cmd_timeout} seconds"
    except asyncssh.Error as e:
        return None, f"SSH error: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def _format(result: Optional[tuple], error: Optional[str], command: str) -> str:
    if error:
        return f"❌ Error\n\nCommand: {command}\n\n{error}"
    if not result:
        return f"⚠️ No result\n\nCommand: {command}"

    stdout, stderr, exit_status = result
    parts = [f"⚡ Command: {command}", f"Exit: {exit_status}"]

    if stdout and stdout.strip():
        parts.append("\n✅ STDOUT:\n" + stdout.rstrip())
    if stderr and stderr.strip():
        parts.append("\n⚠️ STDERR:\n" + stderr.rstrip())

    return "\n".join(parts)


# -----------------------
# Core tools (generic)
# -----------------------

@mcp.tool()
async def check_connection() -> str:
    """Check SSH connectivity and basic identity."""
    cmd = "whoami && hostname && uname -a"
    res, err = await _run_ssh(cmd, timeout=15)
    return _format(res, err, cmd)


@mcp.tool()
async def execute_command(command: str, timeout_seconds: int = 30) -> str:
    """Execute any shell command on the target host via SSH."""
    # log command for audit trail
    logger.info("execute_command: %s", command)
    res, err = await _run_ssh(command, timeout=timeout_seconds)
    return _format(res, err, command)


@mcp.tool()
async def get_system_status() -> str:
    """Get high-level CPU/mem/disk uptime + temperature (if available)."""
    cmd = """set -e
echo "== Identity =="
whoami; hostname; date
echo
echo "== Uptime / Load =="
uptime || true
echo
echo "== CPU =="
lscpu | sed -n '1,12p' || true
echo
echo "== Memory =="
free -h || true
echo
echo "== Disk =="
df -h / || df -h || true
echo
echo "== Temp (if available) =="
( cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{print $1/1000" C"}' ) || echo "N/A"
"""
    res, err = await _run_ssh(cmd, timeout=40)
    return _format(res, err, "get_system_status")


@mcp.tool()
async def list_directory(path: str = ".") -> str:
    """List files in a directory (ls -la)."""
    safe = shlex.quote(path)
    cmd = f"ls -la {safe}"
    res, err = await _run_ssh(cmd, timeout=20)
    return _format(res, err, cmd)


@mcp.tool()
async def read_file(path: str) -> str:
    """Read a file (cat)."""
    safe = shlex.quote(path)
    cmd = f"sed -n '1,400p' {safe}"
    res, err = await _run_ssh(cmd, timeout=20)
    return _format(res, err, cmd)


@mcp.tool()
async def write_file(path: str, content: str, append: bool = False) -> str:
    """Write content to a file (optionally append).

    NOTE: This uses a heredoc. Large files are possible but avoid huge binaries.
    """
    safe = shlex.quote(path)
    redir = ">>" if append else ">"
    cmd = f"cat {redir} {safe} << 'MCP_EOF'\n{content}\nMCP_EOF"
    res, err = await _run_ssh(cmd, timeout=40)
    return _format(res, err, f"write_file {path} (append={append})")


@mcp.tool()
async def get_process_list(filter: str = "") -> str:
    """List processes (ps aux), optionally filter by substring."""
    if filter.strip():
        f = shlex.quote(filter.strip())
        cmd = f"ps aux | grep -i --color=never {f} | grep -v grep || true"
    else:
        cmd = "ps aux --sort=-%cpu | head -n 30"
    res, err = await _run_ssh(cmd, timeout=20)
    return _format(res, err, "get_process_list")


@mcp.tool()
async def kill_process(pid: int, signal: str = "TERM") -> str:
    """Send a signal to a PID (default TERM)."""
    sig = shlex.quote(signal.strip().upper() or "TERM")
    cmd = f"kill -s {sig} {int(pid)}"
    res, err = await _run_ssh(cmd, timeout=15)
    return _format(res, err, cmd)


@mcp.tool()
async def reboot_host() -> str:
    """Reboot the target host (requires sudo privileges on the target)."""
    cmd = "sudo reboot"
    res, err = await _run_ssh(cmd, timeout=10)
    return _format(res, err, cmd)


@mcp.tool()
async def shutdown_host() -> str:
    """Shutdown the target host (requires sudo privileges on the target)."""
    cmd = "sudo shutdown -h now"
    res, err = await _run_ssh(cmd, timeout=10)
    return _format(res, err, cmd)


# -----------------------
# Optional: wardriving helpers (safe to ignore if not installed)
# -----------------------

@mcp.tool()
async def kismet_status() -> str:
    """Check Kismet service status (if installed)."""
    cmd = "systemctl status kismet --no-pager || true; ls -la /var/log/kismet 2>/dev/null | tail -n +1 || true"
    res, err = await _run_ssh(cmd, timeout=25)
    return _format(res, err, "kismet_status")


@mcp.tool()
async def start_kismet() -> str:
    """Start Kismet service (if installed)."""
    cmd = "sudo systemctl start kismet || true; systemctl is-active kismet || true"
    res, err = await _run_ssh(cmd, timeout=25)
    return _format(res, err, "start_kismet")


@mcp.tool()
async def stop_kismet() -> str:
    """Stop Kismet service (if installed)."""
    cmd = "sudo systemctl stop kismet || true; systemctl is-active kismet || true"
    res, err = await _run_ssh(cmd, timeout=25)
    return _format(res, err, "stop_kismet")


@mcp.tool()
async def gps_status() -> str:
    """Check GPS status (gpsd / cgps / gpsmon if installed)."""
    cmd = """set -e
echo "== Devices =="
ls -l /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || true
echo
echo "== gpsd =="
systemctl is-active gpsd 2>/dev/null || true
systemctl status gpsd --no-pager 2>/dev/null | sed -n '1,20p' || true
echo
echo "== cgps (5s) =="
timeout 5 cgps -s 2>/dev/null || true
"""
    res, err = await _run_ssh(cmd, timeout=25)
    return _format(res, err, "gps_status")


@mcp.tool()
async def wifi_scan(interface: str = "wlan0") -> str:
    """Quick Wi-Fi scan using nmcli (preferred) or iwlist."""
    iface = shlex.quote(interface)
    cmd = f"(nmcli -t -f SSID,SECURITY,SIGNAL dev wifi list ifname {iface} 2>/dev/null | head -n 50) || (sudo iwlist {iface} scan 2>/dev/null | head -n 200) || true"
    res, err = await _run_ssh(cmd, timeout=35)
    return _format(res, err, "wifi_scan")


def main() -> None:
    cfg = SSHConfig.from_env()
    logger.info(
        "Starting MCP SSH server -> %s@%s:%s",
        cfg.user,
        cfg.host,
        cfg.port,
    )
    # Ensure key file early so Docker permissions issues fail fast
    _ensure_key_file(cfg)
    mcp.run()


if __name__ == "__main__":
    main()
