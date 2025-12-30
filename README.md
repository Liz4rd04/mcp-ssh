# MCP SSH Server (Linux Remote Control)

A lightweight **Model Context Protocol (MCP)** server that gives an AI assistant **SSH-based remote control** of a Linux host.

This started life as a Raspberry Pi wardriving helper (Kismet + GPS), but the core is **generic**: point it at **any Linux box** you can SSH into and it exposes a clean tool surface (execute commands, read/write files, process management, etc.).

> ⚠️ Security note: Treat access to this MCP server as equivalent to giving someone SSH access to your target host. Run it only in environments you trust.

## What this is good for

- Quickly **test / troubleshoot** a headless Linux device (Pi, homelab server, VM) from an MCP-enabled assistant
- Automate repeatable ops tasks (system status checks, service restarts, log pulls)
- Optional “wardriving helpers” (Kismet/GPS/Wi‑Fi scans) if those tools are installed

## Tools exposed

### Core (generic)
- `check_connection`
- `execute_command`
- `get_system_status`
- `list_directory`
- `read_file`
- `write_file`
- `get_process_list`
- `kill_process`
- `reboot_host`
- `shutdown_host`

### Optional (only useful if installed on target)
- `kismet_status`, `start_kismet`, `stop_kismet`
- `gps_status`
- `wifi_scan`

## Configuration

Environment variables:

| Variable | Meaning | Default |
|---|---|---|
| `SSH_HOST` | target hostname/IP | `localhost` |
| `SSH_PORT` | ssh port | `22` |
| `SSH_USER` | username | `$USER` or `root` |
| `SSH_KEY` | **private key content** (optional) | empty |
| `SSH_KEY_PATH` | private key path inside container (optional) | empty |
| `SSH_CONNECT_TIMEOUT` | ssh connect timeout (sec) | `10` |
| `SSH_CMD_TIMEOUT` | default command timeout (sec) | `30` |

Backwards compatible aliases (from the Pi version): `PI_HOST`, `PI_PORT`, `PI_USER`, `PI_SSH_KEY`.

## Quick start (local dev)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SSH_HOST="192.168.1.50"
export SSH_USER="luke"
export SSH_KEY="$(cat ~/.ssh/id_ed25519)"   # optional; otherwise ssh-agent is used

python ssh_mcp_server.py
```

## Run in Docker

### Build
```bash
docker build -t mcp-ssh-server .
```

### Run (key via env var)
```bash
docker run --rm -it \
  -e SSH_HOST="192.168.1.50" \
  -e SSH_USER="luke" \
  -e SSH_KEY="$(cat ~/.ssh/id_ed25519)" \
  mcp-ssh-server
```

> Tip: In a real MCP setup (Claude Desktop, etc.) you’ll typically inject `SSH_KEY` via your secret manager rather than an env var in a shell history.

## Extending

Add new tools by creating an async function and decorating it with `@mcp.tool()` in `ssh_mcp_server.py`.

## License

MIT — see `LICENSE`.
