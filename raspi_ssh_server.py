#!/usr/bin/env python3
"""
Raspberry Pi SSH MCP Server - Full remote control for wardriving operations
"""
import os
import sys
import logging
import asyncio
from datetime import datetime, timezone
import asyncssh
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("raspi-ssh-server")

# Initialize MCP server
mcp = FastMCP("raspi-ssh")

# Configuration from environment variables - UPDATED DEFAULTS
PI_HOST = os.environ.get("PI_HOST", "YOUR_LINUX_BOX_IP")
PI_USER = os.environ.get("PI_USER", "YOUR_LINUX_BOX_USERNAME")
PI_SSH_KEY = os.environ.get("PI_SSH_KEY", "")
PI_PORT = int(os.environ.get("PI_PORT", "22"))

# === UTILITY FUNCTIONS ===

async def run_ssh_command(command: str = "", timeout: int = 30):
    """Execute command on Raspberry Pi via SSH and return output."""
    if not command.strip():
        return None, "No command provided"
    
    try:
        # Setup SSH connection options
        connect_kwargs = {
            'host': PI_HOST,
            'port': PI_PORT,
            'username': PI_USER,
            'known_hosts': None,
        }
        
        # Use SSH key if provided, otherwise rely on ssh-agent
        if PI_SSH_KEY.strip():
            key_path = "/home/mcpuser/.ssh/pi_key"
            connect_kwargs['client_keys'] = [key_path]
        
        # Connect and execute command
        async with asyncssh.connect(**connect_kwargs) as conn:
            result = await asyncio.wait_for(
                conn.run(command),
                timeout=timeout
            )
            
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            exit_status = result.exit_status
            
            return (stdout, stderr, exit_status), None
            
    except asyncio.TimeoutError:
        return None, f"Command timed out after {timeout} seconds"
    except asyncssh.Error as e:
        return None, f"SSH error: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def format_command_output(result, error, command: str = ""):
    """Format command execution results for display."""
    if error:
        return f"❌ Error executing command:\n{command}\n\n{error}"
    
    stdout, stderr, exit_status = result
    
    output = f"⚡ Command: {command}\n"
    output += f"Exit Status: {exit_status}\n"
    output += "=" * 60 + "\n"
    
    if stdout:
        output += f"📤 Output:\n{stdout}\n"
    
    if stderr:
        output += f"⚠️ Stderr:\n{stderr}\n"
    
    if not stdout and not stderr:
        output += "✅ Command completed (no output)\n"
    
    return output

# === MCP TOOLS ===

@mcp.tool()
async def execute_command(command: str = "", timeout: str = "30") -> str:
    """Execute any shell command on the Raspberry Pi with full privileges."""
    logger.info(f"Executing command: {command}")
    
    if not command.strip():
        return "❌ Error: Command cannot be empty"
    
    try:
        timeout_int = int(timeout) if timeout.strip() else 30
        result, error = await run_ssh_command(command, timeout_int)
        return format_command_output(result, error, command)
    except ValueError:
        return f"❌ Error: Invalid timeout value: {timeout}"
    except Exception as e:
        logger.error(f"Error: {e}")
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def read_file(filepath: str = "") -> str:
    """Read contents of a file from the Raspberry Pi."""
    logger.info(f"Reading file: {filepath}")
    
    if not filepath.strip():
        return "❌ Error: Filepath cannot be empty"
    
    command = f"cat {filepath}"
    result, error = await run_ssh_command(command)
    
    if error:
        return f"❌ Error reading file {filepath}:\n{error}"
    
    stdout, stderr, exit_status = result
    
    if exit_status != 0:
        return f"❌ Error reading file {filepath}:\n{stderr}"
    
    return f"📁 Contents of {filepath}:\n{'=' * 60}\n{stdout}"

@mcp.tool()
async def write_file(filepath: str = "", content: str = "") -> str:
    """Write content to a file on the Raspberry Pi."""
    logger.info(f"Writing to file: {filepath}")
    
    if not filepath.strip():
        return "❌ Error: Filepath cannot be empty"
    
    if not content.strip():
        return "❌ Error: Content cannot be empty"
    
    # Escape single quotes in content
    escaped_content = content.replace("'", "'\\''")
    command = f"echo '{escaped_content}' > {filepath}"
    
    result, error = await run_ssh_command(command)
    
    if error:
        return f"❌ Error writing file {filepath}:\n{error}"
    
    stdout, stderr, exit_status = result
    
    if exit_status != 0:
        return f"❌ Error writing file {filepath}:\n{stderr}"
    
    return f"✅ Successfully wrote to {filepath}"

@mcp.tool()
async def list_directory(path: str = "") -> str:
    """List contents of a directory on the Raspberry Pi with detailed information."""
    logger.info(f"Listing directory: {path}")
    
    dir_path = path.strip() if path.strip() else "~"
    command = f"ls -lah {dir_path}"
    
    result, error = await run_ssh_command(command)
    return format_command_output(result, error, command)

@mcp.tool()
async def get_system_status() -> str:
    """Get comprehensive system status of the Raspberry Pi including CPU, memory, disk, and temperature."""
    logger.info("Getting system status")
    
    command = """
    echo "=== SYSTEM STATUS ===" && \
    echo "Hostname: $(hostname)" && \
    echo "Uptime: $(uptime -p)" && \
    echo "" && \
    echo "=== CPU INFO ===" && \
    top -bn1 | head -n 5 && \
    echo "" && \
    echo "=== MEMORY ===" && \
    free -h && \
    echo "" && \
    echo "=== DISK USAGE ===" && \
    df -h && \
    echo "" && \
    echo "=== TEMPERATURE ===" && \
    vcgencmd measure_temp 2>/dev/null || echo "Temperature not available" && \
    echo "" && \
    echo "=== NETWORK ===" && \
    ip -br addr
    """
    
    result, error = await run_ssh_command(command, timeout=15)
    
    if error:
        return f"❌ Error getting system status:\n{error}"
    
    stdout, stderr, exit_status = result
    return f"📊 Raspberry Pi System Status:\n{'=' * 60}\n{stdout}"

@mcp.tool()
async def kismet_status() -> str:
    """Check Kismet service status and recent capture information."""
    logger.info("Checking Kismet status")
    
    command = """
    echo "=== KISMET SERVICE ===" && \
    sudo systemctl status kismet 2>/dev/null || echo "Kismet service not found" && \
    echo "" && \
    echo "=== KISMET PROCESSES ===" && \
    ps aux | grep kismet | grep -v grep || echo "No Kismet processes running" && \
    echo "" && \
    echo "=== RECENT CAPTURES ===" && \
    ls -lth /var/log/kismet/ 2>/dev/null | head -n 10 || echo "No capture directory found"
    """
    
    result, error = await run_ssh_command(command, timeout=15)
    return format_command_output(result, error, "kismet_status")

@mcp.tool()
async def start_kismet() -> str:
    """Start Kismet capture service."""
    logger.info("Starting Kismet")
    
    command = "sudo systemctl start kismet && sleep 2 && sudo systemctl status kismet"
    result, error = await run_ssh_command(command, timeout=15)
    return format_command_output(result, error, "start_kismet")

@mcp.tool()
async def stop_kismet() -> str:
    """Stop Kismet capture service."""
    logger.info("Stopping Kismet")
    
    command = "sudo systemctl stop kismet && sleep 2 && sudo systemctl status kismet"
    result, error = await run_ssh_command(command, timeout=15)
    return format_command_output(result, error, "stop_kismet")

@mcp.tool()
async def wifi_scan() -> str:
    """Perform a quick WiFi scan to see available networks."""
    logger.info("Scanning WiFi networks")
    
    command = """
    echo "=== WIFI INTERFACES ===" && \
    iwconfig 2>/dev/null | grep -v "no wireless" && \
    echo "" && \
    echo "=== SCANNING NETWORKS ===" && \
    sudo iwlist wlan0 scan 2>/dev/null | grep -E "Cell|ESSID|Quality|Encryption" || \
    echo "Scan failed - check interface name or permissions"
    """
    
    result, error = await run_ssh_command(command, timeout=30)
    return format_command_output(result, error, "wifi_scan")

@mcp.tool()
async def gps_status() -> str:
    """Check GPS device status and current location if available."""
    logger.info("Checking GPS status")
    
    command = """
    echo "=== GPS DEVICES ===" && \
    ls -la /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || echo "No GPS devices found" && \
    echo "" && \
    echo "=== GPSD STATUS ===" && \
    sudo systemctl status gpsd 2>/dev/null || echo "GPSD not installed/running" && \
    echo "" && \
    echo "=== GPS DATA ===" && \
    timeout 5 gpspipe -w -n 10 2>/dev/null | grep -m 1 TPV || echo "No GPS fix available"
    """
    
    result, error = await run_ssh_command(command, timeout=15)
    return format_command_output(result, error, "gps_status")

@mcp.tool()
async def get_process_list(filter: str = "") -> str:
    """Get list of running processes, optionally filtered by name."""
    logger.info(f"Getting process list with filter: {filter}")
    
    if filter.strip():
        command = f"ps aux | grep -i '{filter}' | grep -v grep"
    else:
        command = "ps aux"
    
    result, error = await run_ssh_command(command)
    return format_command_output(result, error, command)

@mcp.tool()
async def kill_process(pid: str = "") -> str:
    """Kill a process by PID on the Raspberry Pi."""
    logger.info(f"Killing process: {pid}")
    
    if not pid.strip():
        return "❌ Error: PID cannot be empty"
    
    try:
        int(pid)
    except ValueError:
        return f"❌ Error: Invalid PID: {pid}"
    
    command = f"sudo kill -9 {pid} && echo 'Process killed'"
    result, error = await run_ssh_command(command)
    return format_command_output(result, error, command)

@mcp.tool()
async def download_capture_files() -> str:
    """List available Kismet capture files for download."""
    logger.info("Listing capture files")
    
    command = """
    echo "=== KISMET CAPTURES ===" && \
    find /var/log/kismet/ -name "*.kismet" -o -name "*.pcap" 2>/dev/null | \
    xargs ls -lh 2>/dev/null || echo "No capture files found"
    """
    
    result, error = await run_ssh_command(command)
    return format_command_output(result, error, "list_captures")

@mcp.tool()
async def reboot_pi() -> str:
    """Reboot the Raspberry Pi (use with caution)."""
    logger.info("Rebooting Raspberry Pi")
    
    command = "sudo reboot"
    result, error = await run_ssh_command(command, timeout=5)
    
    if error and "timed out" in error.lower():
        return "✅ Reboot command sent - Pi is restarting"
    
    return format_command_output(result, error, command)

@mcp.tool()
async def shutdown_pi() -> str:
    """Shutdown the Raspberry Pi (use with caution)."""
    logger.info("Shutting down Raspberry Pi")
    
    command = "sudo shutdown -h now"
    result, error = await run_ssh_command(command, timeout=5)
    
    if error and "timed out" in error.lower():
        return "✅ Shutdown command sent - Pi is powering off"
    
    return format_command_output(result, error, command)

@mcp.tool()
async def check_connection() -> str:
    """Test SSH connection to the Raspberry Pi."""
    logger.info("Testing connection")
    
    command = "echo 'Connection successful!' && hostname && date"
    result, error = await run_ssh_command(command, timeout=10)
    
    if error:
        return f"❌ Connection failed:\n{error}\n\nCheck that:\n- Pi is powered on\n- Pi is on the same network\n- SSH is enabled on Pi\n- Hostname/IP is correct: {PI_HOST}"
    
    stdout, stderr, exit_status = result
    return f"✅ Successfully connected to {PI_HOST}!\n\n{stdout}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting Raspberry Pi SSH MCP server...")
    logger.info(f"Target: {PI_USER}@{PI_HOST}:{PI_PORT}")
    
    # Check if SSH key needs to be written
    if PI_SSH_KEY.strip():
        try:
            key_path = "/home/mcpuser/.ssh/pi_key"
            with open(key_path, 'w') as f:
                f.write(PI_SSH_KEY)
            os.chmod(key_path, 0o600)
            logger.info("SSH key configured")
        except Exception as e:
            logger.error(f"Failed to write SSH key: {e}")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
