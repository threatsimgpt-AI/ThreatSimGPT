"""VM Command Execution Tools.

MCP tools for executing commands on VMs via SSH.
Provides secure command execution with safety controls.
"""

import asyncio
import json
import logging
import os
from typing import Any, List, Optional

try:
    import asyncssh
except ImportError:
    asyncssh = None

try:
    from mcp.types import Tool, TextContent
except ImportError:
    # Fallback for type hints
    Tool = Any
    TextContent = Any

from ..providers.proxmox import ProxmoxClient
from ..config import MCPConfig
from ..safety import SafetyController

logger = logging.getLogger(__name__)


# Tool Definitions
VM_EXECUTE_TOOLS: List[Tool] = [
    Tool(
        name="vm_execute",
        description="""Execute a shell command on a virtual machine via SSH.

SAFETY: Commands are validated before execution. Dangerous commands
like 'rm -rf /', 'dd', 'mkfs' are blocked.

Returns stdout, stderr, and exit code.

Example commands:
- "whoami" - Check current user
- "id" - Get user/group info
- "hostname" - Get hostname
- "ip addr" - Show network interfaces
- "nmap -sn 10.0.100.0/24" - Network discovery scan
- "cat /etc/passwd" - Read file contents""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "Target VM ID"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 60, max: 300)",
                    "default": 60
                }
            },
            "required": ["vm_id", "command"]
        }
    ),
    Tool(
        name="vm_execute_script",
        description="""Upload and execute a script on a virtual machine.

Supports bash, python, and powershell scripts.
The script will be uploaded to /tmp and executed.""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "Target VM ID"
                },
                "script": {
                    "type": "string",
                    "description": "Script content"
                },
                "script_type": {
                    "type": "string",
                    "enum": ["bash", "python", "powershell"],
                    "description": "Script language"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 120)",
                    "default": 120
                }
            },
            "required": ["vm_id", "script", "script_type"]
        }
    ),
]


async def execute_ssh_command(
    host: str,
    command: str,
    username: str = "root",
    password: str = "threatsimgpt",
    timeout: int = 60
) -> dict:
    """
    Execute command on remote host via SSH.

    Args:
        host: Target hostname or IP
        command: Command to execute
        username: SSH username
        password: SSH password
        timeout: Command timeout in seconds

    Returns:
        Dict with stdout, stderr, exit_code
    """
    if asyncssh is None:
        raise ImportError("asyncssh is required: pip install asyncssh")

    try:
        async with asyncssh.connect(
            host,
            username=username,
            password=password,
            known_hosts=None,  # Disable host key checking in lab environment
            connect_timeout=10
        ) as conn:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout
            )

            return {
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "exit_code": result.returncode
            }

    except asyncio.TimeoutError:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "exit_code": -1
        }
    except asyncssh.PermissionDenied:
        return {
            "stdout": "",
            "stderr": f"SSH authentication failed for {username}@{host}",
            "exit_code": -1
        }
    except asyncssh.ConnectionLost:
        return {
            "stdout": "",
            "stderr": f"SSH connection lost to {host}",
            "exit_code": -1
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"SSH error: {str(e)}",
            "exit_code": -1
        }


async def handle_vm_execute(
    name: str,
    arguments: dict,
    proxmox: ProxmoxClient,
    config: MCPConfig,
    safety: SafetyController
) -> list:
    """
    Handle VM execute tool calls.

    Args:
        name: Tool name
        arguments: Tool arguments
        proxmox: Proxmox client
        config: MCP configuration
        safety: Safety controller

    Returns:
        List of TextContent responses
    """
    import json

    if name == "vm_execute":
        vm_id = int(arguments["vm_id"])
        command = arguments["command"]
        timeout = min(arguments.get("timeout", 60), 300)  # Max 5 minutes

        # Safety validation
        is_safe, reason = safety.validate_command(command)
        if not is_safe:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Command blocked by safety controller",
                    "reason": reason,
                    "command": command[:100]
                }, indent=2)
            )]

        # Get VM IP address
        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Could not get IP address for VM {vm_id}",
                    "hint": "Ensure VM is running and has qemu-guest-agent installed"
                }, indent=2)
            )]

        # Validate target IP is in allowed network
        is_allowed, reason = safety.validate_network(ip_address)
        if not is_allowed:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Target IP blocked by safety controller",
                    "reason": reason
                }, indent=2)
            )]

        # Get credentials from environment or template
        # SECURITY: Credentials should be provided via environment variables
        username = os.getenv("THREATSIMGPT_VM_USERNAME", "root")
        password = os.getenv("THREATSIMGPT_VM_PASSWORD", "")

        if not password:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "VM credentials not configured",
                    "reason": "Set THREATSIMGPT_VM_PASSWORD environment variable"
                }, indent=2)
            )]

        logger.info(f"Executing on VM {vm_id} ({ip_address}): {command[:50]}...")

        # Execute command
        result = await execute_ssh_command(
            host=ip_address,
            command=command,
            username=username,
            password=password,
            timeout=timeout
        )

        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "ip_address": ip_address,
                "command": command,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    elif name == "vm_execute_script":
        vm_id = int(arguments["vm_id"])
        script = arguments["script"]
        script_type = arguments["script_type"]
        timeout = min(arguments.get("timeout", 120), 600)

        # Validate script doesn't contain dangerous content
        is_safe, reason = safety.validate_command(script)
        if not is_safe:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Script blocked by safety controller",
                    "reason": reason
                }, indent=2)
            )]

        # Get VM IP
        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Could not get IP address for VM {vm_id}"
                }, indent=2)
            )]

        # Determine script extension and interpreter
        script_config = {
            "bash": {"ext": ".sh", "interpreter": "/bin/bash"},
            "python": {"ext": ".py", "interpreter": "/usr/bin/python3"},
            "powershell": {"ext": ".ps1", "interpreter": "powershell -File"},
        }

        conf = script_config[script_type]
        script_name = f"/tmp/threatsimgpt_script_{vm_id}{conf['ext']}"

        # Upload script
        upload_cmd = f"cat > {script_name} << 'THREATSIMGPT_EOF'\n{script}\nTHREATSIMGPT_EOF"
        upload_result = await execute_ssh_command(
            host=ip_address,
            command=upload_cmd,
            timeout=30
        )

        if upload_result["exit_code"] != 0:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Failed to upload script",
                    "stderr": upload_result["stderr"]
                }, indent=2)
            )]

        # Make executable (for bash/python)
        if script_type in ["bash", "python"]:
            await execute_ssh_command(
                host=ip_address,
                command=f"chmod +x {script_name}",
                timeout=10
            )

        # Execute script
        exec_cmd = f"{conf['interpreter']} {script_name}"
        result = await execute_ssh_command(
            host=ip_address,
            command=exec_cmd,
            timeout=timeout
        )

        # Cleanup
        await execute_ssh_command(
            host=ip_address,
            command=f"rm -f {script_name}",
            timeout=10
        )

        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "ip_address": ip_address,
                "script_type": script_type,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    else:
        return [TextContent(
            type="text",
            text=f"Unknown execute tool: {name}"
        )]
