"""
VM Lifecycle Tools

MCP tools for VM creation, starting, stopping, and destruction.
"""

import asyncio
import json
import logging
from typing import Any, List

from mcp.types import Tool, TextContent

from ..providers.proxmox import ProxmoxClient
from ..config import MCPConfig

logger = logging.getLogger(__name__)


# Tool Definitions
VM_LIFECYCLE_TOOLS: List[Tool] = [
    Tool(
        name="vm_list",
        description="List all virtual machines and their current status.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    Tool(
        name="vm_status",
        description="Get detailed status of a specific VM including IP address, CPU, memory usage.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to check"
                }
            },
            "required": ["vm_id"]
        }
    ),
    Tool(
        name="vm_create",
        description="""Create a new virtual machine from a template.

Available templates:
- ubuntu-attacker: Ubuntu 24.04 with security tools (nmap, metasploit, gobuster, nuclei, hydra)
- ubuntu-target: Ubuntu 24.04 as vulnerable target
- windows-target: Windows 11 as vulnerable target

The VM will be automatically started and you'll receive the IP address once ready.
This typically takes 30-90 seconds.""",
        inputSchema={
            "type": "object",
            "properties": {
                "template": {
                    "type": "string",
                    "enum": ["ubuntu-attacker", "ubuntu-target", "windows-target"],
                    "description": "VM template to use"
                },
                "name": {
                    "type": "string",
                    "description": "Name for the new VM (alphanumeric and hyphens only, max 32 chars)"
                }
            },
            "required": ["template", "name"]
        }
    ),
    Tool(
        name="vm_start",
        description="Start a stopped virtual machine.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to start"
                }
            },
            "required": ["vm_id"]
        }
    ),
    Tool(
        name="vm_stop",
        description="Stop a running virtual machine gracefully (ACPI shutdown).",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to stop"
                }
            },
            "required": ["vm_id"]
        }
    ),
    Tool(
        name="vm_destroy",
        description="Permanently delete a virtual machine and all its data. This cannot be undone.",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to destroy"
                }
            },
            "required": ["vm_id"]
        }
    ),
]


async def handle_vm_lifecycle(
    name: str,
    arguments: dict,
    proxmox: ProxmoxClient,
    config: MCPConfig
) -> List[TextContent]:
    """
    Handle VM lifecycle tool calls.

    Args:
        name: Tool name
        arguments: Tool arguments
        proxmox: Proxmox client
        config: MCP configuration

    Returns:
        List of TextContent responses
    """

    if name == "vm_list":
        vms = await proxmox.list_vms()

        # Format for readability
        formatted = []
        for vm in vms:
            formatted.append({
                "vmid": vm.get("vmid"),
                "name": vm.get("name"),
                "status": vm.get("status"),
                "mem_mb": vm.get("mem", 0) // (1024 * 1024),
                "cpu_usage": f"{vm.get('cpu', 0) * 100:.1f}%"
            })

        return [TextContent(
            type="text",
            text=json.dumps(formatted, indent=2)
        )]

    elif name == "vm_status":
        vm_id = int(arguments["vm_id"])

        status = await proxmox.get_vm(vm_id)
        ip_address = await proxmox.get_vm_ip(vm_id)

        result = {
            "vmid": vm_id,
            "name": status.get("name"),
            "status": status.get("status"),
            "ip_address": ip_address,
            "uptime_seconds": status.get("uptime", 0),
            "cpu_count": status.get("cpus"),
            "memory_mb": status.get("maxmem", 0) // (1024 * 1024),
            "memory_used_mb": status.get("mem", 0) // (1024 * 1024),
        }

        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]

    elif name == "vm_create":
        template_name = arguments["template"]
        vm_name = arguments["name"]

        # Get template config
        template_config = config.templates.get_template(template_name)
        template_vmid = template_config["vmid"]

        # Get next available VM ID
        new_vmid = await proxmox.get_next_vmid()

        logger.info(f"Creating VM '{vm_name}' from template {template_name} (VMID: {new_vmid})")

        # Clone the template
        await proxmox.clone_vm(
            source_vmid=template_vmid,
            new_vmid=new_vmid,
            name=vm_name,
            description=f"ThreatSimGPT attack simulation: {vm_name}"
        )

        # Start the VM
        await proxmox.start_vm(new_vmid)

        # Wait for IP address (with timeout)
        ip_address = None
        try:
            ip_address = await proxmox.wait_for_ip(new_vmid, timeout=120)
        except Exception as e:
            logger.warning(f"Could not get IP for VM {new_vmid}: {e}")

        result = {
            "vm_id": str(new_vmid),
            "name": vm_name,
            "template": template_name,
            "ip_address": ip_address,
            "status": "running",
            "credentials": {
                "username": template_config.get("default_user"),
                "password": template_config.get("default_password")
            },
            "message": f"VM '{vm_name}' created successfully"
        }

        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]

    elif name == "vm_start":
        vm_id = int(arguments["vm_id"])

        await proxmox.start_vm(vm_id)

        # Try to get IP
        await asyncio.sleep(10)  # Give VM time to boot
        ip_address = await proxmox.get_vm_ip(vm_id)

        result = {
            "vm_id": str(vm_id),
            "status": "running",
            "ip_address": ip_address,
            "message": f"VM {vm_id} started successfully"
        }

        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]

    elif name == "vm_stop":
        vm_id = int(arguments["vm_id"])

        await proxmox.stop_vm(vm_id)

        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "status": "stopped",
                "message": f"VM {vm_id} stopped successfully"
            }, indent=2)
        )]

    elif name == "vm_destroy":
        vm_id = int(arguments["vm_id"])

        await proxmox.destroy_vm(vm_id)

        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "status": "destroyed",
                "message": f"VM {vm_id} has been permanently deleted"
            }, indent=2)
        )]

    else:
        return [TextContent(
            type="text",
            text=f"Unknown lifecycle tool: {name}"
        )]
