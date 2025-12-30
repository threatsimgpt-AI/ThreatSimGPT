"""
VM Snapshot Management Tools

MCP tools for managing VM snapshots (save/restore attack state).
"""

import logging
from typing import Any, List

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
VM_SNAPSHOT_TOOLS: List[Tool] = [
    Tool(
        name="vm_snapshot_create",
        description="""Create a snapshot of a virtual machine.

Snapshots capture the current state of a VM including:
- Disk state (all filesystem changes)
- Memory state (if vmstate=true)

Use snapshots to:
- Save state before risky operations
- Create restore points during multi-stage attacks
- Preserve evidence of successful exploits

Naming convention: Use descriptive names like:
- "pre_exploit" - Before exploitation attempt
- "post_initial_access" - After gaining initial access
- "pivot_ready" - Ready to pivot to new target""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to snapshot"
                },
                "name": {
                    "type": "string",
                    "description": "Snapshot name (alphanumeric, underscores, max 40 chars)"
                },
                "description": {
                    "type": "string",
                    "description": "Optional description of the snapshot"
                },
                "vmstate": {
                    "type": "boolean",
                    "description": "Include VM memory state (default: false)",
                    "default": False
                }
            },
            "required": ["vm_id", "name"]
        }
    ),
    Tool(
        name="vm_snapshot_restore",
        description="""Restore a VM to a previous snapshot state.

WARNING: This will stop the VM and restore all data to the snapshot point.
Any changes made after the snapshot will be lost.

Use this to:
- Revert failed exploitation attempts
- Reset target VMs between tests
- Return to known good states""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to restore"
                },
                "snapshot_name": {
                    "type": "string",
                    "description": "Name of snapshot to restore"
                },
                "start_after": {
                    "type": "boolean",
                    "description": "Start VM after restore (default: true)",
                    "default": True
                }
            },
            "required": ["vm_id", "snapshot_name"]
        }
    ),
    Tool(
        name="vm_snapshot_list",
        description="""List all snapshots for a virtual machine.

Returns snapshot names, descriptions, and timestamps.""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to list snapshots for"
                }
            },
            "required": ["vm_id"]
        }
    ),
    Tool(
        name="vm_snapshot_delete",
        description="""Delete a snapshot from a virtual machine.

This frees up storage space but removes the ability to restore to that point.""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID"
                },
                "snapshot_name": {
                    "type": "string",
                    "description": "Name of snapshot to delete"
                }
            },
            "required": ["vm_id", "snapshot_name"]
        }
    ),
]


async def handle_vm_snapshot(
    name: str,
    arguments: dict,
    proxmox: ProxmoxClient,
    config: MCPConfig,
    safety: SafetyController
) -> list:
    """
    Handle VM snapshot tool calls.

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
    import re

    if name == "vm_snapshot_create":
        vm_id = int(arguments["vm_id"])
        snap_name = arguments["name"]
        description = arguments.get("description", "")
        vmstate = arguments.get("vmstate", False)

        # Validate snapshot name
        if not re.match(r'^[a-zA-Z0-9_-]{1,40}$', snap_name):
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Invalid snapshot name",
                    "hint": "Use alphanumeric characters, underscores, hyphens. Max 40 chars."
                }, indent=2)
            )]

        logger.info(f"Creating snapshot '{snap_name}' for VM {vm_id}")

        result = await proxmox.create_snapshot(
            vm_id=vm_id,
            name=snap_name,
            description=description,
            vmstate=vmstate
        )

        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "vm_id": str(vm_id),
                "snapshot_name": snap_name,
                "description": description,
                "vmstate": vmstate,
                "message": f"Snapshot '{snap_name}' created successfully"
            }, indent=2)
        )]

    elif name == "vm_snapshot_restore":
        vm_id = int(arguments["vm_id"])
        snapshot_name = arguments["snapshot_name"]
        start_after = arguments.get("start_after", True)

        logger.info(f"Restoring VM {vm_id} to snapshot '{snapshot_name}'")

        # First, stop the VM if running
        status = await proxmox.get_vm_status(vm_id)
        if status.get("status") == "running":
            await proxmox.stop_vm(vm_id)
            # Wait for VM to stop
            import asyncio
            for _ in range(30):
                await asyncio.sleep(1)
                status = await proxmox.get_vm_status(vm_id)
                if status.get("status") == "stopped":
                    break

        # Restore snapshot
        result = await proxmox.restore_snapshot(
            vm_id=vm_id,
            snapshot_name=snapshot_name
        )

        # Start VM if requested
        if start_after:
            await proxmox.start_vm(vm_id)

        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "vm_id": str(vm_id),
                "snapshot_name": snapshot_name,
                "started": start_after,
                "message": f"VM {vm_id} restored to '{snapshot_name}'"
            }, indent=2)
        )]

    elif name == "vm_snapshot_list":
        vm_id = int(arguments["vm_id"])

        logger.info(f"Listing snapshots for VM {vm_id}")

        snapshots = await proxmox.list_snapshots(vm_id)

        # Format snapshot info
        formatted = []
        for snap in snapshots:
            if snap.get("name") == "current":
                continue  # Skip the "current" pseudo-snapshot
            formatted.append({
                "name": snap.get("name"),
                "description": snap.get("description", ""),
                "timestamp": snap.get("snaptime"),
                "vmstate": snap.get("vmstate", False)
            })

        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "snapshot_count": len(formatted),
                "snapshots": formatted
            }, indent=2)
        )]

    elif name == "vm_snapshot_delete":
        vm_id = int(arguments["vm_id"])
        snapshot_name = arguments["snapshot_name"]

        # Safety check - prevent deleting certain snapshots
        protected_names = ["base", "clean", "pristine", "factory"]
        if snapshot_name.lower() in protected_names:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Cannot delete protected snapshot",
                    "snapshot_name": snapshot_name,
                    "hint": f"Snapshots named {protected_names} are protected"
                }, indent=2)
            )]

        logger.info(f"Deleting snapshot '{snapshot_name}' from VM {vm_id}")

        result = await proxmox.delete_snapshot(
            vm_id=vm_id,
            snapshot_name=snapshot_name
        )

        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "vm_id": str(vm_id),
                "snapshot_name": snapshot_name,
                "message": f"Snapshot '{snapshot_name}' deleted"
            }, indent=2)
        )]

    else:
        return [TextContent(
            type="text",
            text=f"Unknown snapshot tool: {name}"
        )]
