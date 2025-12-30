"""
MCP Tools Package

Contains tool implementations for the ThreatSimGPT VM MCP server.

Tool Categories:
    - vm_lifecycle: Create, start, stop, destroy VMs
    - vm_execute: Execute commands on VMs
    - vm_snapshot: Snapshot management
    - computer_use: GUI automation via VNC
    - attack_tools: Pre-built attack operations
"""

from .vm_lifecycle import VM_LIFECYCLE_TOOLS, handle_vm_lifecycle
from .vm_execute import VM_EXECUTE_TOOLS, handle_vm_execute
from .vm_snapshot import VM_SNAPSHOT_TOOLS, handle_vm_snapshot
from .computer_use import COMPUTER_USE_TOOLS, handle_computer_use
from .attack_tools import ATTACK_TOOLS, handle_attack_tools

# Aggregate all tools for easy import
ALL_TOOLS = []
ALL_TOOLS.extend(VM_LIFECYCLE_TOOLS)
ALL_TOOLS.extend(VM_EXECUTE_TOOLS)
ALL_TOOLS.extend(VM_SNAPSHOT_TOOLS)
ALL_TOOLS.extend(COMPUTER_USE_TOOLS)
ALL_TOOLS.extend(ATTACK_TOOLS)

__all__ = [
    # Aggregated
    "ALL_TOOLS",

    # By category
    "VM_LIFECYCLE_TOOLS",
    "VM_EXECUTE_TOOLS",
    "VM_SNAPSHOT_TOOLS",
    "COMPUTER_USE_TOOLS",
    "ATTACK_TOOLS",

    # Handlers
    "handle_vm_lifecycle",
    "handle_vm_execute",
    "handle_vm_snapshot",
    "handle_computer_use",
    "handle_attack_tools",
]
