"""
ThreatSimGPT MCP Server Package

Provides Model Context Protocol (MCP) integration for AI-controlled
attack simulations on virtual machines.

This is the PRIMARY implementation approach for ThreatSimGPT VM operations,
providing a standardized interface that works with any MCP-compatible
AI model (Claude, GPT-4, Llama, etc.).

Key Components:
    - MCPConfig: Configuration for MCP server and Proxmox connection
    - ProxmoxClient: Async client for Proxmox VE API
    - SafetyController: Validates operations for safety
    - create_server: Factory function to create MCP server
    - run_server: Entry point to run the MCP server

Example Usage:
    # Run as standalone server
    python -m threatsimgpt.mcp.server

    # Or programmatically
    from threatsimgpt.mcp import create_server, MCPConfig

    config = MCPConfig.from_env()
    server = create_server(config)

MCP Tools Provided:
    - vm_create: Create VM from template
    - vm_start/vm_stop/vm_destroy: VM lifecycle
    - vm_execute: Run commands via SSH
    - vm_screenshot: Capture VM display
    - vm_snapshot_*: Snapshot management
    - attack_*: Pre-built attack tools
"""

__version__ = "0.1.0"

from .config import MCPConfig, ProxmoxConfig, NetworkConfig, SafetyConfig, TemplateConfig
from .server import ThreatSimGPTMCPServer, run_server, main
from .providers.proxmox import ProxmoxClient
from .safety import SafetyController

__all__ = [
    # Server
    "ThreatSimGPTMCPServer",
    "run_server",
    "main",

    # Configuration
    "MCPConfig",
    "ProxmoxConfig",
    "NetworkConfig",
    "SafetyConfig",
    "TemplateConfig",

    # Providers
    "ProxmoxClient",

    # Safety
    "SafetyController",

    # Version
    "__version__",
]
