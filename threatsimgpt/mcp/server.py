"""
ThreatSimGPT VM MCP Server

Model Context Protocol server for AI-driven VM attack simulations.
Provides tools for VM lifecycle, command execution, and snapshot management.
"""

import asyncio
import logging
import os
import signal
from typing import Any, Callable, Dict, List, Optional

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    Server = None
    stdio_server = None
    Tool = Any
    TextContent = Any

from .config import MCPConfig, ProxmoxConfig, SafetyConfig, NetworkConfig
from .providers.proxmox import ProxmoxClient
from .safety import SafetyController
from .tools.vm_lifecycle import VM_LIFECYCLE_TOOLS, handle_vm_lifecycle
from .tools.vm_execute import VM_EXECUTE_TOOLS, handle_vm_execute
from .tools.vm_snapshot import VM_SNAPSHOT_TOOLS, handle_vm_snapshot
from .tools.computer_use import COMPUTER_USE_TOOLS, handle_computer_use
from .tools.attack_tools import ATTACK_TOOLS, handle_attack_tools

logger = logging.getLogger(__name__)


class ThreatSimGPTMCPServer:
    """
    Main MCP server for ThreatSimGPT VM operations.

    Provides:
    - VM lifecycle management (create, start, stop, destroy)
    - Command execution via SSH
    - Snapshot management for state preservation
    - Safety controls and audit logging
    """

    def __init__(
        self,
        config: Optional[MCPConfig] = None,
        proxmox_config: Optional[ProxmoxConfig] = None,
        safety_config: Optional[SafetyConfig] = None
    ):
        """
        Initialize the MCP server.

        Args:
            config: Server configuration
            proxmox_config: Proxmox VE connection settings
            safety_config: Safety and validation settings
        """
        self.config = config or MCPConfig()
        self.proxmox_config = proxmox_config or self.config.proxmox
        self.safety_config = safety_config or self.config.safety

        # Initialize components
        self.proxmox: Optional[ProxmoxClient] = None
        self.safety = SafetyController(self.safety_config)
        self.server: Optional[Server] = None

        # Collect all tools
        self.tools: List[Tool] = []
        self.tools.extend(VM_LIFECYCLE_TOOLS)
        self.tools.extend(VM_EXECUTE_TOOLS)
        self.tools.extend(VM_SNAPSHOT_TOOLS)
        self.tools.extend(COMPUTER_USE_TOOLS)
        self.tools.extend(ATTACK_TOOLS)

        # Track active simulations
        self.active_vms: Dict[int, dict] = {}

        logger.info(
            f"ThreatSimGPT MCP Server initialized: "
            f"{len(self.tools)} tools registered"
        )

    async def connect_proxmox(self) -> bool:
        """
        Connect to Proxmox VE.

        Returns:
            True if connected successfully
        """
        try:
            self.proxmox = ProxmoxClient(self.proxmox_config)
            await self.proxmox.connect()

            # Verify connection
            version = await self.proxmox.get_version()
            logger.info(f"Connected to Proxmox VE {version}")

            return True

        except Exception as e:
            logger.error(f"Failed to connect to Proxmox: {e}")
            return False

    async def disconnect(self):
        """Cleanup and disconnect."""
        if self.proxmox:
            await self.proxmox.disconnect()
            self.proxmox = None

        logger.info("MCP server disconnected")

    def get_tools(self) -> List[Tool]:
        """Return all registered tools."""
        return self.tools

    async def handle_tool_call(
        self,
        name: str,
        arguments: dict
    ) -> List[TextContent]:
        """
        Handle incoming tool calls.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            List of TextContent responses
        """
        import json

        # Ensure Proxmox is connected
        if self.proxmox is None:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Proxmox not connected",
                    "hint": "Server may still be initializing"
                }, indent=2)
            )]

        # Route to appropriate handler
        try:
            # VM Lifecycle tools
            if name in ["vm_create", "vm_start", "vm_stop", "vm_destroy", "vm_list", "vm_status"]:
                return await handle_vm_lifecycle(
                    name, arguments, self.proxmox, self.config, self.safety
                )

            # Command execution tools
            elif name in ["vm_execute", "vm_execute_script"]:
                return await handle_vm_execute(
                    name, arguments, self.proxmox, self.config, self.safety
                )

            # Snapshot tools
            elif name in ["vm_snapshot_create", "vm_snapshot_restore",
                         "vm_snapshot_list", "vm_snapshot_delete"]:
                return await handle_vm_snapshot(
                    name, arguments, self.proxmox, self.config, self.safety
                )

            # Computer Use tools (GUI automation)
            elif name in ["vm_screenshot", "vm_mouse_click", "vm_keyboard_type",
                         "vm_keyboard_key", "vm_wait_for_screen"]:
                return await handle_computer_use(
                    name, arguments, self.proxmox, self.config, self.safety
                )

            # Attack tools
            elif name in ["attack_nmap_scan", "attack_port_check", "attack_gobuster",
                         "attack_nuclei", "attack_hydra", "attack_curl"]:
                return await handle_attack_tools(
                    name, arguments, self.proxmox, self.config, self.safety
                )

            else:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "error": f"Unknown tool: {name}",
                        "available_tools": [t.name for t in self.tools]
                    }, indent=2)
                )]

        except Exception as e:
            logger.exception(f"Error handling tool {name}: {e}")
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": str(e),
                    "tool": name,
                    "arguments": arguments
                }, indent=2)
            )]

    async def run(self):
        """
        Start the MCP server.

        Runs the server using stdio transport for MCP communication.
        """
        if not MCP_AVAILABLE:
            raise RuntimeError(
                "MCP SDK not installed. Install with: pip install mcp"
            )

        # Create MCP server
        self.server = Server(self.config.name)

        # Register tool list handler
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return self.get_tools()

        # Register tool call handler
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> List[TextContent]:
            return await self.handle_tool_call(name, arguments)

        # Connect to Proxmox
        connected = await self.connect_proxmox()
        if not connected:
            logger.warning("Starting server without Proxmox connection")

        # Run server
        logger.info("Starting ThreatSimGPT MCP Server on stdio...")

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def run_server(
    config_path: Optional[str] = None,
    log_level: str = "INFO"
):
    """
    Entry point to run the MCP server.

    Args:
        config_path: Optional path to configuration file
        log_level: Logging level
    """
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Load configuration
    if config_path:
        config = MCPConfig.from_file(config_path)
    else:
        # Load from environment variables
        config = MCPConfig.from_env()

    # Create and run server
    server = ThreatSimGPTMCPServer(config=config)

    # Handle shutdown gracefully
    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("Shutdown signal received")
        asyncio.create_task(server.disconnect())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    try:
        await server.run()
    finally:
        await server.disconnect()


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="ThreatSimGPT VM MCP Server"
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )

    args = parser.parse_args()

    asyncio.run(run_server(
        config_path=args.config,
        log_level=args.log_level
    ))


if __name__ == "__main__":
    main()
