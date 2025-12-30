"""
Computer Use Tools

MCP tools for GUI automation via VNC/screenshot analysis.
Enables AI agents to interact with graphical applications.
"""

import base64
import logging
from typing import Any, List, Optional

try:
    from mcp.types import Tool, TextContent
except ImportError:
    Tool = Any
    TextContent = Any

from ..providers.proxmox import ProxmoxClient
from ..config import MCPConfig
from ..safety import SafetyController

logger = logging.getLogger(__name__)


# Tool Definitions
COMPUTER_USE_TOOLS: List[Tool] = [
    Tool(
        name="vm_screenshot",
        description="""Capture a screenshot of a VM's display.

Returns a base64-encoded PNG image of the VM's current screen.
Use this to see what's on the screen before interacting with GUI elements.

Common use cases:
- Check if login prompt is displayed
- Verify application state
- Find GUI elements to click
- Debug GUI automation issues""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "VM ID to capture"
                }
            },
            "required": ["vm_id"]
        }
    ),
    Tool(
        name="vm_mouse_click",
        description="""Click at specific coordinates on a VM's display.

Sends a mouse click event to the VM at the specified x,y coordinates.
Use vm_screenshot first to determine correct coordinates.

Coordinate system: (0,0) is top-left corner.""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "Target VM ID"
                },
                "x": {
                    "type": "integer",
                    "description": "X coordinate (pixels from left)"
                },
                "y": {
                    "type": "integer",
                    "description": "Y coordinate (pixels from top)"
                },
                "button": {
                    "type": "string",
                    "enum": ["left", "right", "middle"],
                    "description": "Mouse button to click",
                    "default": "left"
                },
                "double_click": {
                    "type": "boolean",
                    "description": "Whether to double-click",
                    "default": False
                }
            },
            "required": ["vm_id", "x", "y"]
        }
    ),
    Tool(
        name="vm_keyboard_type",
        description="""Type text into a VM's display.

Sends keyboard input to the VM as if typing on a keyboard.
Use for entering text into focused input fields.

The text will be typed character by character.
For special keys, use vm_keyboard_key instead.""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "Target VM ID"
                },
                "text": {
                    "type": "string",
                    "description": "Text to type"
                },
                "delay_ms": {
                    "type": "integer",
                    "description": "Delay between keystrokes in milliseconds",
                    "default": 50
                }
            },
            "required": ["vm_id", "text"]
        }
    ),
    Tool(
        name="vm_keyboard_key",
        description="""Send a special key press to a VM.

Use for keys that aren't regular characters:
- Enter, Tab, Escape, Backspace, Delete
- Arrow keys: Up, Down, Left, Right
- Function keys: F1-F12
- Modifiers: ctrl-c, alt-f4, ctrl-alt-delete

Key combinations use + separator: ctrl+c, alt+tab, ctrl+shift+esc""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "Target VM ID"
                },
                "key": {
                    "type": "string",
                    "description": "Key or key combination to send (e.g., 'enter', 'ctrl+c', 'alt+f4')"
                }
            },
            "required": ["vm_id", "key"]
        }
    ),
    Tool(
        name="vm_wait_for_screen",
        description="""Wait for a specific visual element or text on screen.

Continuously captures screenshots until:
- The expected text/element appears
- The timeout is reached

Useful for waiting for:
- Login prompt to appear
- Application to load
- Dialog box to open""",
        inputSchema={
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "string",
                    "description": "Target VM ID"
                },
                "wait_for": {
                    "type": "string",
                    "description": "Text or description of element to wait for"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Maximum seconds to wait",
                    "default": 30
                },
                "interval": {
                    "type": "number",
                    "description": "Seconds between screenshot checks",
                    "default": 1.0
                }
            },
            "required": ["vm_id", "wait_for"]
        }
    ),
]


# Key code mapping for special keys
KEY_CODES = {
    # Navigation
    "enter": "ret",
    "return": "ret",
    "tab": "tab",
    "escape": "esc",
    "esc": "esc",
    "backspace": "backspace",
    "delete": "delete",
    "del": "delete",
    "space": "spc",

    # Arrow keys
    "up": "up",
    "down": "down",
    "left": "left",
    "right": "right",

    # Function keys
    "f1": "f1", "f2": "f2", "f3": "f3", "f4": "f4",
    "f5": "f5", "f6": "f6", "f7": "f7", "f8": "f8",
    "f9": "f9", "f10": "f10", "f11": "f11", "f12": "f12",

    # Modifiers
    "ctrl": "ctrl",
    "alt": "alt",
    "shift": "shift",
    "win": "meta_l",
    "super": "meta_l",
    "meta": "meta_l",
}


async def handle_computer_use(
    name: str,
    arguments: dict,
    proxmox: ProxmoxClient,
    config: MCPConfig,
    safety: SafetyController
) -> list:
    """
    Handle Computer Use tool calls.

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
    import asyncio

    if name == "vm_screenshot":
        vm_id = int(arguments["vm_id"])

        logger.info(f"Capturing screenshot for VM {vm_id}")

        # Capture screenshot from VNC
        screenshot_data = await proxmox.capture_screenshot(vm_id)

        if screenshot_data is None:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Failed to capture screenshot for VM {vm_id}",
                    "hint": "Ensure VM is running and VNC is enabled"
                }, indent=2)
            )]

        # Return base64-encoded image
        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "format": "png",
                "encoding": "base64",
                "data": screenshot_data,
                "hint": "Use this screenshot to identify GUI elements and their coordinates"
            }, indent=2)
        )]

    elif name == "vm_mouse_click":
        vm_id = int(arguments["vm_id"])
        x = arguments["x"]
        y = arguments["y"]
        button = arguments.get("button", "left")
        double_click = arguments.get("double_click", False)

        logger.info(f"Mouse click on VM {vm_id} at ({x}, {y}), button={button}")

        # Map button names
        button_map = {"left": 0, "middle": 1, "right": 2}
        button_num = button_map.get(button, 0)

        # Send click via QEMU monitor
        # First move mouse to position
        await proxmox.send_qemu_command(
            vm_id,
            f"mouse_move {x} {y}"
        )

        # Then click
        await proxmox.send_qemu_command(
            vm_id,
            f"mouse_button {1 << button_num}"  # Button down
        )
        await asyncio.sleep(0.05)
        await proxmox.send_qemu_command(
            vm_id,
            "mouse_button 0"  # Button up
        )

        # Double click if requested
        if double_click:
            await asyncio.sleep(0.1)
            await proxmox.send_qemu_command(
                vm_id,
                f"mouse_button {1 << button_num}"
            )
            await asyncio.sleep(0.05)
            await proxmox.send_qemu_command(
                vm_id,
                "mouse_button 0"
            )

        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "vm_id": str(vm_id),
                "x": x,
                "y": y,
                "button": button,
                "double_click": double_click
            }, indent=2)
        )]

    elif name == "vm_keyboard_type":
        vm_id = int(arguments["vm_id"])
        text = arguments["text"]
        delay_ms = arguments.get("delay_ms", 50)

        logger.info(f"Typing text on VM {vm_id}: '{text[:20]}...'")

        # Send each character
        for char in text:
            await proxmox.send_key(vm_id, char)
            await asyncio.sleep(delay_ms / 1000)

        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "vm_id": str(vm_id),
                "characters_typed": len(text)
            }, indent=2)
        )]

    elif name == "vm_keyboard_key":
        vm_id = int(arguments["vm_id"])
        key = arguments["key"].lower()

        logger.info(f"Sending key to VM {vm_id}: {key}")

        # Parse key combination
        parts = key.split("+")
        keys_to_send = []

        for part in parts:
            part = part.strip()
            if part in KEY_CODES:
                keys_to_send.append(KEY_CODES[part])
            else:
                # Single character key
                keys_to_send.append(part)

        # Build QEMU key string (modifiers held together)
        if len(keys_to_send) > 1:
            qemu_key = "-".join(keys_to_send)
        else:
            qemu_key = keys_to_send[0]

        await proxmox.send_qemu_command(vm_id, f"sendkey {qemu_key}")

        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "vm_id": str(vm_id),
                "key": key,
                "qemu_key": qemu_key
            }, indent=2)
        )]

    elif name == "vm_wait_for_screen":
        vm_id = int(arguments["vm_id"])
        wait_for = arguments["wait_for"]
        timeout = arguments.get("timeout", 30)
        interval = arguments.get("interval", 1.0)

        logger.info(f"Waiting for '{wait_for}' on VM {vm_id}, timeout={timeout}s")

        # Note: Full implementation would use OCR to detect text on screen
        # For now, just capture screenshots and return them for AI analysis

        start_time = asyncio.get_event_loop().time()
        attempts = 0
        last_screenshot = None

        while (asyncio.get_event_loop().time() - start_time) < timeout:
            attempts += 1

            # Capture screenshot
            screenshot_data = await proxmox.capture_screenshot(vm_id)
            if screenshot_data:
                last_screenshot = screenshot_data

            await asyncio.sleep(interval)

        return [TextContent(
            type="text",
            text=json.dumps({
                "vm_id": str(vm_id),
                "wait_for": wait_for,
                "timeout_reached": True,
                "attempts": attempts,
                "last_screenshot": last_screenshot,
                "hint": "Screenshot captured after timeout. Analyze to check if expected element appeared."
            }, indent=2)
        )]

    else:
        return [TextContent(
            type="text",
            text=f"Unknown computer use tool: {name}"
        )]
