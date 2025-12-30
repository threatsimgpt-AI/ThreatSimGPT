"""
Attack Tools

MCP tools for common offensive security operations.
Pre-built attack primitives for network scanning, enumeration,
and exploitation.
"""

import logging
from typing import Any, List

try:
    from mcp.types import Tool, TextContent
except ImportError:
    Tool = Any
    TextContent = Any

from ..providers.proxmox import ProxmoxClient
from ..config import MCPConfig
from ..safety import SafetyController
from .vm_execute import execute_ssh_command

logger = logging.getLogger(__name__)


# Tool Definitions
ATTACK_TOOLS: List[Tool] = [
    Tool(
        name="attack_nmap_scan",
        description="""Run an nmap scan from the attacker VM.

Performs network scanning and service discovery on target(s).
Results include open ports, service versions, and OS detection.

Scan types:
- quick: Fast top 100 ports (-F)
- default: Top 1000 ports
- full: All ports (-p-)
- stealth: SYN scan (-sS)
- service: Version detection (-sV)

SAFETY: Only targets in the attack network (10.0.100.0/24) are allowed.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID to run scan from"
                },
                "target": {
                    "type": "string",
                    "description": "Target IP, hostname, or CIDR range"
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "default", "full", "stealth", "service"],
                    "description": "Type of scan to perform",
                    "default": "default"
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional nmap arguments (e.g., '-sU' for UDP)"
                }
            },
            "required": ["attacker_vm_id", "target"]
        }
    ),
    Tool(
        name="attack_port_check",
        description="""Check if specific ports are open on a target.

Quick connectivity test using nc or telnet.
Returns connection status for each port.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target": {
                    "type": "string",
                    "description": "Target IP or hostname"
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of ports to check"
                }
            },
            "required": ["attacker_vm_id", "target", "ports"]
        }
    ),
    Tool(
        name="attack_gobuster",
        description="""Run gobuster for directory/file enumeration.

Discovers hidden directories and files on web servers.

Modes:
- dir: Directory enumeration (default)
- dns: DNS subdomain enumeration
- vhost: Virtual host enumeration""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_url": {
                    "type": "string",
                    "description": "Target URL (e.g., http://10.0.100.10)"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist to use (default: common.txt)",
                    "default": "/usr/share/wordlists/dirb/common.txt"
                },
                "mode": {
                    "type": "string",
                    "enum": ["dir", "dns", "vhost"],
                    "default": "dir"
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to check (e.g., 'php,html,txt')"
                }
            },
            "required": ["attacker_vm_id", "target_url"]
        }
    ),
    Tool(
        name="attack_nuclei",
        description="""Run nuclei vulnerability scanner.

Scans for known vulnerabilities using template-based detection.
Fast and comprehensive vulnerability scanning.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target": {
                    "type": "string",
                    "description": "Target URL or IP"
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Minimum severity to report",
                    "default": "medium"
                },
                "tags": {
                    "type": "string",
                    "description": "Template tags to filter (e.g., 'cve,rce')"
                }
            },
            "required": ["attacker_vm_id", "target"]
        }
    ),
    Tool(
        name="attack_hydra",
        description="""Run hydra for credential brute-forcing.

Tests login credentials against various services:
- SSH, FTP, SMB, RDP
- HTTP forms, HTTP Basic Auth
- MySQL, PostgreSQL, MSSQL

CAUTION: Only use on authorized targets.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target": {
                    "type": "string",
                    "description": "Target IP or hostname"
                },
                "service": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "smb", "rdp", "http-get", "http-post-form", "mysql", "mssql"],
                    "description": "Service to attack"
                },
                "username": {
                    "type": "string",
                    "description": "Username to try (or file path with -L)"
                },
                "password_list": {
                    "type": "string",
                    "description": "Path to password wordlist",
                    "default": "/usr/share/wordlists/rockyou.txt"
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional hydra arguments"
                }
            },
            "required": ["attacker_vm_id", "target", "service", "username"]
        }
    ),
    Tool(
        name="attack_curl",
        description="""Make HTTP request with curl.

Flexible HTTP client for web application testing.
Supports custom headers, methods, data, and authentication.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                    "default": "GET"
                },
                "headers": {
                    "type": "object",
                    "description": "HTTP headers to send"
                },
                "data": {
                    "type": "string",
                    "description": "Request body data"
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True
                }
            },
            "required": ["attacker_vm_id", "url"]
        }
    ),
]


async def handle_attack_tools(
    name: str,
    arguments: dict,
    proxmox: ProxmoxClient,
    config: MCPConfig,
    safety: SafetyController
) -> list:
    """
    Handle attack tool calls.

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

    if name == "attack_nmap_scan":
        vm_id = int(arguments["attacker_vm_id"])
        target = arguments["target"]
        scan_type = arguments.get("scan_type", "default")
        extra_args = arguments.get("extra_args", "")

        # Validate target is in allowed network
        is_allowed, reason = safety.validate_network(target)
        if not is_allowed:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Target blocked by safety controller",
                    "reason": reason,
                    "target": target
                }, indent=2)
            )]

        # Build nmap command
        nmap_args = {
            "quick": "-F -T4",
            "default": "-T4",
            "full": "-p- -T4",
            "stealth": "-sS -T4",
            "service": "-sV -T4",
        }

        args = nmap_args.get(scan_type, "-T4")
        command = f"nmap {args} {extra_args} {target}"

        # Execute on attacker VM
        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Could not get IP for VM {vm_id}"}, indent=2)
            )]

        result = await execute_ssh_command(ip_address, command, timeout=300)

        return [TextContent(
            type="text",
            text=json.dumps({
                "tool": "nmap",
                "target": target,
                "scan_type": scan_type,
                "command": command,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    elif name == "attack_port_check":
        vm_id = int(arguments["attacker_vm_id"])
        target = arguments["target"]
        ports = arguments["ports"]

        # Validate target
        is_allowed, reason = safety.validate_network(target)
        if not is_allowed:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "Target blocked", "reason": reason}, indent=2)
            )]

        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Could not get IP for VM {vm_id}"}, indent=2)
            )]

        # Check each port
        results = []
        for port in ports:
            command = f"nc -zv -w 2 {target} {port} 2>&1"
            result = await execute_ssh_command(ip_address, command, timeout=5)
            results.append({
                "port": port,
                "open": result["exit_code"] == 0,
                "output": result["stdout"] + result["stderr"]
            })

        return [TextContent(
            type="text",
            text=json.dumps({
                "target": target,
                "port_results": results
            }, indent=2)
        )]

    elif name == "attack_gobuster":
        vm_id = int(arguments["attacker_vm_id"])
        target_url = arguments["target_url"]
        wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = arguments.get("mode", "dir")
        extensions = arguments.get("extensions", "")

        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Could not get IP for VM {vm_id}"}, indent=2)
            )]

        # Build gobuster command
        ext_arg = f"-x {extensions}" if extensions else ""
        command = f"gobuster {mode} -u {target_url} -w {wordlist} {ext_arg} -q"

        result = await execute_ssh_command(ip_address, command, timeout=180)

        return [TextContent(
            type="text",
            text=json.dumps({
                "tool": "gobuster",
                "mode": mode,
                "target": target_url,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    elif name == "attack_nuclei":
        vm_id = int(arguments["attacker_vm_id"])
        target = arguments["target"]
        severity = arguments.get("severity", "medium")
        tags = arguments.get("tags", "")

        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Could not get IP for VM {vm_id}"}, indent=2)
            )]

        # Build nuclei command
        tags_arg = f"-tags {tags}" if tags else ""
        command = f"nuclei -u {target} -severity {severity},{','.join(s for s in ['high', 'critical'] if severity in ['info', 'low', 'medium'])} {tags_arg}"

        result = await execute_ssh_command(ip_address, command, timeout=300)

        return [TextContent(
            type="text",
            text=json.dumps({
                "tool": "nuclei",
                "target": target,
                "severity_filter": severity,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    elif name == "attack_hydra":
        vm_id = int(arguments["attacker_vm_id"])
        target = arguments["target"]
        service = arguments["service"]
        username = arguments["username"]
        password_list = arguments.get("password_list", "/usr/share/wordlists/rockyou.txt")
        extra_args = arguments.get("extra_args", "")

        # Validate target
        is_allowed, reason = safety.validate_network(target)
        if not is_allowed:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "Target blocked", "reason": reason}, indent=2)
            )]

        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Could not get IP for VM {vm_id}"}, indent=2)
            )]

        # Build hydra command
        command = f"hydra -l {username} -P {password_list} {target} {service} {extra_args}"

        result = await execute_ssh_command(ip_address, command, timeout=300)

        return [TextContent(
            type="text",
            text=json.dumps({
                "tool": "hydra",
                "target": target,
                "service": service,
                "username": username,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    elif name == "attack_curl":
        vm_id = int(arguments["attacker_vm_id"])
        url = arguments["url"]
        method = arguments.get("method", "GET")
        headers = arguments.get("headers", {})
        data = arguments.get("data", "")
        follow_redirects = arguments.get("follow_redirects", True)

        ip_address = await proxmox.get_vm_ip(vm_id)
        if not ip_address:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Could not get IP for VM {vm_id}"}, indent=2)
            )]

        # Build curl command
        header_args = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
        data_arg = f"-d '{data}'" if data else ""
        follow_arg = "-L" if follow_redirects else ""

        command = f"curl -s -X {method} {follow_arg} {header_args} {data_arg} '{url}'"

        result = await execute_ssh_command(ip_address, command, timeout=60)

        return [TextContent(
            type="text",
            text=json.dumps({
                "tool": "curl",
                "url": url,
                "method": method,
                "response": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"]
            }, indent=2)
        )]

    else:
        return [TextContent(
            type="text",
            text=f"Unknown attack tool: {name}"
        )]
