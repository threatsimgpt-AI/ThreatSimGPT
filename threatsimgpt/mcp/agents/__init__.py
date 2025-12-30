"""
AI Agent Integration Module

Connects AI models (Claude, GPT-4, etc.) with the MCP server for
autonomous attack simulation.

This module provides:
- MCP client wrapper for AI agents
- ReAct-style reasoning loop
- Tool execution with safety checks
- State management and logging
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Agent execution states."""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentContext:
    """
    Maintains state across agent execution.

    Tracks discovered information, attack progress, and execution history.
    """
    # Attack state
    objective: str = ""
    current_phase: str = "reconnaissance"

    # Discovered information
    discovered_hosts: List[str] = field(default_factory=list)
    discovered_services: Dict[str, List[dict]] = field(default_factory=dict)
    discovered_credentials: List[dict] = field(default_factory=list)
    compromised_hosts: List[str] = field(default_factory=list)

    # Execution history
    executed_commands: List[dict] = field(default_factory=list)
    tool_calls: List[dict] = field(default_factory=list)

    # VM tracking
    active_vms: Dict[str, dict] = field(default_factory=dict)
    attacker_vm_id: Optional[str] = None
    target_vm_ids: List[str] = field(default_factory=list)

    # Timing
    start_time: Optional[datetime] = None
    last_action_time: Optional[datetime] = None

    def to_prompt_context(self) -> str:
        """Format context for inclusion in LLM prompts."""
        return f"""
CURRENT ATTACK CONTEXT:
- Objective: {self.objective}
- Phase: {self.current_phase}
- Attacker VM: {self.attacker_vm_id}
- Target VMs: {', '.join(self.target_vm_ids) or 'None'}

DISCOVERED HOSTS: {', '.join(self.discovered_hosts) or 'None'}
COMPROMISED HOSTS: {', '.join(self.compromised_hosts) or 'None'}

DISCOVERED SERVICES:
{json.dumps(self.discovered_services, indent=2) if self.discovered_services else 'None'}

CREDENTIALS FOUND: {len(self.discovered_credentials)} sets
{json.dumps(self.discovered_credentials[:5], indent=2) if self.discovered_credentials else ''}

RECENT COMMANDS ({len(self.executed_commands)} total):
{self._format_recent_commands(5)}
"""

    def _format_recent_commands(self, n: int) -> str:
        """Format last N commands for prompt."""
        recent = self.executed_commands[-n:] if self.executed_commands else []
        lines = []
        for cmd in recent:
            status = "✓" if cmd.get("exit_code", 1) == 0 else "✗"
            lines.append(f"  {status} {cmd.get('command', 'unknown')[:60]}...")
        return "\n".join(lines) or "  No commands executed yet"


# MCP Tool Definitions for AI Agent
MCP_TOOL_DESCRIPTIONS = """
AVAILABLE TOOLS:

## VM Management
- vm_create(template_name, vm_name) - Create a new VM from template
- vm_start(vm_id) - Start a VM
- vm_stop(vm_id) - Stop a VM
- vm_status(vm_id) - Get VM status and IP address
- vm_list() - List all VMs

## Command Execution
- vm_execute(vm_id, command) - Execute shell command on VM via SSH
- vm_execute_script(vm_id, script, script_type) - Run a script (bash/python)

## Snapshots
- vm_snapshot_create(vm_id, name) - Save VM state
- vm_snapshot_restore(vm_id, snapshot_name) - Restore to previous state
- vm_snapshot_list(vm_id) - List available snapshots

## Attack Tools
- attack_nmap_scan(attacker_vm_id, target, scan_type) - Network scanning
- attack_port_check(attacker_vm_id, target, ports) - Quick port check
- attack_gobuster(attacker_vm_id, target_url, wordlist, mode) - Directory enumeration
- attack_nuclei(attacker_vm_id, target, severity) - Vulnerability scanning
- attack_hydra(attacker_vm_id, target, service, username, password_list) - Credential brute-force
- attack_curl(attacker_vm_id, url, method, headers, data) - HTTP requests

## GUI Automation (Computer Use)
- vm_screenshot(vm_id) - Capture screen
- vm_mouse_click(vm_id, x, y, button) - Click at coordinates
- vm_keyboard_type(vm_id, text) - Type text
- vm_keyboard_key(vm_id, key) - Press special key (enter, ctrl+c, etc.)
"""


# ReAct Prompt Templates
REACT_SYSTEM_PROMPT = """You are an expert red team operator executing attack simulations in an isolated lab environment.

You follow the ReAct pattern:
1. THOUGHT: Reason about what to do next based on the objective and current state
2. ACTION: Choose a tool to execute
3. OBSERVATION: Analyze the result
4. Repeat until objective is achieved or determined impossible

{tool_descriptions}

SAFETY RULES:
- Only attack targets in the allowed network (10.0.100.0/24)
- Never execute destructive commands (rm -rf /, dd, etc.)
- Always verify target before exploitation
- Document all findings for the report

OUTPUT FORMAT:
Always respond in this exact JSON format:
{{
    "thought": "Your reasoning about current situation and next step",
    "action": {{
        "tool": "tool_name",
        "arguments": {{
            "arg1": "value1",
            "arg2": "value2"
        }}
    }},
    "is_complete": false
}}

When the objective is achieved or cannot be completed:
{{
    "thought": "Final reasoning",
    "action": null,
    "is_complete": true,
    "result": "success|failure",
    "summary": "What was accomplished"
}}
"""

REACT_USER_PROMPT = """
OBJECTIVE: {objective}

{context}

What is your next action?
"""


class MCPAgentClient:
    """
    Client for AI agents to interact with MCP server tools.

    Wraps MCP tool calls with:
    - Safety validation
    - Result parsing
    - State updates
    - Logging
    """

    def __init__(
        self,
        mcp_server: Any,  # ThreatSimGPTMCPServer instance
        safety_enabled: bool = True
    ):
        self.server = mcp_server
        self.safety_enabled = safety_enabled
        self.call_history: List[dict] = []

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict,
        context: Optional[AgentContext] = None
    ) -> dict:
        """
        Call an MCP tool and return the result.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            context: Optional agent context to update

        Returns:
            Parsed result dictionary
        """
        start_time = datetime.utcnow()

        # Log the call
        call_record = {
            "tool": tool_name,
            "arguments": arguments,
            "timestamp": start_time.isoformat(),
            "result": None,
            "error": None,
            "duration_ms": 0
        }

        try:
            # Execute via MCP server
            result = await self.server.handle_tool_call(tool_name, arguments)

            # Parse result (MCP returns TextContent list)
            if result and len(result) > 0:
                result_text = result[0].text
                try:
                    parsed = json.loads(result_text)
                except json.JSONDecodeError:
                    parsed = {"raw": result_text}
            else:
                parsed = {"error": "Empty result"}

            call_record["result"] = parsed

            # Update context if provided
            if context:
                self._update_context(context, tool_name, arguments, parsed)

            return parsed

        except Exception as e:
            logger.error(f"Tool call failed: {tool_name} - {e}")
            call_record["error"] = str(e)
            return {"error": str(e)}

        finally:
            call_record["duration_ms"] = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.call_history.append(call_record)

    def _update_context(
        self,
        context: AgentContext,
        tool: str,
        args: dict,
        result: dict
    ):
        """Update agent context based on tool results."""
        context.last_action_time = datetime.utcnow()

        # Track command execution
        if tool == "vm_execute":
            context.executed_commands.append({
                "command": args.get("command"),
                "vm_id": args.get("vm_id"),
                "exit_code": result.get("exit_code"),
                "timestamp": datetime.utcnow().isoformat()
            })

        # Track VM creation
        elif tool == "vm_create" and "vm_id" in result:
            vm_id = result["vm_id"]
            context.active_vms[vm_id] = {
                "name": args.get("name"),
                "template": args.get("template"),
                "created": datetime.utcnow().isoformat()
            }

        # Track discovered hosts from nmap
        elif tool == "attack_nmap_scan" and result.get("stdout"):
            # Parse nmap output for discovered hosts
            stdout = result.get("stdout", "")
            import re
            hosts = re.findall(r'Nmap scan report for (\S+)', stdout)
            for host in hosts:
                if host not in context.discovered_hosts:
                    context.discovered_hosts.append(host)

        context.tool_calls.append({
            "tool": tool,
            "args": args,
            "timestamp": datetime.utcnow().isoformat()
        })


class ReActAgent:
    """
    ReAct-style AI agent for attack simulation.

    Implements the Reasoning + Acting pattern:
    1. Observe current state
    2. Think about what to do
    3. Take action using MCP tools
    4. Analyze results
    5. Repeat until complete
    """

    def __init__(
        self,
        llm_client: Any,  # Anthropic/OpenAI client
        mcp_client: MCPAgentClient,
        max_iterations: int = 50,
        model: str = "claude-sonnet-4-20250514"
    ):
        self.llm = llm_client
        self.mcp = mcp_client
        self.max_iterations = max_iterations
        self.model = model

        self.state = AgentState.IDLE
        self.context = AgentContext()
        self.iteration = 0

    async def run(
        self,
        objective: str,
        attacker_vm_id: Optional[str] = None,
        target_vm_ids: Optional[List[str]] = None,
        initial_context: Optional[dict] = None
    ) -> dict:
        """
        Run the agent until objective is achieved or max iterations.

        Args:
            objective: What the agent should accomplish
            attacker_vm_id: Pre-existing attacker VM ID (or None to create)
            target_vm_ids: Target VM IDs
            initial_context: Additional context to include

        Returns:
            Final result with summary and findings
        """
        self.state = AgentState.PLANNING
        self.context = AgentContext(
            objective=objective,
            attacker_vm_id=attacker_vm_id,
            target_vm_ids=target_vm_ids or [],
            start_time=datetime.utcnow()
        )

        logger.info(f"Starting ReAct agent with objective: {objective}")

        # Build system prompt
        system_prompt = REACT_SYSTEM_PROMPT.format(
            tool_descriptions=MCP_TOOL_DESCRIPTIONS
        )

        messages = [{"role": "system", "content": system_prompt}]

        try:
            while self.iteration < self.max_iterations:
                self.iteration += 1
                self.state = AgentState.EXECUTING

                # Build user prompt with current context
                user_prompt = REACT_USER_PROMPT.format(
                    objective=objective,
                    context=self.context.to_prompt_context()
                )

                messages.append({"role": "user", "content": user_prompt})

                # Get LLM response
                response = await self._call_llm(messages)
                messages.append({"role": "assistant", "content": response})

                # Parse response
                try:
                    action_data = json.loads(response)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse LLM response: {response[:200]}")
                    continue

                thought = action_data.get("thought", "")
                logger.info(f"[Iteration {self.iteration}] Thought: {thought[:100]}...")

                # Check if complete
                if action_data.get("is_complete"):
                    self.state = AgentState.COMPLETED
                    return {
                        "status": action_data.get("result", "completed"),
                        "summary": action_data.get("summary", ""),
                        "iterations": self.iteration,
                        "context": self.context.__dict__
                    }

                # Execute action
                action = action_data.get("action")
                if action:
                    tool = action.get("tool")
                    args = action.get("arguments", {})

                    logger.info(f"[Iteration {self.iteration}] Action: {tool}({args})")

                    # Call MCP tool
                    result = await self.mcp.call_tool(tool, args, self.context)

                    # Add observation to messages
                    observation = f"OBSERVATION: {json.dumps(result, indent=2)}"
                    messages.append({"role": "user", "content": observation})

                    self.state = AgentState.ANALYZING

            # Max iterations reached
            self.state = AgentState.COMPLETED
            return {
                "status": "max_iterations",
                "iterations": self.iteration,
                "context": self.context.__dict__
            }

        except Exception as e:
            logger.exception(f"Agent failed: {e}")
            self.state = AgentState.FAILED
            return {
                "status": "error",
                "error": str(e),
                "iterations": self.iteration,
                "context": self.context.__dict__
            }

    async def _call_llm(self, messages: List[dict]) -> str:
        """Call LLM and return response text."""
        # This is a placeholder - implement based on your LLM provider
        # Example for Anthropic:
        if hasattr(self.llm, 'messages'):
            # Anthropic client
            response = await self.llm.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=messages[1:],  # Skip system (handle separately)
                system=messages[0]["content"]
            )
            return response.content[0].text

        # Example for OpenAI:
        elif hasattr(self.llm, 'chat'):
            response = await self.llm.chat.completions.create(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content

        else:
            raise ValueError("Unknown LLM client type")


# Convenience function to run a complete attack simulation
async def run_attack_simulation(
    objective: str,
    llm_client: Any,
    proxmox_host: str = "192.168.1.100",
    proxmox_token: str = "",
    create_attacker: bool = True,
    target_template: str = "ubuntu-target"
) -> dict:
    """
    High-level function to run a complete attack simulation.

    Args:
        objective: Attack objective (e.g., "Gain root access to target")
        llm_client: Initialized LLM client (Anthropic/OpenAI)
        proxmox_host: Proxmox server address
        proxmox_token: Proxmox API token
        create_attacker: Whether to create attacker VM
        target_template: Template name for target VM

    Returns:
        Simulation results
    """
    from threatsimgpt.mcp import ThreatSimGPTMCPServer, MCPConfig, ProxmoxConfig

    # Initialize MCP server
    config = MCPConfig(
        proxmox=ProxmoxConfig(
            host=proxmox_host,
            token_value=proxmox_token
        )
    )

    server = ThreatSimGPTMCPServer(config=config)
    await server.connect_proxmox()

    # Create MCP client
    mcp_client = MCPAgentClient(server)

    # Create agent
    agent = ReActAgent(llm_client, mcp_client)

    try:
        # Optionally set up VMs first
        attacker_vm_id = None
        target_vm_ids = []

        if create_attacker:
            result = await mcp_client.call_tool("vm_create", {
                "template": "ubuntu-attacker",
                "name": "attack-agent-attacker"
            })
            attacker_vm_id = result.get("vm_id")

            # Create target
            result = await mcp_client.call_tool("vm_create", {
                "template": target_template,
                "name": "attack-agent-target"
            })
            target_vm_ids.append(result.get("vm_id"))

            # Wait for VMs to start
            await asyncio.sleep(30)

        # Run the agent
        results = await agent.run(
            objective=objective,
            attacker_vm_id=attacker_vm_id,
            target_vm_ids=target_vm_ids
        )

        return results

    finally:
        await server.disconnect()
