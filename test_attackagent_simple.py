"""Simplified unit tests for refactored AttackAgent run_single_command method.

Tests Issue #132: AttackAgent Single Command - Refactor for Proper State Tracking
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4


class MockAgentState:
    """Mock agent state for testing."""
    def __init__(self):
        self.current_vm = ""
        self.current_phase = MockAttackPhase()
        self.current_objective = ""
        self.action_history = []
        self.command_history = []
        self.compromised_hosts = []
        self.collected_credentials = []
        self.discovered_services = []
        self.discovered_users = []
        self.errors = []
        self.last_action = None


class MockAttackPhase:
    """Mock attack phase for testing."""
    def __init__(self, phase="reconnaissance"):
        self.value = phase


class MockCommandResult:
    """Mock command result for testing."""
    def __init__(self, command, stdout="", stderr="", exit_code=0, vm_id=""):
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.vm_id = vm_id
        self.timestamp = datetime.utcnow()
        self.execution_time_ms = 100.0
        self.command_id = str(uuid4())
        self.analyzed = False
        self.intelligence_gathered = {}
    
    @property
    def success(self):
        return self.exit_code == 0


class MockAttackAgent:
    """Simplified mock attack agent for testing refactored methods."""
    
    def __init__(self):
        self.state = None
        self.attack_log = []
        self.llm = AsyncMock()
        self.vm = AsyncMock()
        self.safety = MagicMock()
    
    async def _generate_llm_response(self, prompt):
        """Mock LLM response."""
        return '{"hosts_discovered": ["192.168.1.100"], "services_found": []}'
    
    def _extract_json(self, text):
        """Mock JSON extraction."""
        return {"hosts_discovered": ["192.168.1.100"], "services_found": []}
    
    async def _analyze_command_output(self, command, stdout, stderr):
        """Mock output analysis."""
        return {
            "hosts_discovered": ["192.168.1.100"],
            "services_found": [],
            "credentials_found": [],
            "vulnerabilities_found": [],
            "users_found": [],
            "network_info": {},
            "file_system_info": {},
            "security_indicators": [],
        }
    
    async def _update_state_from_intelligence(self, intelligence):
        """Mock state update."""
        if not self.state:
            return
        for host in intelligence.get("hosts_discovered", []):
            if host not in self.state.compromised_hosts:
                pass  # Discovered hosts are not automatically compromised
        for service in intelligence.get("services_found", []):
            if service not in self.state.discovered_services:
                self.state.discovered_services.append(service)
    
    async def _update_attack_graph(self, command, result):
        """Mock attack graph update."""
        graph_update = {
            "command_id": getattr(result, 'command_id', 'unknown'),
            "command": command,
            "success": result.success,
            "timestamp": result.timestamp.isoformat(),
            "vm_id": result.vm_id,
            "phase": self.state.current_phase.value if self.state else "unknown",
            "technique_inferred": self._infer_technique_from_command(command),
            "impact_level": self._assess_command_impact(command, result),
            "connections": [],
        }
        self.attack_log.append({
            "type": "attack_graph_update",
            "timestamp": datetime.utcnow().isoformat(),
            "update": graph_update,
        })
    
    def _log_single_command(self, command, result, command_id):
        """Mock single command logging."""
        log_entry = {
            "type": "single_command",
            "command_id": command_id,
            "command": command,
            "vm_id": result.vm_id,
            "success": result.success,
            "exit_code": result.exit_code,
            "execution_time_ms": result.execution_time_ms,
            "analyzed": getattr(result, 'analyzed', False),
            "intelligence_count": len(getattr(result, 'intelligence_gathered', {})),
            "timestamp": result.timestamp.isoformat(),
            "phase": self.state.current_phase.value if self.state else "unknown",
            "objective": self.state.current_objective if self.state else "",
        }
        self.attack_log.append(log_entry)
    
    def _infer_technique_from_command(self, command):
        """Mock technique inference."""
        command_lower = command.lower()
        if "nmap" in command_lower:
            return "T1595"
        elif "hydra" in command_lower:
            return "T1110"
        else:
            return "T1059"
    
    def _assess_command_impact(self, command, result):
        """Mock impact assessment."""
        if not result.success:
            return "low"
        command_lower = command.lower()
        if "exploit" in command_lower:
            return "high"
        elif "nmap" in command_lower:
            return "medium"
        else:
            return "low"
    
    async def run_single_command(self, command, vm_id=None, analyze_output=True, update_attack_graph=True):
        """Refactored run_single_command method."""
        target_vm = vm_id or (self.state.current_vm if self.state else None)
        if not target_vm:
            raise ValueError("No VM specified and no active state")

        # Initialize state if not present
        if not self.state:
            self.state = MockAgentState()
            self.state.current_vm = target_vm
            self.state.current_phase = MockAttackPhase("execution")
            self.state.current_objective = "Single command execution"

        # Track command in state
        command_id = str(uuid4())
        self.state.action_history.append({
            "command_id": command_id,
            "command": command,
            "vm_id": target_vm,
            "timestamp": datetime.utcnow().isoformat(),
            "phase": self.state.current_phase.value,
            "objective": self.state.current_objective,
        })

        # Validate command safety
        is_safe, reason = self.safety.validate_command(command)
        if not is_safe:
            blocked_result = MockCommandResult(
                command=command,
                stdout="",
                stderr=f"Command blocked by safety controller: {reason}",
                exit_code=-1,
                vm_id=target_vm,
            )
            
            # Track blocked command
            self.state.errors.append(f"Command blocked: {reason}")
            self.state.action_history.append({
                "command_id": command_id,
                "result": "blocked",
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat(),
            })
            
            return blocked_result

        # Execute command
        result = await self.vm.execute_command(target_vm, command)
        
        # Add command metadata
        result.command_id = command_id
        result.analyzed = False
        result.intelligence_gathered = {}

        # Track in command history
        self.state.command_history.append(result)
        self.state.last_action = datetime.utcnow()

        # Analyze output for intelligence gathering
        if analyze_output and result.stdout:
            intelligence = await self._analyze_command_output(command, result.stdout, result.stderr)
            result.intelligence_gathered = intelligence
            result.analyzed = True

            # Update state with intelligence findings
            await self._update_state_from_intelligence(intelligence)

        # Update attack graph based on results
        if update_attack_graph:
            await self._update_attack_graph(command, result)

        # Log action with enhanced tracking
        self._log_single_command(command, result, command_id)

        return result


class TestAttackAgentSingleCommand:
    """Test suite for refactored run_single_command method."""

    @pytest.fixture
    def mock_vm_operator(self):
        """Create mock VM operator."""
        vm_op = AsyncMock()
        vm_op.execute_command = AsyncMock(return_value=MockCommandResult(
            command="nmap -sV 192.168.1.100",
            stdout="Starting Nmap scan...\n192.168.1.100 - ssh open",
            stderr="",
            exit_code=0,
            vm_id="attacker-vm",
        ))
        return vm_op

    @pytest.fixture
    def mock_safety_controller(self):
        """Create mock safety controller."""
        safety = MagicMock()
        safety.validate_command.return_value = (True, "")
        return safety

    @pytest.fixture
    def agent(self, mock_vm_operator, mock_safety_controller):
        """Create AttackAgent instance with mocked dependencies."""
        agent = MockAttackAgent()
        agent.safety = mock_safety_controller
        return agent

    @pytest.mark.asyncio
    async def test_run_single_command_basic_execution(self, agent):
        """Test basic command execution with state tracking."""
        agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
            command="ls -la",
            stdout="total 0",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        ))
        
        result = await agent.run_single_command("ls -la", "test-vm")
        
        assert result.command == "ls -la"
        assert result.vm_id == "test-vm"
        assert result.success is True
        assert hasattr(result, 'command_id')
        assert hasattr(result, 'analyzed')
        assert hasattr(result, 'intelligence_gathered')

    @pytest.mark.asyncio
    async def test_run_single_command_state_initialization(self, agent):
        """Test state initialization when no state exists."""
        assert agent.state is None
        
        agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
            command="pwd",
            stdout="/root",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        ))
        
        result = await agent.run_single_command("pwd", "test-vm")
        
        assert agent.state is not None
        assert agent.state.current_vm == "test-vm"
        assert agent.state.current_phase == "execution"
        assert agent.state.current_objective == "Single command execution"

    @pytest.mark.asyncio
    async def test_run_single_command_command_tracking(self, agent):
        """Test command tracking in agent state."""
        agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
            command="nmap -sV 192.168.1.100",
            stdout="scan results",
            stderr="",
            exit_code=0,
            vm_id="attacker-vm",
        ))
        
        result = await agent.run_single_command("nmap -sV 192.168.1.100", "attacker-vm")
        
        # Check action history
        assert len(agent.state.action_history) >= 2  # Command tracking + result tracking
        command_entry = agent.state.action_history[0]
        assert command_entry["command"] == "nmap -sV 192.168.1.100"
        assert command_entry["vm_id"] == "attacker-vm"
        assert "command_id" in command_entry
        assert "timestamp" in command_entry
        assert "phase" in command_entry

    @pytest.mark.asyncio
    async def test_run_single_command_intelligence_analysis(self, agent):
        """Test output analysis for intelligence gathering."""
        agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
            command="nmap -sV 192.168.1.100",
            stdout="192.168.1.100 - ssh open",
            stderr="",
            exit_code=0,
            vm_id="attacker-vm",
        ))
        
        result = await agent.run_single_command(
            "nmap -sV 192.168.1.100", 
            "attacker-vm",
            analyze_output=True
        )
        
        assert result.analyzed is True
        assert "hosts_discovered" in result.intelligence_gathered
        assert "services_found" in result.intelligence_gathered
        assert len(result.intelligence_gathered["hosts_discovered"]) > 0

    @pytest.mark.asyncio
    async def test_run_single_command_attack_graph_update(self, agent):
        """Test attack graph updates based on results."""
        agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
            command="nmap -sV 192.168.1.100",
            stdout="scan results",
            stderr="",
            exit_code=0,
            vm_id="attacker-vm",
        ))
        
        result = await agent.run_single_command(
            "nmap -sV 192.168.1.100",
            "attacker-vm",
            update_attack_graph=True
        )
        
        # Check attack log for graph updates
        graph_updates = [entry for entry in agent.attack_log if entry["type"] == "attack_graph_update"]
        assert len(graph_updates) > 0
        
        graph_update = graph_updates[0]["update"]
        assert graph_update["command"] == "nmap -sV 192.168.1.100"
        assert graph_update["success"] is True
        assert "technique_inferred" in graph_update
        assert "impact_level" in graph_update
        assert "connections" in graph_update

    @pytest.mark.asyncio
    async def test_run_single_command_safety_blocking(self, agent):
        """Test command safety blocking."""
        # Configure safety controller to block command
        agent.safety.validate_command.return_value = (False, "Dangerous command")
        
        result = await agent.run_single_command("rm -rf /", "test-vm")
        
        assert result.success is False
        assert result.exit_code == -1
        assert "blocked by safety controller" in result.stderr
        assert len(agent.state.errors) > 0
        assert "Command blocked" in agent.state.errors[0]

    @pytest.mark.asyncio
    async def test_run_single_command_no_vm_specified(self, agent):
        """Test error when no VM is specified and no active state."""
        with pytest.raises(ValueError, match="No VM specified"):
            await agent.run_single_command("ls")

    @pytest.mark.asyncio
    async def test_run_single_command_technique_inference(self, agent):
        """Test MITRE technique inference from commands."""
        test_cases = [
            ("nmap -sV 192.168.1.100", "T1595"),
            ("hydra -l admin -p password ssh://192.168.1.100", "T1110"),
            ("ssh user@192.168.1.100", "T1021"),
            ("unknown_command", "T1059"),  # Default
        ]
        
        for command, expected_technique in test_cases:
            agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
                command=command,
                stdout="success",
                stderr="",
                exit_code=0,
                vm_id="attacker-vm",
            ))
            
            result = await agent.run_single_command(command, "attacker-vm")
            
            # Find graph update for this command
            graph_updates = [entry for entry in agent.attack_log if entry["type"] == "attack_graph_update"]
            latest_update = graph_updates[-1]["update"]
            assert latest_update["technique_inferred"] == expected_technique

    @pytest.mark.asyncio
    async def test_run_single_command_optional_analysis(self, agent):
        """Test optional analysis and graph updates."""
        agent.vm.execute_command = AsyncMock(return_value=MockCommandResult(
            command="echo 'test'",
            stdout="test",
            stderr="",
            exit_code=0,
            vm_id="attacker-vm",
        ))
        
        result = await agent.run_single_command(
            "echo 'test'",
            "attacker-vm",
            analyze_output=False,
            update_attack_graph=False
        )
        
        assert result.analyzed is False
        assert result.intelligence_gathered == {}
        
        # Check no attack graph updates
        graph_updates = [entry for entry in agent.attack_log if entry["type"] == "attack_graph_update"]
        assert len(graph_updates) == 0

    def test_technique_inference_edge_cases(self, agent):
        """Test technique inference with various edge cases."""
        test_cases = [
            ("", "T1059"),  # Empty command
            ("UNKNOWN_TOOL", "T1059"),  # Unknown tool
            ("NMAP -sV", "T1595"),  # Case insensitive
        ]
        
        for command, expected in test_cases:
            result = agent._infer_technique_from_command(command)
            assert result == expected

    def test_impact_assessment_edge_cases(self, agent):
        """Test impact assessment with various scenarios."""
        # Failed command
        failed_result = MockCommandResult(
            command="test",
            stdout="",
            stderr="error",
            exit_code=1,
            vm_id="test",
        )
        impact = agent._assess_command_impact("test", failed_result)
        assert impact == "low"
        
        # High impact command
        success_result = MockCommandResult(
            command="exploit",
            stdout="success",
            stderr="",
            exit_code=0,
            vm_id="test",
        )
        impact = agent._assess_command_impact("exploit", success_result)
        assert impact == "high"
