"""Unit tests for refactored AttackAgent run_single_command method.

Tests Issue #132: AttackAgent Single Command - Refactor for Proper State Tracking
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from threatsimgpt.vm.agent import AIAttackAgent
from threatsimgpt.vm.models import (
    AgentState,
    AttackPhase,
    CommandResult,
)
from threatsimgpt.vm.safety import VMSafetyController


class TestAttackAgentSingleCommand:
    """Test suite for refactored run_single_command method."""

    @pytest.fixture
    def mock_llm_manager(self):
        """Create mock LLM manager."""
        llm = AsyncMock()
        llm.generate = AsyncMock(return_value='{"hosts_discovered": ["192.168.1.100"], "services_found": []}')
        return llm

    @pytest.fixture
    def mock_vm_operator(self):
        """Create mock VM operator."""
        vm_op = AsyncMock()
        vm_op.execute_command = AsyncMock(return_value=CommandResult(
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
    def agent(self, mock_llm_manager, mock_vm_operator, mock_safety_controller):
        """Create AttackAgent instance with mocked dependencies."""
        return AIAttackAgent(
            llm_manager=mock_llm_manager,
            vm_operator=mock_vm_operator,
            safety_controller=mock_safety_controller,
        )

    @pytest.mark.asyncio
    async def test_run_single_command_basic_execution(self, agent):
        """Test basic command execution with state tracking."""
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
        
        result = await agent.run_single_command("pwd", "test-vm")
        
        assert agent.state is not None
        assert agent.state.current_vm == "test-vm"
        assert agent.state.current_phase == AttackPhase.EXECUTION
        assert agent.state.current_objective == "Single command execution"

    @pytest.mark.asyncio
    async def test_run_single_command_command_tracking(self, agent):
        """Test command tracking in agent state."""
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
    async def test_run_single_command_with_existing_state(self, agent):
        """Test command execution with existing agent state."""
        # Set up existing state
        agent.state = AgentState(
            current_vm="existing-vm",
            current_phase=AttackPhase.RECONNAISSANCE,
            current_objective="Network discovery",
        )
        
        result = await agent.run_single_command("ping -c 1 192.168.1.1")
        
        assert result.vm_id == "existing-vm"  # Uses VM from state
        assert agent.state.current_phase == AttackPhase.RECONNAISSANCE  # Preserves existing phase

    @pytest.mark.asyncio
    async def test_run_single_command_intelligence_fallback(self, agent):
        """Test fallback to basic analysis when LLM fails."""
        # Configure LLM to fail
        agent.llm.generate.side_effect = Exception("LLM failed")
        
        result = await agent.run_single_command("nmap 192.168.1.100", "attacker-vm")
        
        # Should still have basic analysis
        assert result.analyzed is True
        assert "hosts_discovered" in result.intelligence_gathered

    @pytest.mark.asyncio
    async def test_run_single_command_optional_analysis(self, agent):
        """Test optional analysis and graph updates."""
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

    @pytest.mark.asyncio
    async def test_run_single_command_technique_inference(self, agent):
        """Test MITRE technique inference from commands."""
        test_cases = [
            ("nmap -sV 192.168.1.100", "T1595"),
            ("hydra -l admin -p password ssh://192.168.1.100", "T1110"),
            ("ssh user@192.168.1.100", "T1021"),
            ("powershell -c Get-Process", "T1059"),
            ("unknown_command", "T1059"),  # Default
        ]
        
        for command, expected_technique in test_cases:
            result = await agent.run_single_command(command, "attacker-vm")
            
            # Find the graph update for this command
            graph_updates = [entry for entry in agent.attack_log if entry["type"] == "attack_graph_update"]
            latest_update = graph_updates[-1]["update"]
            assert latest_update["technique_inferred"] == expected_technique

    @pytest.mark.asyncio
    async def test_run_single_command_impact_assessment(self, agent):
        """Test command impact assessment."""
        test_cases = [
            ("echo 'test'", "low"),
            ("nmap -sV 192.168.1.100", "medium"),
            ("exploit/multi/handler", "high"),
        ]
        
        for command, expected_impact in test_cases:
            # Configure mock to return success
            agent.vm.execute_command.return_value = CommandResult(
                command=command,
                stdout="success",
                stderr="",
                exit_code=0,
                vm_id="attacker-vm",
            )
            
            result = await agent.run_single_command(command, "attacker-vm")
            
            # Find the graph update for this command
            graph_updates = [entry for entry in agent.attack_log if entry["type"] == "attack_graph_update"]
            latest_update = graph_updates[-1]["update"]
            assert latest_update["impact_level"] == expected_impact

    @pytest.mark.asyncio
    async def test_run_single_command_state_updates_from_intelligence(self, agent):
        """Test state updates from intelligence findings."""
        # Configure LLM to return specific intelligence
        agent.llm.generate.return_value = '''{
            "hosts_discovered": ["192.168.1.100"],
            "services_found": [{"host": "192.168.1.100", "port": 22, "service": "ssh"}],
            "credentials_found": [{"username": "admin", "password_hash": "hash", "type": "ssh"}],
            "users_found": ["admin", "root"],
            "security_indicators": ["SSH brute force attempt"]
        }'''
        
        result = await agent.run_single_command("nmap 192.168.1.100", "attacker-vm")
        
        # Check state updates
        assert len(agent.state.discovered_services) > 0
        assert len(agent.state.collected_credentials) > 0
        assert len(agent.state.discovered_users) > 0
        
        # Check security indicators logged
        security_logs = [entry for entry in agent.attack_log if entry["type"] == "security_indicators"]
        assert len(security_logs) > 0
        assert "SSH brute force attempt" in security_logs[0]["indicators"]

    @pytest.mark.asyncio
    async def test_run_single_command_enhanced_logging(self, agent):
        """Test enhanced logging with intelligence summary."""
        result = await agent.run_single_command("nmap 192.168.1.100", "attacker-vm")
        
        # Find single command log entry
        command_logs = [entry for entry in agent.attack_log if entry["type"] == "single_command"]
        assert len(command_logs) > 0
        
        log_entry = command_logs[0]
        assert "command_id" in log_entry
        assert "intelligence_summary" in log_entry
        assert "execution_time_ms" in log_entry
        assert "phase" in log_entry
        assert "objective" in log_entry
        
        # Check intelligence summary structure
        summary = log_entry["intelligence_summary"]
        assert "hosts_discovered" in summary
        assert "services_found" in summary
        assert "credentials_found" in summary

    def test_basic_output_analysis_fallback(self, agent):
        """Test basic pattern-based output analysis."""
        stdout = "192.168.1.100 - ssh open\n192.168.1.101 - http open\nuser: admin found"
        stderr = ""
        
        intelligence = agent._basic_output_analysis("nmap", stdout, stderr)
        
        assert "192.168.1.100" in intelligence["hosts_discovered"]
        assert "192.168.1.101" in intelligence["hosts_discovered"]
        assert len(intelligence["services_found"]) > 0
        assert "admin" in intelligence["users_found"]

    def test_technique_inference_edge_cases(self, agent):
        """Test technique inference with various edge cases."""
        test_cases = [
            ("", "T1059"),  # Empty command
            ("UNKNOWN_TOOL", "T1059"),  # Unknown tool
            ("NMAP -sV", "T1595"),  # Case insensitive
            ("sudo nmap", "T1595"),  # With sudo
        ]
        
        for command, expected in test_cases:
            result = agent._infer_technique_from_command(command)
            assert result == expected

    def test_impact_assessment_edge_cases(self, agent):
        """Test impact assessment with various scenarios."""
        # Failed command
        failed_result = CommandResult(
            command="test",
            stdout="",
            stderr="error",
            exit_code=1,
            vm_id="test",
        )
        impact = agent._assess_command_impact("test", failed_result)
        assert impact == "low"
        
        # High impact command
        success_result = CommandResult(
            command="exploit",
            stdout="success",
            stderr="",
            exit_code=0,
            vm_id="test",
        )
        impact = agent._assess_command_impact("exploit", success_result)
        assert impact == "high"
