"""Enhanced unit tests for improved AttackAgent run_single_command method.

Tests Issue #132 improvements: pluggable analysis engines, better error handling, and caching.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from threatsimgpt.vm.agent import AIAttackAgent
from threatsimgpt.vm.models import AgentState, AttackPhase, CommandResult
from threatsimgpt.vm.analysis_engine import (
    AnalysisEngineFactory,
    LLMAnalysisError,
    PatternAnalysisEngine,
    LLMAnalysisEngine,
)
from threatsimgpt.vm.safety import VMSafetyController


class MockVMOperator:
    """Mock VM operator for testing."""
    def __init__(self):
        self.execute_command = AsyncMock()
    
    async def execute_command(self, vm_id, command):
        return self.execute_command(vm_id, command)


class MockLLMManager:
    """Mock LLM manager for testing."""
    def __init__(self, should_fail=False, json_response=None):
        self.should_fail = should_fail
        self.json_response = json_response or '{"hosts_discovered": ["192.168.1.100"]}'
        self.generate_calls = []
    
    async def generate(self, prompt):
        self.generate_calls.append(prompt)
        if self.should_fail:
            raise Exception("LLM service unavailable")
        return self.json_response


class TestImprovedAttackAgent:
    """Test suite for improved AttackAgent with pluggable analysis engines."""

    @pytest.fixture
    def mock_vm_operator(self):
        return MockVMOperator()

    @pytest.fixture
    def mock_llm_manager(self):
        return MockLLMManager()

    @pytest.fixture
    def mock_safety_controller(self):
        safety = MagicMock()
        safety.validate_command.return_value = (True, "")
        return safety

    @pytest.fixture
    def agent_with_hybrid_engine(self, mock_vm_operator, mock_llm_manager, mock_safety_controller):
        """Create agent with hybrid analysis engine."""
        return AIAttackAgent(
            llm_manager=mock_llm_manager,
            vm_operator=mock_vm_operator,
            safety_controller=mock_safety_controller,
            analysis_engine_type="cached_hybrid",
            analysis_cache_ttl_minutes=30,
        )

    @pytest.mark.asyncio
    async def test_pluggable_analysis_engine_factory(self, mock_llm_manager):
        """Test that analysis engine factory creates correct engines."""
        # Test different engine types
        llm_engine = AnalysisEngineFactory.create_engine("llm", mock_llm_manager)
        assert llm_engine.get_engine_name() == "llm"
        assert llm_engine.get_reliability_score() == 0.8

        pattern_engine = AnalysisEngineFactory.create_engine("pattern")
        assert pattern_engine.get_engine_name() == "pattern"
        assert pattern_engine.get_reliability_score() == 0.6

        hybrid_engine = AnalysisEngineFactory.create_engine("hybrid", mock_llm_manager)
        assert hybrid_engine.get_engine_name() == "hybrid"
        assert hybrid_engine.get_reliability_score() == 0.9

        cached_engine = AnalysisEngineFactory.create_engine("cached_llm", mock_llm_manager)
        assert cached_engine.get_engine_name() == "cached_llm"
        assert cached_engine.get_reliability_score() == 0.8

    @pytest.mark.asyncio
    async def test_analysis_engine_caching(self, agent_with_hybrid_engine):
        """Test that analysis results are cached for repeated commands."""
        # Mock VM to return same output
        agent_with_hybrid_engine.vm.execute_command.return_value = CommandResult(
            command="nmap 192.168.1.100",
            stdout="192.168.1.100 - ssh open",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        )

        # Execute same command twice
        result1 = await agent_with_hybrid_engine.run_single_command("nmap 192.168.1.100", "test-vm")
        result2 = await agent_with_hybrid_engine.run_single_command("nmap 192.168.1.100", "test-vm")

        # Both should have same intelligence (cached)
        assert result1.intelligence_gathered == result2.intelligence_gathered
        assert result1.analyzed == result2.analyzed

        # Verify LLM was only called once due to caching
        assert len(agent_with_hybrid_engine.llm.generate_calls) == 1

    @pytest.mark.asyncio
    async def test_llm_fallback_to_pattern_analysis(self, mock_vm_operator, mock_safety_controller):
        """Test fallback to pattern analysis when LLM fails."""
        # Create LLM manager that will fail
        failing_llm = MockLLMManager(should_fail=True)
        
        agent = AIAttackAgent(
            llm_manager=failing_llm,
            vm_operator=mock_vm_operator,
            safety_controller=mock_safety_controller,
            analysis_engine_type="hybrid",
        )

        # Mock VM response
        agent.vm.execute_command.return_value = CommandResult(
            command="nmap 192.168.1.100",
            stdout="192.168.1.100 - ssh open",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        )

        # Execute command - should fall back to pattern analysis
        result = await agent.run_single_command("nmap 192.168.1.100", "test-vm")

        # Should still have analysis results from pattern engine
        assert result.analyzed is True
        assert "hosts_discovered" in result.intelligence_gathered
        assert "192.168.1.100" in result.intelligence_gathered["hosts_discovered"]

    @pytest.mark.asyncio
    async def test_specific_error_handling(self, agent_with_hybrid_engine):
        """Test specific error handling for different failure types."""
        # Test LLMAnalysisError handling
        with patch.object(agent_with_hybrid_engine.analysis_engine, 'analyze') as mock_analyze:
            mock_analyze.side_effect = LLMAnalysisError("JSON parsing failed", Exception("original error"))
            
            agent_with_hybrid_engine.vm.execute_command.return_value = CommandResult(
                command="test command",
                stdout="output",
                stderr="",
                exit_code=0,
                vm_id="test-vm",
            )

            result = await agent_with_hybrid_engine.run_single_command("test command", "test-vm")

            # Should fall back to pattern analysis
            assert result.analyzed is True
            assert "hosts_discovered" in result.intelligence_gathered

    @pytest.mark.asyncio
    async def test_analysis_engine_configuration(self, mock_vm_operator, mock_llm_manager, mock_safety_controller):
        """Test different analysis engine configurations."""
        # Test with pattern-only engine
        pattern_agent = AIAttackAgent(
            llm_manager=mock_llm_manager,
            vm_operator=mock_vm_operator,
            safety_controller=mock_safety_controller,
            analysis_engine_type="pattern",
        )
        assert pattern_agent.analysis_engine.get_engine_name() == "pattern"

        # Test with cached hybrid engine
        cached_agent = AIAttackAgent(
            llm_manager=mock_llm_manager,
            vm_operator=mock_vm_operator,
            safety_controller=mock_safety_controller,
            analysis_engine_type="cached_hybrid",
            analysis_cache_ttl_minutes=60,
        )
        assert cached_agent.analysis_engine.get_engine_name() == "cached_hybrid"

    @pytest.mark.asyncio
    async def test_performance_improvements(self, agent_with_hybrid_engine):
        """Test performance improvements from caching."""
        # Mock VM response
        agent_with_hybrid_engine.vm.execute_command.return_value = CommandResult(
            command="nmap 192.168.1.100",
            stdout="192.168.1.100 - ssh open",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        )

        # Time multiple executions
        import time
        start_time = time.time()
        
        await agent_with_hybrid_engine.run_single_command("nmap 192.168.1.100", "test-vm")
        first_duration = time.time() - start_time

        start_time = time.time()
        await agent_with_hybrid_engine.run_single_command("nmap 192.168.1.100", "test-vm")
        second_duration = time.time() - start_time

        # Second execution should be faster due to caching
        assert second_duration < first_duration

    @pytest.mark.asyncio
    async def test_reliability_scoring(self, mock_llm_manager):
        """Test reliability scoring of different engines."""
        engines = {
            "llm": AnalysisEngineFactory.create_engine("llm", mock_llm_manager),
            "pattern": AnalysisEngineFactory.create_engine("pattern"),
            "hybrid": AnalysisEngineFactory.create_engine("hybrid", mock_llm_manager),
            "cached_hybrid": AnalysisEngineFactory.create_engine("cached_hybrid", mock_llm_manager),
        }

        expected_scores = {
            "llm": 0.8,
            "pattern": 0.6,
            "hybrid": 0.9,
            "cached_hybrid": 0.9,
        }

        for engine_type, engine in engines.items():
            assert engine.get_reliability_score() == expected_scores[engine_type]

    @pytest.mark.asyncio
    async def test_backward_compatibility(self, agent_with_hybrid_engine):
        """Test that new implementation maintains backward compatibility."""
        agent_with_hybrid_engine.vm.execute_command.return_value = CommandResult(
            command="ls -la",
            stdout="total 0",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        )

        # Test with optional parameters disabled (old behavior)
        result = await agent_with_hybrid_engine.run_single_command(
            "ls -la", 
            "test-vm",
            analyze_output=False,
            update_attack_graph=False
        )

        # Should still work without analysis and graph updates
        assert result.analyzed is False
        assert result.intelligence_gathered == {}

    @pytest.mark.asyncio
    async def test_intelligence_quality_validation(self, agent_with_hybrid_engine):
        """Test that intelligence quality is maintained across different engines."""
        # Mock VM with realistic nmap output
        nmap_output = """
        Starting Nmap 7.92 scan
        Nmap scan report for 192.168.1.100
        Host is up (0.021s latency).
        PORT     STATE SERVICE
        22/tcp   open  ssh
        80/tcp   open  http
        443/tcp  open  https
        """

        agent_with_hybrid_engine.vm.execute_command.return_value = CommandResult(
            command="nmap -sV 192.168.1.100",
            stdout=nmap_output,
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        )

        result = await agent_with_hybrid_engine.run_single_command("nmap -sV 192.168.1.100", "test-vm")

        # Validate intelligence quality
        intelligence = result.intelligence_gathered
        assert "hosts_discovered" in intelligence
        assert "services_found" in intelligence
        assert len(intelligence["services_found"]) >= 3  # ssh, http, https
        
        # Check service structure
        services = intelligence["services_found"]
        service_ports = [s["port"] for s in services]
        assert 22 in service_ports  # SSH
        assert 80 in service_ports  # HTTP

    @pytest.mark.asyncio
    async def test_error_recovery_mechanisms(self, agent_with_hybrid_engine):
        """Test multiple layers of error recovery."""
        # Mock analysis engine to fail multiple times
        original_analyze = agent_with_hybrid_engine.analysis_engine.analyze
        
        call_count = 0
        async def failing_analyze(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception(f"Analysis failure {call_count}")
            return await original_analyze(*args, **kwargs)
        
        agent_with_hybrid_engine.analysis_engine.analyze = failing_analyze

        agent_with_hybrid_engine.vm.execute_command.return_value = CommandResult(
            command="test command",
            stdout="output",
            stderr="",
            exit_code=0,
            vm_id="test-vm",
        )

        # Should eventually succeed after retries
        result = await agent_with_hybrid_engine.run_single_command("test command", "test-vm")
        
        assert result.analyzed is True
        assert "hosts_discovered" in result.intelligence_gathered


class TestAnalysisEngines:
    """Test individual analysis engine implementations."""

    @pytest.mark.asyncio
    async def test_pattern_analysis_engine_basic(self):
        """Test pattern analysis engine with basic input."""
        engine = PatternAnalysisEngine()
        
        result = await engine.analyze(
            "nmap 192.168.1.100",
            "192.168.1.100 - ssh open\n192.168.1.101 - http open",
            "user: admin found"
        )
        
        assert "192.168.1.100" in result["hosts_discovered"]
        assert "192.168.1.101" in result["hosts_discovered"]
        assert len(result["services_found"]) == 2
        assert "admin" in result["users_found"]

    @pytest.mark.asyncio
    async def test_llm_analysis_engine_with_mock(self):
        """Test LLM analysis engine with mock LLM."""
        mock_llm = MockLLMManager(
            json_response='{"hosts_discovered": ["192.168.1.100"], "services_found": []}'
        )
        
        engine = LLMAnalysisEngine(mock_llm)
        result = await engine.analyze("test command", "output", "")
        
        assert result["hosts_discovered"] == ["192.168.1.100"]
        assert len(mock_llm.generate_calls) == 1

    @pytest.mark.asyncio
    async def test_hybrid_engine_fallback(self):
        """Test hybrid engine fallback mechanism."""
        failing_llm = MockLLMManager(should_fail=True)
        
        engine = AnalysisEngineFactory.create_engine("hybrid", failing_llm)
        result = await engine.analyze(
            "nmap 192.168.1.100",
            "192.168.1.100 - ssh open",
            ""
        )
        
        # Should fall back to pattern analysis
        assert "192.168.1.100" in result["hosts_discovered"]
        assert engine.get_engine_name() == "hybrid"
