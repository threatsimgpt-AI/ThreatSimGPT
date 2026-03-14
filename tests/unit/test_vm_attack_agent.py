import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("numpy", MagicMock())

from threatsimgpt.vm.agent import AIAttackAgent
from threatsimgpt.vm.models import AttackPhase, AttackStep, AgentState, CommandResult


class FakeLLM:
    def __init__(self, response: str):
        self.response = response

    async def generate(self, prompt: str):
        return self.response


class FakeVMOperator:
    async def execute_command(self, vm_id, command, timeout_seconds=60):
        return CommandResult(command=command, stdout="ok", stderr="", exit_code=0, vm_id=vm_id)

    async def snapshot_vm(self, vm_id, name):
        return None


@pytest.mark.asyncio
async def test_plan_attack_parses_and_sanitizes_commands():
    llm_response = """
    {
        "name": "Unit Test Plan",
        "description": "Plan for unit test",
        "objectives": ["Discover services"],
        "mitre_techniques": ["T1595"],
        "steps": [
            {
                "phase": "reconnaissance",
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "description": "Scan target",
                "commands": ["nmap -sV TARGET"],
                "success_indicators": ["open"],
                "timeout_seconds": 120
            },
            {
                "phase": "discovery",
                "technique_id": "T1083",
                "technique_name": "File and Directory Discovery",
                "description": "Check system",
                "commands": ["uname -a"],
                "success_indicators": ["Linux"],
                "timeout_seconds": 120
            },
            {
                "phase": "credential_access",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "description": "Attempt credentials",
                "commands": ["hydra -L users.txt -P passwords.txt ssh://TARGET"],
                "success_indicators": ["login"],
                "timeout_seconds": 300
            },
            {
                "phase": "collection",
                "technique_id": "T1005",
                "technique_name": "Data from Local System",
                "description": "Collect info",
                "commands": ["cat /etc/os-release"],
                "success_indicators": ["NAME="],
                "timeout_seconds": 120
            }
        ],
        "success_criteria": ["services discovered"],
        "estimated_duration_minutes": 30
    }
    """

    agent = AIAttackAgent(FakeLLM(llm_response), FakeVMOperator())
    scenario = {"name": "Test Scenario", "objectives": ["Discover services"]}
    target_info = {"ip_address": "10.0.100.10"}

    plan = await agent.plan_attack(scenario, target_info)

    assert plan.name == "Unit Test Plan"
    assert len(plan.steps) >= 4
    assert plan.steps[0].phase == AttackPhase.RECONNAISSANCE
    assert "10.0.100.10" in plan.steps[0].commands[0]


def test_sanitize_command_replaces_only_placeholders():
    agent = AIAttackAgent(FakeLLM("{}"), FakeVMOperator())
    command = "echo HOSTNAME && ping -c 1 HOST && curl http://TARGET"

    sanitized = agent._sanitize_command(command, "10.0.0.5")

    assert "HOSTNAME" in sanitized
    assert "10.0.0.5" in sanitized
    assert "TARGET" not in sanitized


@pytest.mark.asyncio
async def test_plan_attack_falls_back_on_invalid_response():
    agent = AIAttackAgent(FakeLLM("not-json"), FakeVMOperator())
    scenario = {"name": "Fallback Scenario", "objectives": ["Establish access"]}
    target_info = {"ip_address": "10.0.100.20"}

    plan = await agent.plan_attack(scenario, target_info)

    assert plan.name == "Fallback Scenario"
    assert len(plan.steps) >= 4
    assert any("10.0.100.20" in cmd for cmd in plan.steps[0].commands)


@pytest.mark.asyncio
async def test_analyze_and_adapt_updates_state():
    llm_response = """
    {
        "step_successful": true,
        "findings": ["SSH open"],
        "new_hosts_compromised": ["10.0.100.50"],
        "new_credentials": [{"username": "root", "password_hash": "hash", "type": "ssh"}],
        "new_services": [{"host": "10.0.100.50", "port": 22, "service": "ssh"}],
        "continue_attack": true,
        "next_action_suggestion": "Attempt SSH login",
        "detection_indicators": ["SSH login attempts"]
    }
    """

    agent = AIAttackAgent(FakeLLM(llm_response), FakeVMOperator())
    agent.state = AgentState(current_vm="attacker")

    step = AttackStep(
        phase=AttackPhase.RECONNAISSANCE,
        technique_id="T1595",
        technique_name="Active Scanning",
        description="Scan",
        commands=["nmap -sV 10.0.100.50"],
        success_indicators=["open"],
    )

    result = {
        "outputs": ["22/tcp open ssh"],
        "commands_executed": [{"exit_code": 0}],
    }

    should_continue = await agent._analyze_and_adapt(step, result)

    assert should_continue is True
    assert "10.0.100.50" in agent.state.compromised_hosts
    assert agent.state.collected_credentials
    assert agent.state.discovered_services
