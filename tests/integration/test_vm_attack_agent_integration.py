import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("numpy", MagicMock())

from threatsimgpt.vm.agent import AIAttackAgent
from threatsimgpt.vm.models import AttackPhase, AttackStep, CommandResult


class FakeLLM:
    async def generate(self, prompt: str):
        if "Create a detailed attack plan" in prompt:
            return """
            {
                "name": "Integration Plan",
                "description": "Integration plan",
                "objectives": ["Discover services"],
                "mitre_techniques": ["T1595"],
                "steps": [
                    {
                        "phase": "reconnaissance",
                        "technique_id": "T1595",
                        "technique_name": "Active Scanning",
                        "description": "Scan target",
                        "commands": ["nmap -sV 10.0.100.10"],
                        "success_indicators": ["open"],
                        "timeout_seconds": 120
                    },
                    {
                        "phase": "discovery",
                        "technique_id": "T1083",
                        "technique_name": "File and Directory Discovery",
                        "description": "Gather info",
                        "commands": ["uname -a"],
                        "success_indicators": ["Linux"],
                        "timeout_seconds": 120
                    },
                    {
                        "phase": "collection",
                        "technique_id": "T1005",
                        "technique_name": "Data from Local System",
                        "description": "Collect data",
                        "commands": ["cat /etc/os-release"],
                        "success_indicators": ["NAME="],
                        "timeout_seconds": 120
                    },
                    {
                        "phase": "credential_access",
                        "technique_id": "T1110",
                        "technique_name": "Brute Force",
                        "description": "Attempt creds",
                        "commands": ["hydra -L users.txt -P passwords.txt ssh://10.0.100.10"],
                        "success_indicators": ["login"],
                        "timeout_seconds": 300
                    }
                ],
                "success_criteria": ["services discovered"],
                "estimated_duration_minutes": 30
            }
            """

        if "Answer these questions in JSON format" in prompt:
            return """
            {
                "step_successful": true,
                "findings": ["open port"],
                "new_hosts_compromised": ["10.0.100.10"],
                "new_credentials": [],
                "new_services": [{"host": "10.0.100.10", "port": 22, "service": "ssh"}],
                "continue_attack": true,
                "next_action_suggestion": "Continue",
                "detection_indicators": ["nmap"]
            }
            """

        if "executive summary" in prompt.lower():
            return "Summary content"

        if "security recommendations" in prompt.lower():
            return "[" + ", ".join(
                f"\"Recommendation {i}\"" for i in range(1, 6)
            ) + "]"

        return "{}"


class FakeVMOperator:
    def __init__(self):
        self.snapshots = []
        self.commands = []

    async def snapshot_vm(self, vm_id, name):
        self.snapshots.append((vm_id, name))

    async def execute_command(self, vm_id, command, timeout_seconds=60):
        self.commands.append((vm_id, command))
        stdout = "open ports found" if "nmap" in command else "command executed"
        return CommandResult(command=command, stdout=stdout, stderr="", exit_code=0, vm_id=vm_id)


@pytest.mark.asyncio
async def test_attack_agent_plan_and_execute_flow():
    agent = AIAttackAgent(FakeLLM(), FakeVMOperator())

    scenario = {"name": "Integration Scenario", "objectives": ["Discover services"]}
    target_info = {"ip_address": "10.0.100.10"}

    plan = await agent.plan_attack(scenario, target_info)

    assert plan.name == "Integration Plan"
    assert len(plan.steps) >= 4
    assert plan.steps[0].phase == AttackPhase.RECONNAISSANCE

    result = await agent.execute_attack(plan, attacker_vm="attacker", target_vms=["target"])

    assert result.success_rate >= 0
    assert result.action_count == len(plan.steps)
    assert result.executive_summary
    assert result.recommendations
