"""VM-based attack simulation module for ThreatSimGPT.

This module provides AI-controlled virtual machine capabilities for executing
realistic attack simulations in isolated environments.

Key Components:
    - VMOperator: Interface for controlling VMs (SSH, commands, files)
    - AIAttackAgent: AI agent that plans and executes attacks
    - VMSafetyController: Safety controls for attack simulations

Example Usage:
    from threatsimgpt.vm import VMOperator, AIAttackAgent
    from threatsimgpt.llm.manager import LLMManager

    # Initialize components
    vm_operator = VMOperator(config)
    llm_manager = LLMManager()
    agent = AIAttackAgent(llm_manager, vm_operator)

    # Run attack simulation
    result = await agent.run_attack_scenario(scenario)
"""

from .models import (
    VMConfig,
    VMInfo,
    VMState,
    CommandResult,
    AttackPlan,
    AttackResult,
    AgentState,
)
from .operator import VMOperator
from .agent import AIAttackAgent
from .safety import VMSafetyController

__all__ = [
    "VMConfig",
    "VMInfo",
    "VMState",
    "CommandResult",
    "AttackPlan",
    "AttackResult",
    "AgentState",
    "VMOperator",
    "AIAttackAgent",
    "VMSafetyController",
]
