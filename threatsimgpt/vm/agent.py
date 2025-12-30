"""AI Attack Agent for autonomous VM-based attack simulation.

This module provides an AI agent that can autonomously plan and execute
attack simulations using LLMs for decision-making and VMs for execution.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AttackPlan,
    AttackStep,
    AttackPhase,
    AttackResult,
    AgentState,
    CommandResult,
)
from .operator import VMOperator
from .safety import VMSafetyController

logger = logging.getLogger(__name__)


# System prompt for attack planning
ATTACK_PLANNING_PROMPT = """You are an expert red team operator and penetration tester.
Your task is to create detailed, realistic attack plans for security testing.

IMPORTANT GUIDELINES:
1. All attacks are in ISOLATED LAB ENVIRONMENTS for authorized security testing
2. Follow MITRE ATT&CK framework for technique classification
3. Include specific, executable commands
4. Consider detection opportunities for blue team training
5. Plan for cleanup and evidence collection

You have access to standard offensive security tools on an Ubuntu attacker VM:
- nmap, masscan (scanning)
- metasploit-framework (exploitation)
- hydra, hashcat (password attacks)
- impacket, crackmapexec (Windows attacks)
- sqlmap, nikto (web attacks)
- proxychains, ssh (pivoting)
"""

COMMAND_REFINEMENT_PROMPT = """You are refining an attack command based on current state.
The command should be ready to execute without modification.

Current attack state:
- Compromised hosts: {compromised}
- Discovered services: {services}
- Collected credentials: {creds_count} sets
- Current phase: {phase}

Original command:
{command}

If the command needs IP addresses, ports, or credentials from discovered information,
substitute them. If no changes needed, return the original command.

Return ONLY the refined command, nothing else.
"""

RESULT_ANALYSIS_PROMPT = """Analyze the result of this attack step and decide next action.

Step executed:
- Phase: {phase}
- Technique: {technique}
- Description: {description}

Command output:
{output}

Exit code: {exit_code}

Current state:
- Compromised hosts: {compromised}
- Current objective: {objective}

Answer these questions in JSON format:
{{
    "step_successful": true/false,
    "findings": ["list of important findings"],
    "new_hosts_compromised": ["list of newly compromised hosts/IPs"],
    "new_credentials": [{{"username": "...", "password_hash": "...", "type": "..."}}],
    "new_services": [{{"host": "...", "port": ..., "service": "..."}}],
    "continue_attack": true/false,
    "next_action_suggestion": "brief description of what to do next",
    "detection_indicators": ["IOCs that defenders might see"]
}}
"""


class AIAttackAgent:
    """
    AI agent capable of planning and executing attacks on VMs.

    Uses LLM for:
    - Attack planning and strategy
    - Command generation and refinement
    - Result interpretation and adaptation
    - Report generation

    Example:
        from threatsimgpt.llm.manager import LLMManager
        from threatsimgpt.vm import VMOperator, AIAttackAgent

        llm = LLMManager()
        vm_op = VMOperator(config)
        agent = AIAttackAgent(llm, vm_op)

        # Create attack plan from scenario
        plan = await agent.plan_attack(scenario, target_info)

        # Execute the attack
        result = await agent.execute_attack(plan, "attacker-vm", ["target-vm"])
    """

    def __init__(
        self,
        llm_manager: Any,  # LLMManager from threatsimgpt.llm
        vm_operator: VMOperator,
        safety_controller: Optional[VMSafetyController] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize AI attack agent.

        Args:
            llm_manager: LLM manager for AI reasoning
            vm_operator: VM operator for command execution
            safety_controller: Safety controller for command validation
            config: Additional configuration
        """
        self.llm = llm_manager
        self.vm = vm_operator
        self.safety = safety_controller or VMSafetyController()
        self.config = config or {}

        self.state: Optional[AgentState] = None
        self.attack_log: List[Dict[str, Any]] = []
        self._current_plan: Optional[AttackPlan] = None

    async def plan_attack(
        self,
        scenario: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> AttackPlan:
        """
        Use LLM to create an attack plan based on scenario.

        Args:
            scenario: ThreatSimGPT scenario definition (from YAML template)
            target_info: Information about target environment

        Returns:
            AttackPlan with steps to execute
        """
        logger.info(f"Planning attack for scenario: {scenario.get('name', 'Unknown')}")

        planning_prompt = f"""{ATTACK_PLANNING_PROMPT}

SCENARIO:
{json.dumps(scenario, indent=2, default=str)}

TARGET ENVIRONMENT:
{json.dumps(target_info, indent=2, default=str)}

Create a detailed attack plan with the following JSON structure:
{{
    "name": "Attack plan name",
    "description": "Brief description of the attack",
    "objectives": ["objective1", "objective2"],
    "mitre_techniques": ["T1595", "T1566", ...],
    "steps": [
        {{
            "phase": "reconnaissance|initial_access|execution|...",
            "technique_id": "T1595.001",
            "technique_name": "Active Scanning: IP Blocks",
            "description": "What this step does",
            "commands": ["nmap -sV -p- 10.0.100.10"],
            "success_indicators": ["open ports found", "services identified"],
            "timeout_seconds": 300
        }}
    ],
    "success_criteria": ["criteria1", "criteria2"],
    "estimated_duration_minutes": 30
}}

Include 5-10 steps covering reconnaissance through objectives.
"""

        # Generate plan using LLM
        response = await self._generate_llm_response(planning_prompt)

        # Parse response
        try:
            plan_data = json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            plan_data = self._extract_json(response)

        # Build AttackPlan
        steps = []
        for step_data in plan_data.get("steps", []):
            phase_str = step_data.get("phase", "reconnaissance")
            try:
                phase = AttackPhase(phase_str.lower())
            except ValueError:
                phase = AttackPhase.EXECUTION

            steps.append(AttackStep(
                phase=phase,
                technique_id=step_data.get("technique_id", "T0000"),
                technique_name=step_data.get("technique_name", "Unknown"),
                description=step_data.get("description", ""),
                commands=step_data.get("commands", []),
                success_indicators=step_data.get("success_indicators", []),
                timeout_seconds=step_data.get("timeout_seconds", 300),
            ))

        plan = AttackPlan(
            name=plan_data.get("name", scenario.get("name", "Attack Plan")),
            description=plan_data.get("description", ""),
            steps=steps,
            objectives=plan_data.get("objectives", []),
            success_criteria=plan_data.get("success_criteria", []),
            timeout_minutes=plan_data.get("estimated_duration_minutes", 60),
            mitre_techniques=plan_data.get("mitre_techniques", []),
        )

        logger.info(f"Created attack plan with {len(steps)} steps")
        return plan

    async def execute_attack(
        self,
        plan: AttackPlan,
        attacker_vm: str,
        target_vms: List[str],
    ) -> AttackResult:
        """
        Execute the attack plan using VM infrastructure.

        Args:
            plan: Attack plan to execute
            attacker_vm: VM ID of attacker machine
            target_vms: List of target VM IDs

        Returns:
            AttackResult with execution results
        """
        logger.info(f"Starting attack execution: {plan.name}")

        # Initialize state
        self.state = AgentState(
            current_vm=attacker_vm,
            current_phase=AttackPhase.RECONNAISSANCE,
            current_objective=plan.objectives[0] if plan.objectives else "",
        )
        self._current_plan = plan
        self.attack_log = []

        plan.attacker_vm = attacker_vm
        plan.target_vms = target_vms

        start_time = datetime.utcnow()

        # Create snapshot before attack (for restoration)
        for vm_id in [attacker_vm] + target_vms:
            try:
                await self.vm.snapshot_vm(vm_id, f"pre-attack-{plan.plan_id[:8]}")
            except Exception as e:
                logger.warning(f"Failed to snapshot VM {vm_id}: {e}")

        # Execute each step
        for i, step in enumerate(plan.steps):
            logger.info(f"Executing step {i+1}/{len(plan.steps)}: {step.phase.value}")

            try:
                # Update state
                self.state.current_phase = step.phase

                # Execute the step
                step_result = await self._execute_step(step)

                # Log the action
                self._log_action(step, step_result)

                # Analyze result and adapt
                should_continue = await self._analyze_and_adapt(step, step_result)

                if not should_continue:
                    logger.info("Agent decided to stop attack")
                    break

                # Check timeout
                elapsed = (datetime.utcnow() - start_time).total_seconds() / 60
                if elapsed > plan.timeout_minutes:
                    self.state.errors.append("Attack timeout reached")
                    logger.warning(f"Attack timeout after {elapsed:.1f} minutes")
                    break

            except Exception as e:
                error_msg = f"Step failed: {step.phase.value} - {str(e)}"
                self.state.errors.append(error_msg)
                logger.error(error_msg)

                # Decide if we should continue
                if not await self._should_continue_after_error(step, e):
                    break

        # Generate final report
        return await self._generate_report(plan, start_time)

    async def run_single_command(
        self,
        command: str,
        vm_id: Optional[str] = None,
    ) -> CommandResult:
        """
        Run a single command (useful for interactive mode).

        Args:
            command: Command to execute
            vm_id: VM to run on (defaults to current VM in state)

        Returns:
            CommandResult
        """
        target_vm = vm_id or (self.state.current_vm if self.state else None)
        if not target_vm:
            raise ValueError("No VM specified and no active state")

        # Validate command safety
        is_safe, reason = self.safety.validate_command(command)
        if not is_safe:
            return CommandResult(
                command=command,
                stdout="",
                stderr=f"Command blocked by safety controller: {reason}",
                exit_code=-1,
                vm_id=target_vm,
            )

        return await self.vm.execute_command(target_vm, command)

    async def _execute_step(self, step: AttackStep) -> Dict[str, Any]:
        """Execute a single attack step."""
        results = {
            "phase": step.phase.value,
            "technique": step.technique_id,
            "commands_executed": [],
            "outputs": [],
            "success": False,
        }

        for command in step.commands:
            # Validate command safety
            is_safe, reason = self.safety.validate_command(command)
            if not is_safe:
                logger.warning(f"Command blocked: {reason}")
                results["commands_executed"].append({
                    "original": command,
                    "executed": None,
                    "blocked": True,
                    "reason": reason,
                })
                continue

            # Refine command based on current state
            refined_command = await self._refine_command(command)

            # Execute on attacker VM
            cmd_result = await self.vm.execute_command(
                self.state.current_vm,
                refined_command,
                timeout_seconds=step.timeout_seconds,
            )

            results["commands_executed"].append({
                "original": command,
                "executed": refined_command,
                "stdout": cmd_result.stdout[:5000],  # Truncate for context
                "stderr": cmd_result.stderr[:1000],
                "exit_code": cmd_result.exit_code,
            })

            results["outputs"].append(cmd_result.stdout)

            # Track in state
            self.state.command_history.append(cmd_result)

        # Check success indicators
        if step.success_indicators:
            results["success"] = await self._check_success_indicators(
                step.success_indicators,
                results["outputs"],
            )
        else:
            # If no indicators, consider successful if any command succeeded
            results["success"] = any(
                c.get("exit_code") == 0
                for c in results["commands_executed"]
                if not c.get("blocked")
            )

        # Update step
        step.executed = True
        step.success = results["success"]
        step.output = "\n".join(results["outputs"])

        return results

    async def _refine_command(self, command: str) -> str:
        """Use AI to refine command based on current state."""
        # If command already looks complete, don't refine
        if not any(placeholder in command for placeholder in ["TARGET", "IP", "HOST", "<"]):
            return command

        prompt = COMMAND_REFINEMENT_PROMPT.format(
            compromised=self.state.compromised_hosts,
            services=self.state.discovered_services[:5],  # Limit for context
            creds_count=len(self.state.collected_credentials),
            phase=self.state.current_phase.value,
            command=command,
        )

        response = await self._generate_llm_response(prompt)
        refined = response.strip()

        # Basic validation - should still look like a command
        if refined and len(refined) < 500 and not refined.startswith("{"):
            return refined

        return command

    async def _analyze_and_adapt(
        self,
        step: AttackStep,
        result: Dict[str, Any],
    ) -> bool:
        """Analyze step result and update state."""
        # Build output summary
        outputs = "\n\n".join(result.get("outputs", []))[:3000]

        prompt = RESULT_ANALYSIS_PROMPT.format(
            phase=step.phase.value,
            technique=step.technique_id,
            description=step.description,
            output=outputs,
            exit_code=result["commands_executed"][0].get("exit_code", -1) if result["commands_executed"] else -1,
            compromised=self.state.compromised_hosts,
            objective=self.state.current_objective,
        )

        response = await self._generate_llm_response(prompt)

        try:
            analysis = json.loads(response)
        except json.JSONDecodeError:
            analysis = self._extract_json(response)

        # Update state with findings
        for host in analysis.get("new_hosts_compromised", []):
            if host not in self.state.compromised_hosts:
                self.state.compromised_hosts.append(host)

        for cred in analysis.get("new_credentials", []):
            self.state.collected_credentials.append(cred)

        for service in analysis.get("new_services", []):
            self.state.discovered_services.append(service)

        # Log detection indicators
        if analysis.get("detection_indicators"):
            self.attack_log.append({
                "type": "detection_indicators",
                "step": step.technique_id,
                "indicators": analysis["detection_indicators"],
            })

        return analysis.get("continue_attack", True)

    async def _check_success_indicators(
        self,
        indicators: List[str],
        outputs: List[str],
    ) -> bool:
        """Check if success indicators are present in outputs."""
        combined_output = "\n".join(outputs).lower()

        # Simple keyword matching
        matches = 0
        for indicator in indicators:
            if indicator.lower() in combined_output:
                matches += 1

        # Consider successful if at least half of indicators match
        return matches >= len(indicators) / 2

    async def _should_continue_after_error(
        self,
        step: AttackStep,
        error: Exception,
    ) -> bool:
        """Decide if attack should continue after error."""
        # For now, simple heuristic - continue unless critical error
        error_str = str(error).lower()

        critical_errors = [
            "connection refused",
            "network unreachable",
            "vm not found",
            "authentication failed",
        ]

        for critical in critical_errors:
            if critical in error_str:
                return False

        return True

    async def _generate_report(
        self,
        plan: AttackPlan,
        start_time: datetime,
    ) -> AttackResult:
        """Generate comprehensive attack report."""
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()

        # Calculate success metrics
        completed_objectives = []
        for obj in plan.objectives:
            # Check if objective seems completed based on state
            obj_lower = obj.lower()
            if "compromise" in obj_lower and self.state.compromised_hosts:
                completed_objectives.append(obj)
            elif "credential" in obj_lower and self.state.collected_credentials:
                completed_objectives.append(obj)
            elif "discover" in obj_lower and self.state.discovered_services:
                completed_objectives.append(obj)

        success_rate = len(completed_objectives) / len(plan.objectives) if plan.objectives else 0

        result = AttackResult(
            plan_id=plan.plan_id,
            attack_name=plan.name,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            success=success_rate >= 0.5,
            objectives_completed=completed_objectives,
            objectives_total=len(plan.objectives),
            success_rate=success_rate,
            compromised_hosts=self.state.compromised_hosts,
            credentials_captured=len(self.state.collected_credentials),
            services_discovered=len(self.state.discovered_services),
            action_count=len(self.state.action_history),
            errors=self.state.errors,
            action_log=self.attack_log,
            mitre_techniques_used=[s.technique_id for s in plan.steps if s.executed],
        )

        # Generate executive summary using LLM
        result.executive_summary = await self._generate_summary(result)

        # Generate recommendations
        result.recommendations = await self._generate_recommendations(result)

        logger.info(f"Attack completed: {result.success_rate*100:.0f}% objectives achieved")
        return result

    async def _generate_summary(self, result: AttackResult) -> str:
        """Generate executive summary of attack."""
        prompt = f"""Generate a brief executive summary (2-3 paragraphs) of this security assessment.

Attack: {result.attack_name}
Duration: {result.duration_seconds/60:.1f} minutes
Success Rate: {result.success_rate*100:.0f}%
Hosts Compromised: {len(result.compromised_hosts)}
Credentials Captured: {result.credentials_captured}
Services Discovered: {result.services_discovered}
Techniques Used: {', '.join(result.mitre_techniques_used[:5])}
Errors: {len(result.errors)}

Write in professional security assessment style, suitable for executive briefing.
"""

        return await self._generate_llm_response(prompt)

    async def _generate_recommendations(self, result: AttackResult) -> List[str]:
        """Generate security recommendations based on attack."""
        prompt = f"""Based on this attack simulation, provide 5 specific security recommendations.

Attack Results:
- Compromised hosts: {result.compromised_hosts}
- Techniques used: {result.mitre_techniques_used}
- Success rate: {result.success_rate*100:.0f}%

Return as JSON array of strings: ["recommendation 1", "recommendation 2", ...]
"""

        response = await self._generate_llm_response(prompt)

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Parse as newline-separated
            return [line.strip("- ").strip() for line in response.split("\n") if line.strip()]

    def _log_action(self, step: AttackStep, result: Dict[str, Any]) -> None:
        """Log action to attack log."""
        self.attack_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "phase": step.phase.value,
            "technique_id": step.technique_id,
            "technique_name": step.technique_name,
            "success": result["success"],
            "vm": self.state.current_vm,
            "commands_count": len(result["commands_executed"]),
        })

        self.state.action_history.append({
            "step": {
                "phase": step.phase.value,
                "technique": step.technique_id,
            },
            "result": {
                "success": result["success"],
            },
        })

        self.state.last_action = datetime.utcnow()

    async def _generate_llm_response(self, prompt: str) -> str:
        """Generate LLM response, handling different manager interfaces."""
        try:
            # Try async generate method
            if hasattr(self.llm, "generate"):
                if asyncio.iscoroutinefunction(self.llm.generate):
                    return await self.llm.generate(prompt)
                else:
                    return self.llm.generate(prompt)

            # Try generate_content method
            if hasattr(self.llm, "generate_content"):
                result = await self.llm.generate_content(prompt)
                return result.content if hasattr(result, "content") else str(result)

            raise AttributeError("LLM manager has no generate method")

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return "{}"

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract JSON from text that may contain other content."""
        # Try to find JSON block
        import re

        # Look for ```json ... ``` blocks
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Look for { ... } blocks
        brace_match = re.search(r"\{[\s\S]*\}", text)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        return {}
