"""
Enhancement Engines
===================

Uses learnings from the feedback loop to enhance
scenarios and playbooks, creating continuous improvement.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    ScenarioLearning,
    PlaybookLearning,
    ImprovementSuggestion,
    ImprovementCategory,
    QualityMetrics,
    QualityDimension,
)

logger = logging.getLogger(__name__)


# MITRE ATT&CK technique database (subset for enhancement)
TECHNIQUE_DATABASE = {
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "subtechniques": ["T1566.001", "T1566.002", "T1566.003"]},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access", "related": ["T1204.002"]},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access", "related": ["T1204.001"]},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence", "subtechniques": ["T1078.001", "T1078.002", "T1078.003"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "subtechniques": ["T1059.001", "T1059.003", "T1059.005"]},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "subtechniques": ["T1055.001", "T1055.012"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "related": ["T1490"]},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "subtechniques": ["T1071.001", "T1071.004"]},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "subtechniques": ["T1110.001", "T1110.003", "T1110.004"]},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence", "related": ["T1136"]},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "subtechniques": ["T1003.001", "T1003.002"]},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "subtechniques": ["T1021.001", "T1021.002", "T1021.006"]},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "subtechniques": ["T1562.001", "T1562.004"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "subtechniques": ["T1027.001", "T1027.010"]},
}


class TechniqueMapper:
    """
    Maps and suggests MITRE ATT&CK techniques for enhancement.
    """

    def __init__(self):
        self.technique_db = TECHNIQUE_DATABASE

    def get_related_techniques(self, technique_id: str) -> List[str]:
        """Get techniques related to the given one."""
        technique = self.technique_db.get(technique_id.upper(), {})
        related = []

        # Get subtechniques
        if "subtechniques" in technique:
            related.extend(technique["subtechniques"])

        # Get related techniques
        if "related" in technique:
            related.extend(technique["related"])

        # Get techniques from same tactic
        if "tactic" in technique:
            tactic = technique["tactic"]
            for tid, tdata in self.technique_db.items():
                if tdata.get("tactic") == tactic and tid != technique_id:
                    related.append(tid)

        return list(set(related))[:5]

    def suggest_technique_chain(
        self,
        current_techniques: List[str],
        target_objective: str = "data_exfiltration"
    ) -> List[str]:
        """
        Suggest a chain of techniques to achieve an objective.

        Builds a realistic attack chain based on current techniques.
        """
        chains = {
            "data_exfiltration": ["T1566", "T1204", "T1059", "T1003", "T1048"],
            "ransomware": ["T1566", "T1059", "T1078", "T1021", "T1486"],
            "persistence": ["T1566", "T1059", "T1078", "T1098", "T1053"],
            "credential_theft": ["T1566", "T1204", "T1059", "T1003", "T1110"],
        }

        base_chain = chains.get(target_objective, chains["data_exfiltration"])

        # Add techniques not already present
        suggestions = []
        current_set = set(t.upper() for t in current_techniques)

        for tech in base_chain:
            if tech not in current_set:
                suggestions.append(tech)

        return suggestions[:3]

    def get_evasion_techniques(self, detection_methods: List[str]) -> List[str]:
        """Suggest evasion techniques based on known detections."""
        evasion_map = {
            "antivirus": ["T1027", "T1055", "T1562.001"],
            "edr": ["T1055.012", "T1562.001", "T1027.010"],
            "firewall": ["T1071.001", "T1071.004", "T1572"],
            "siem": ["T1070", "T1027", "T1036"],
            "email_filter": ["T1566.003", "T1566.002", "T1204.001"],
        }

        suggestions = []
        for method in detection_methods:
            method_lower = method.lower()
            for key, techniques in evasion_map.items():
                if key in method_lower:
                    suggestions.extend(techniques)

        return list(set(suggestions))[:5]


class ScenarioEnhancer:
    """
    Enhances scenarios using learnings from playbooks.

    Uses playbook analysis to make scenarios more realistic,
    harder to detect, and more effective for training.
    """

    def __init__(self, llm_provider: Optional[Any] = None):
        self.llm = llm_provider
        self.technique_mapper = TechniqueMapper()

    async def enhance(
        self,
        scenario_content: str,
        playbook_learnings: List[PlaybookLearning],
        target_improvements: Optional[List[QualityDimension]] = None,
        sector: Optional[str] = None
    ) -> Tuple[str, List[ImprovementSuggestion]]:
        """
        Enhance a scenario based on playbook learnings.

        Args:
            scenario_content: Original scenario content
            playbook_learnings: Learnings from analyzed playbooks
            target_improvements: Specific dimensions to improve
            sector: Target sector

        Returns:
            Tuple of (enhanced_content, applied_suggestions)
        """
        suggestions = []

        # Generate improvement suggestions
        for learning in playbook_learnings:
            suggestions.extend(
                self._generate_suggestions_from_learning(
                    scenario_content, learning, sector
                )
            )

        # Filter by target dimensions if specified
        if target_improvements:
            suggestions = [
                s for s in suggestions
                if any(dim in s.affected_dimensions for dim in target_improvements)
            ]

        # Sort by priority and expected improvement
        suggestions.sort(
            key=lambda s: (s.priority, s.expected_improvement),
            reverse=True
        )

        # Apply top suggestions
        enhanced_content = scenario_content
        applied = []

        for suggestion in suggestions[:5]:  # Apply top 5
            try:
                enhanced_content = await self._apply_suggestion(
                    enhanced_content,
                    suggestion
                )
                suggestion.status = "applied"
                suggestion.applied_at = datetime.utcnow()
                applied.append(suggestion)
            except Exception as e:
                logger.warning(f"Failed to apply suggestion: {e}")
                suggestion.status = "failed"

        return enhanced_content, applied

    def _generate_suggestions_from_learning(
        self,
        scenario: str,
        learning: PlaybookLearning,
        sector: Optional[str]
    ) -> List[ImprovementSuggestion]:
        """Generate improvement suggestions from a single learning."""
        suggestions = []

        # Exploit defensive gaps
        for gap in learning.defensive_gaps[:3]:
            suggestions.append(ImprovementSuggestion(
                target_type="scenario",
                category=ImprovementCategory.REALISM_BOOST,
                title=f"Exploit: {gap[:50]}",
                description=f"Modify scenario to exploit the defensive gap: {gap}",
                suggested_changes=[f"Add attack vector targeting: {gap}"],
                expected_improvement=0.1,
                affected_dimensions=[QualityDimension.REALISM, QualityDimension.DETECTION_DIFFICULTY],
                source_type="automated",
                source_id=learning.id,
                priority=7,
            ))

        # Leverage detection blind spots
        for blind_spot in learning.detection_blind_spots[:2]:
            suggestions.append(ImprovementSuggestion(
                target_type="scenario",
                category=ImprovementCategory.DETECTION_EVASION,
                title=f"Use blind spot: {blind_spot[:40]}",
                description=f"Route attack through detection blind spot: {blind_spot}",
                suggested_changes=[f"Modify attack path to use: {blind_spot}"],
                expected_improvement=0.15,
                affected_dimensions=[QualityDimension.DETECTION_DIFFICULTY],
                source_type="automated",
                source_id=learning.id,
                priority=8,
            ))

        # Add evasion techniques
        for evasion in learning.evasion_techniques[:2]:
            suggestions.append(ImprovementSuggestion(
                target_type="scenario",
                category=ImprovementCategory.DETECTION_EVASION,
                title=f"Add evasion: {evasion}",
                description=f"Incorporate evasion technique: {evasion}",
                techniques_to_add=self.technique_mapper.get_evasion_techniques([evasion]),
                expected_improvement=0.1,
                affected_dimensions=[QualityDimension.DETECTION_DIFFICULTY, QualityDimension.REALISM],
                source_type="automated",
                source_id=learning.id,
                priority=6,
            ))

        # Exploit timing opportunities
        for timing in learning.timing_opportunities[:2]:
            suggestions.append(ImprovementSuggestion(
                target_type="scenario",
                category=ImprovementCategory.REALISM_BOOST,
                title=f"Timing: {timing[:40]}",
                description=f"Time the attack to exploit: {timing}",
                suggested_changes=[f"Set attack timing for: {timing}"],
                expected_improvement=0.08,
                affected_dimensions=[QualityDimension.REALISM],
                source_type="automated",
                source_id=learning.id,
                priority=5,
            ))

        # Sector-specific vulnerabilities
        if sector and sector.lower() in learning.sector_vulnerabilities:
            for vuln in learning.sector_vulnerabilities[sector.lower()][:2]:
                suggestions.append(ImprovementSuggestion(
                    target_type="scenario",
                    category=ImprovementCategory.SECTOR_CUSTOMIZATION,
                    title=f"Sector vuln: {vuln}",
                    description=f"Target {sector}-specific vulnerability: {vuln}",
                    suggested_changes=[f"Add {sector}-specific attack targeting {vuln}"],
                    expected_improvement=0.12,
                    affected_dimensions=[QualityDimension.SECTOR_RELEVANCE, QualityDimension.REALISM],
                    source_type="automated",
                    source_id=learning.id,
                    priority=8,
                ))

        # Add techniques based on effectiveness
        for tech, effectiveness in learning.technique_effectiveness.items():
            if effectiveness < 0.4:  # Low detection = good for scenarios
                suggestions.append(ImprovementSuggestion(
                    target_type="scenario",
                    category=ImprovementCategory.TECHNIQUE_ADDITION,
                    title=f"Add technique: {tech}",
                    description=f"Add {tech} which has low detection rate ({effectiveness:.0%})",
                    techniques_to_add=[tech] + self.technique_mapper.get_related_techniques(tech),
                    expected_improvement=0.1,
                    affected_dimensions=[QualityDimension.TECHNIQUE_COVERAGE, QualityDimension.DETECTION_DIFFICULTY],
                    source_type="automated",
                    source_id=learning.id,
                    priority=6,
                ))

        return suggestions

    async def _apply_suggestion(
        self,
        content: str,
        suggestion: ImprovementSuggestion
    ) -> str:
        """Apply a suggestion to the scenario content."""

        # If we have an LLM, use it for intelligent enhancement
        if self.llm:
            return await self._llm_enhance(content, suggestion)

        # Otherwise, use heuristic enhancement
        return self._heuristic_enhance(content, suggestion)

    async def _llm_enhance(
        self,
        content: str,
        suggestion: ImprovementSuggestion
    ) -> str:
        """Use LLM to apply enhancement."""
        prompt = f"""Enhance this threat scenario based on the following improvement:

IMPROVEMENT: {suggestion.title}
DESCRIPTION: {suggestion.description}
CHANGES TO MAKE: {', '.join(suggestion.suggested_changes)}
TECHNIQUES TO ADD: {', '.join(suggestion.techniques_to_add) if suggestion.techniques_to_add else 'None'}

ORIGINAL SCENARIO:
{content}

Generate an enhanced version that incorporates the improvement while maintaining the original structure and intent. Only output the enhanced scenario, no explanations."""

        try:
            enhanced = await self.llm.generate(prompt)
            return enhanced
        except Exception as e:
            logger.warning(f"LLM enhancement failed: {e}")
            return self._heuristic_enhance(content, suggestion)

    def _heuristic_enhance(
        self,
        content: str,
        suggestion: ImprovementSuggestion
    ) -> str:
        """Apply heuristic enhancement without LLM."""
        enhanced = content

        # Add techniques to content
        if suggestion.techniques_to_add:
            technique_text = f"\n\n**Additional Techniques:** {', '.join(suggestion.techniques_to_add)}"
            enhanced += technique_text

        # Add suggested changes as notes
        if suggestion.suggested_changes:
            changes_text = f"\n\n**Enhancement:** {suggestion.title}\n"
            changes_text += "\n".join(f"- {change}" for change in suggestion.suggested_changes)
            enhanced += changes_text

        return enhanced


class PlaybookEnhancer:
    """
    Enhances playbooks using learnings from scenarios.

    Uses scenario analysis to make playbooks more comprehensive,
    better aligned with real threats, and more actionable.
    """

    def __init__(self, llm_provider: Optional[Any] = None):
        self.llm = llm_provider
        self.technique_mapper = TechniqueMapper()

    async def enhance(
        self,
        playbook_content: str,
        scenario_learnings: List[ScenarioLearning],
        target_improvements: Optional[List[QualityDimension]] = None,
        sector: Optional[str] = None
    ) -> Tuple[str, List[ImprovementSuggestion]]:
        """
        Enhance a playbook based on scenario learnings.

        Args:
            playbook_content: Original playbook content
            scenario_learnings: Learnings from analyzed scenarios
            target_improvements: Specific dimensions to improve
            sector: Target sector

        Returns:
            Tuple of (enhanced_content, applied_suggestions)
        """
        suggestions = []

        # Generate improvement suggestions
        for learning in scenario_learnings:
            suggestions.extend(
                self._generate_suggestions_from_learning(
                    playbook_content, learning, sector
                )
            )

        # Filter by target dimensions
        if target_improvements:
            suggestions = [
                s for s in suggestions
                if any(dim in s.affected_dimensions for dim in target_improvements)
            ]

        # Sort by priority
        suggestions.sort(key=lambda s: (s.priority, s.expected_improvement), reverse=True)

        # Apply top suggestions
        enhanced_content = playbook_content
        applied = []

        for suggestion in suggestions[:5]:
            try:
                enhanced_content = await self._apply_suggestion(
                    enhanced_content,
                    suggestion
                )
                suggestion.status = "applied"
                suggestion.applied_at = datetime.utcnow()
                applied.append(suggestion)
            except Exception as e:
                logger.warning(f"Failed to apply suggestion: {e}")

        return enhanced_content, applied

    def _generate_suggestions_from_learning(
        self,
        playbook: str,
        learning: ScenarioLearning,
        sector: Optional[str]
    ) -> List[ImprovementSuggestion]:
        """Generate improvement suggestions from scenario learning."""
        suggestions = []

        # Add detection for effective techniques
        for technique in learning.effective_techniques[:3]:
            suggestions.append(ImprovementSuggestion(
                target_type="playbook",
                category=ImprovementCategory.TECHNICAL_DEPTH,
                title=f"Add detection for {technique}",
                description=f"Add detection rules for technique {technique} which was effective in scenarios",
                techniques_to_add=[technique],
                expected_improvement=0.1,
                affected_dimensions=[QualityDimension.TECHNIQUE_COVERAGE],
                source_type="automated",
                source_id=learning.id,
                priority=8,
            ))

        # Counter engagement patterns
        for pattern in learning.engagement_patterns[:2]:
            suggestions.append(ImprovementSuggestion(
                target_type="playbook",
                category=ImprovementCategory.NARRATIVE_ENHANCEMENT,
                title=f"Counter: {pattern}",
                description=f"Add training content to counter engagement pattern: {pattern}",
                narratives_to_enhance=[f"Recognition and response to {pattern}"],
                expected_improvement=0.08,
                affected_dimensions=[QualityDimension.TRAINING_VALUE],
                source_type="automated",
                source_id=learning.id,
                priority=6,
            ))

        # Address success factors
        for factor in learning.success_factors[:2]:
            suggestions.append(ImprovementSuggestion(
                target_type="playbook",
                category=ImprovementCategory.TECHNICAL_DEPTH,
                title=f"Mitigate: {factor[:30]}",
                description=f"Add mitigation for scenario success factor: {factor}",
                suggested_changes=[f"Add detection/prevention for: {factor}"],
                expected_improvement=0.12,
                affected_dimensions=[QualityDimension.REALISM, QualityDimension.TRAINING_VALUE],
                source_type="automated",
                source_id=learning.id,
                priority=7,
            ))

        # Sector-specific enhancements
        if sector and sector.lower() in learning.applicable_sectors:
            insights = learning.sector_insights.get('sector_elements_used', [])
            for element in insights[:2]:
                suggestions.append(ImprovementSuggestion(
                    target_type="playbook",
                    category=ImprovementCategory.SECTOR_CUSTOMIZATION,
                    title=f"Add {sector} defense for {element}",
                    description=f"Add {sector}-specific defense for: {element}",
                    suggested_changes=[f"Add {sector} defensive procedure for {element}"],
                    expected_improvement=0.1,
                    affected_dimensions=[QualityDimension.SECTOR_RELEVANCE],
                    source_type="automated",
                    source_id=learning.id,
                    priority=7,
                ))

        # Add coverage for applicable threats
        for threat in learning.applicable_threat_types[:2]:
            suggestions.append(ImprovementSuggestion(
                target_type="playbook",
                category=ImprovementCategory.TECHNICAL_DEPTH,
                title=f"Expand {threat} coverage",
                description=f"Expand playbook coverage for threat type: {threat}",
                suggested_changes=[f"Add detection and response procedures for {threat}"],
                expected_improvement=0.1,
                affected_dimensions=[QualityDimension.TECHNIQUE_COVERAGE, QualityDimension.TRAINING_VALUE],
                source_type="automated",
                source_id=learning.id,
                priority=6,
            ))

        return suggestions

    async def _apply_suggestion(
        self,
        content: str,
        suggestion: ImprovementSuggestion
    ) -> str:
        """Apply suggestion to playbook content."""
        if self.llm:
            return await self._llm_enhance(content, suggestion)
        return self._heuristic_enhance(content, suggestion)

    async def _llm_enhance(
        self,
        content: str,
        suggestion: ImprovementSuggestion
    ) -> str:
        """Use LLM to apply enhancement."""
        prompt = f"""Enhance this security playbook based on the following improvement:

IMPROVEMENT: {suggestion.title}
DESCRIPTION: {suggestion.description}
CHANGES TO MAKE: {', '.join(suggestion.suggested_changes)}
TECHNIQUES TO COVER: {', '.join(suggestion.techniques_to_add) if suggestion.techniques_to_add else 'None'}

ORIGINAL PLAYBOOK:
{content}

Generate an enhanced version that incorporates the improvement while maintaining the original structure. Only output the enhanced playbook, no explanations."""

        try:
            enhanced = await self.llm.generate(prompt)
            return enhanced
        except Exception as e:
            logger.warning(f"LLM enhancement failed: {e}")
            return self._heuristic_enhance(content, suggestion)

    def _heuristic_enhance(
        self,
        content: str,
        suggestion: ImprovementSuggestion
    ) -> str:
        """Apply heuristic enhancement."""
        enhanced = content

        # Add detection section for techniques
        if suggestion.techniques_to_add:
            detection_text = f"\n\n## Detection: {suggestion.title}\n"
            detection_text += f"{suggestion.description}\n\n"
            detection_text += "### Techniques to Monitor:\n"
            for tech in suggestion.techniques_to_add:
                detection_text += f"- {tech}: Monitor for indicators of this technique\n"
            enhanced += detection_text

        # Add enhancement notes
        if suggestion.suggested_changes:
            changes_text = f"\n\n## Enhancement: {suggestion.title}\n"
            for change in suggestion.suggested_changes:
                changes_text += f"- {change}\n"
            enhanced += changes_text

        return enhanced
