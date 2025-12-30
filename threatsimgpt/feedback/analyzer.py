"""
Quality Analyzers
=================

Analyze scenarios and playbooks to extract quality metrics
and learnings for the feedback loop.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    QualityMetrics,
    QualityDimension,
    ScenarioLearning,
    PlaybookLearning,
    ImprovementSuggestion,
    ImprovementCategory,
)

logger = logging.getLogger(__name__)


# MITRE ATT&CK technique patterns
TECHNIQUE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)


class QualityScorer:
    """
    Scores content quality across multiple dimensions.

    Uses both heuristic analysis and LLM-based evaluation.
    """

    # Indicators for different quality dimensions
    REALISM_INDICATORS = [
        'real-world', 'observed in the wild', 'actual incident',
        'case study', 'documented attack', 'threat intelligence',
        'APT', 'campaign', 'threat actor', 'IOC', 'indicator',
    ]

    ENGAGEMENT_INDICATORS = [
        'interactive', 'hands-on', 'exercise', 'simulation',
        'role-play', 'scenario-based', 'practical', 'drill',
    ]

    COMPLIANCE_FRAMEWORKS = [
        'NIST', 'ISO 27001', 'SOC 2', 'HIPAA', 'PCI-DSS',
        'GDPR', 'CCPA', 'FedRAMP', 'CMMC', 'CIS Controls',
    ]

    SECTORS = [
        'healthcare', 'finance', 'government', 'energy',
        'technology', 'retail', 'education', 'defense',
        'manufacturing', 'telecommunications',
    ]

    def __init__(self, llm_provider: Optional[Any] = None):
        self.llm = llm_provider

    async def score_content(
        self,
        content: str,
        content_type: str = "scenario",
        sector: Optional[str] = None
    ) -> QualityMetrics:
        """
        Score content across all quality dimensions.

        Args:
            content: The text content to analyze
            content_type: 'scenario' or 'playbook'
            sector: Target sector for relevance scoring

        Returns:
            QualityMetrics with all dimension scores
        """
        content_lower = content.lower()

        # Heuristic scoring
        realism = self._score_realism(content_lower)
        technique_coverage = self._score_technique_coverage(content)
        engagement = self._score_engagement(content_lower)
        compliance = self._score_compliance(content_lower)
        sector_relevance = self._score_sector_relevance(content_lower, sector)

        # Estimate other scores based on content analysis
        training_value = (realism + engagement + technique_coverage) / 3
        detection_difficulty = self._score_detection_difficulty(content_lower)
        temporal_relevance = self._score_temporal_relevance(content_lower)

        # If LLM available, enhance with AI scoring
        if self.llm:
            ai_scores = await self._llm_score(content, content_type)
            # Blend heuristic and AI scores
            realism = (realism + ai_scores.get('realism', realism)) / 2
            engagement = (engagement + ai_scores.get('engagement', engagement)) / 2
            training_value = (training_value + ai_scores.get('training_value', training_value)) / 2

        return QualityMetrics(
            realism_score=realism,
            technique_coverage=technique_coverage,
            engagement_score=engagement,
            training_value=training_value,
            detection_difficulty=detection_difficulty,
            compliance_alignment=compliance,
            sector_relevance=sector_relevance,
            temporal_relevance=temporal_relevance,
            evaluator="hybrid" if self.llm else "automated",
        )

    def _score_realism(self, content: str) -> float:
        """Score realism based on indicators."""
        score = 0.3  # Base score

        for indicator in self.REALISM_INDICATORS:
            if indicator in content:
                score += 0.07

        # Boost for specific threat actor mentions
        if re.search(r'apt\d+|fin\d+|lazarus|cozy bear|fancy bear', content):
            score += 0.15

        # Boost for IOC mentions
        if re.search(r'\b(?:hash|md5|sha256|domain|ip address|c2)\b', content):
            score += 0.1

        return min(score, 1.0)

    def _score_technique_coverage(self, content: str) -> float:
        """Score MITRE ATT&CK technique coverage."""
        techniques = TECHNIQUE_PATTERN.findall(content)
        unique_techniques = set(t.upper() for t in techniques)

        # Score based on number of techniques
        if len(unique_techniques) == 0:
            return 0.2
        elif len(unique_techniques) < 3:
            return 0.4
        elif len(unique_techniques) < 6:
            return 0.6
        elif len(unique_techniques) < 10:
            return 0.8
        else:
            return 0.95

    def _score_engagement(self, content: str) -> float:
        """Score engagement potential."""
        score = 0.3

        for indicator in self.ENGAGEMENT_INDICATORS:
            if indicator in content:
                score += 0.1

        # Boost for action-oriented language
        action_words = ['click', 'open', 'execute', 'run', 'download', 'install']
        for word in action_words:
            if word in content:
                score += 0.05

        return min(score, 1.0)

    def _score_compliance(self, content: str) -> float:
        """Score compliance framework alignment."""
        score = 0.2

        for framework in self.COMPLIANCE_FRAMEWORKS:
            if framework.lower() in content:
                score += 0.1

        return min(score, 1.0)

    def _score_sector_relevance(self, content: str, target_sector: Optional[str]) -> float:
        """Score sector-specific relevance."""
        if not target_sector:
            return 0.5  # Neutral if no target specified

        target = target_sector.lower()

        # Direct mention
        if target in content:
            score = 0.7
        else:
            score = 0.3

        # Sector-specific keywords
        sector_keywords = {
            'healthcare': ['patient', 'hipaa', 'ehr', 'medical', 'hospital', 'phi'],
            'finance': ['bank', 'transaction', 'pci', 'trading', 'account', 'swift'],
            'government': ['agency', 'classified', 'clearance', 'federal', 'citizen'],
            'energy': ['scada', 'ics', 'grid', 'utility', 'pipeline', 'power plant'],
            'retail': ['pos', 'customer', 'e-commerce', 'payment', 'inventory'],
        }

        if target in sector_keywords:
            for keyword in sector_keywords[target]:
                if keyword in content:
                    score += 0.05

        return min(score, 1.0)

    def _score_detection_difficulty(self, content: str) -> float:
        """Score how difficult the scenario is to detect."""
        score = 0.4

        evasion_indicators = [
            'evasion', 'bypass', 'evade', 'stealth', 'covert',
            'living off the land', 'lolbins', 'fileless',
            'obfuscation', 'encryption', 'encoded',
        ]

        for indicator in evasion_indicators:
            if indicator in content:
                score += 0.08

        return min(score, 1.0)

    def _score_temporal_relevance(self, content: str) -> float:
        """Score relevance to current threat landscape."""
        score = 0.5

        current_threats = [
            'ransomware', 'supply chain', 'zero-day', 'cloud',
            'kubernetes', 'container', 'api', 'ai', 'llm',
            'deepfake', 'mfa bypass', 'qr code', 'qrishing',
        ]

        for threat in current_threats:
            if threat in content:
                score += 0.06

        # Check for recent years
        if re.search(r'202[3-5]', content):
            score += 0.1

        return min(score, 1.0)

    async def _llm_score(self, content: str, content_type: str) -> Dict[str, float]:
        """Use LLM to score content quality."""
        prompt = f"""Analyze this {content_type} and rate it on a scale of 0-1 for:
1. Realism - How realistic and plausible is this?
2. Engagement - How engaging is this for training?
3. Training Value - How educational is this?

Content:
{content[:2000]}

Respond in JSON format:
{{"realism": 0.X, "engagement": 0.X, "training_value": 0.X}}
"""

        try:
            response = await self.llm.generate(prompt)
            import json
            scores = json.loads(response)
            return scores
        except Exception as e:
            logger.warning(f"LLM scoring failed: {e}")
            return {}


class PlaybookAnalyzer:
    """
    Analyzes playbooks to extract learnings for scenario improvement.

    Identifies defensive gaps, detection blind spots, and opportunities
    that can make future scenarios more effective.
    """

    def __init__(self, quality_scorer: Optional[QualityScorer] = None):
        self.scorer = quality_scorer or QualityScorer()

    async def analyze(
        self,
        playbook_id: str,
        playbook_content: str,
        sector: Optional[str] = None
    ) -> PlaybookLearning:
        """
        Analyze a playbook and extract learnings.

        Args:
            playbook_id: Unique identifier for the playbook
            playbook_content: Full playbook content
            sector: Target sector

        Returns:
            PlaybookLearning with extracted insights
        """
        content_lower = playbook_content.lower()

        # Extract defensive gaps
        defensive_gaps = self._find_defensive_gaps(content_lower)

        # Find detection blind spots
        blind_spots = self._find_detection_blind_spots(content_lower)

        # Identify response delays
        response_delays = self._find_response_delays(content_lower)

        # Analyze technique effectiveness
        technique_effectiveness = self._analyze_technique_effectiveness(playbook_content)

        # Find evasion opportunities
        evasion_techniques = self._find_evasion_opportunities(content_lower)

        # Timing opportunities
        timing_opportunities = self._find_timing_opportunities(content_lower)

        # Sector vulnerabilities
        sector_vulnerabilities = self._find_sector_vulnerabilities(content_lower, sector)

        # Compliance gaps
        compliance_gaps = self._find_compliance_gaps(content_lower)

        # Score the playbook
        metrics = await self.scorer.score_content(playbook_content, "playbook", sector)

        return PlaybookLearning(
            playbook_id=playbook_id,
            defensive_gaps=defensive_gaps,
            detection_blind_spots=blind_spots,
            response_delays=response_delays,
            technique_effectiveness=technique_effectiveness,
            evasion_techniques=evasion_techniques,
            timing_opportunities=timing_opportunities,
            sector_vulnerabilities=sector_vulnerabilities,
            compliance_gaps=compliance_gaps,
            metrics=metrics,
        )

    def _find_defensive_gaps(self, content: str) -> List[str]:
        """Identify defensive gaps mentioned in playbook."""
        gaps = []

        gap_patterns = [
            (r'lack[s]? (?:of )?(\w+ \w+)', 'Lacks {}'),
            (r'missing (\w+ \w+)', 'Missing {}'),
            (r'no (\w+ \w+) in place', 'No {} in place'),
            (r'limited (\w+ \w+)', 'Limited {}'),
            (r'insufficient (\w+ \w+)', 'Insufficient {}'),
        ]

        for pattern, template in gap_patterns:
            matches = re.findall(pattern, content)
            for match in matches[:3]:  # Limit per pattern
                gaps.append(template.format(match))

        return gaps[:10]

    def _find_detection_blind_spots(self, content: str) -> List[str]:
        """Find detection blind spots from playbook analysis."""
        blind_spots = []

        indicators = [
            'difficult to detect', 'evades detection', 'bypasses',
            'not monitored', 'limited visibility', 'blind spot',
            'unmonitored', 'no alerting', 'silent', 'stealthy',
        ]

        for indicator in indicators:
            if indicator in content:
                # Extract surrounding context
                idx = content.find(indicator)
                context = content[max(0, idx-50):idx+100]
                blind_spots.append(f"Blind spot: {context.strip()[:100]}")

        return blind_spots[:5]

    def _find_response_delays(self, content: str) -> List[str]:
        """Identify response time vulnerabilities."""
        delays = []

        time_patterns = [
            (r'(\d+)\s*(?:hour|hr)s?\s*(?:to|before|until)', 'Response delay: {} hours'),
            (r'(\d+)\s*(?:day)s?\s*(?:to|before|until)', 'Response delay: {} days'),
            (r'delayed?\s*(?:by\s*)?(\d+)', 'Delayed response: {} time units'),
        ]

        for pattern, template in time_patterns:
            matches = re.findall(pattern, content)
            for match in matches[:2]:
                delays.append(template.format(match))

        return delays

    def _analyze_technique_effectiveness(self, content: str) -> Dict[str, float]:
        """Analyze which techniques are most/least effective based on playbook."""
        techniques = TECHNIQUE_PATTERN.findall(content)
        effectiveness = {}

        content_lower = content.lower()

        for tech in set(techniques):
            tech = tech.upper()

            # Look for effectiveness indicators near technique mentions
            score = 0.5  # Neutral default

            # Positive effectiveness indicators
            if any(ind in content_lower for ind in ['effective', 'successful', 'worked']):
                score += 0.2

            # Negative effectiveness indicators
            if any(ind in content_lower for ind in ['blocked', 'detected', 'prevented']):
                score -= 0.2

            effectiveness[tech] = max(0.1, min(0.9, score))

        return effectiveness

    def _find_evasion_opportunities(self, content: str) -> List[str]:
        """Find techniques that could evade defenses mentioned."""
        opportunities = []

        evasion_patterns = [
            'bypass', 'evade', 'circumvent', 'avoid detection',
            'living off the land', 'legitimate tool', 'native',
        ]

        for pattern in evasion_patterns:
            if pattern in content:
                opportunities.append(f"Potential evasion: {pattern}")

        return opportunities

    def _find_timing_opportunities(self, content: str) -> List[str]:
        """Identify timing-based opportunities."""
        opportunities = []

        timing_indicators = [
            ('after hours', 'Attack during off-hours when monitoring reduced'),
            ('weekend', 'Weekend attacks face slower response'),
            ('holiday', 'Holiday periods have reduced staffing'),
            ('maintenance window', 'Maintenance windows provide cover'),
            ('backup', 'During backup operations'),
        ]

        for indicator, opportunity in timing_indicators:
            if indicator in content:
                opportunities.append(opportunity)

        return opportunities

    def _find_sector_vulnerabilities(
        self,
        content: str,
        sector: Optional[str]
    ) -> Dict[str, List[str]]:
        """Find sector-specific vulnerabilities."""
        vulnerabilities: Dict[str, List[str]] = {}

        sector_vulns = {
            'healthcare': ['legacy systems', 'medical devices', 'phi exposure', 'hipaa gaps'],
            'finance': ['swift', 'trading platform', 'customer data', 'transaction fraud'],
            'government': ['legacy infrastructure', 'clearance process', 'contractor access'],
            'energy': ['scada', 'ics', 'remote access', 'vendor connections'],
        }

        for sec, vulns in sector_vulns.items():
            found = []
            for vuln in vulns:
                if vuln in content:
                    found.append(vuln)
            if found:
                vulnerabilities[sec] = found

        return vulnerabilities

    def _find_compliance_gaps(self, content: str) -> List[str]:
        """Find compliance-related gaps."""
        gaps = []

        compliance_issues = [
            ('not compliant', 'Non-compliance identified'),
            ('audit finding', 'Audit findings to exploit'),
            ('policy violation', 'Policy violations as entry points'),
            ('exception', 'Security exceptions to leverage'),
        ]

        for indicator, gap in compliance_issues:
            if indicator in content:
                gaps.append(gap)

        return gaps


class ScenarioAnalyzer:
    """
    Analyzes scenarios to extract learnings for playbook improvement.
    """

    def __init__(self, quality_scorer: Optional[QualityScorer] = None):
        self.scorer = quality_scorer or QualityScorer()

    async def analyze(
        self,
        scenario_id: str,
        scenario_content: str,
        sector: Optional[str] = None,
        simulation_results: Optional[Dict[str, Any]] = None
    ) -> ScenarioLearning:
        """
        Analyze a scenario and extract learnings.

        Args:
            scenario_id: Unique identifier
            scenario_content: Full scenario content
            sector: Target sector
            simulation_results: Results from running the simulation

        Returns:
            ScenarioLearning with extracted insights
        """
        # Extract effective techniques
        effective_techniques = self._extract_effective_techniques(
            scenario_content,
            simulation_results
        )

        # Extract successful narratives
        successful_narratives = self._extract_narratives(scenario_content)

        # Identify engagement patterns
        engagement_patterns = self._identify_engagement_patterns(scenario_content)

        # Extract sector insights
        sector_insights = self._extract_sector_insights(scenario_content, sector)

        # Identify success factors
        success_factors = self._identify_success_factors(
            scenario_content,
            simulation_results
        )

        # Determine applicable contexts
        applicable_sectors = self._determine_applicable_sectors(scenario_content)
        applicable_threats = self._determine_applicable_threats(scenario_content)

        # Score the scenario
        metrics = await self.scorer.score_content(scenario_content, "scenario", sector)

        return ScenarioLearning(
            scenario_id=scenario_id,
            effective_techniques=effective_techniques,
            successful_narratives=successful_narratives,
            engagement_patterns=engagement_patterns,
            sector_insights=sector_insights,
            success_factors=success_factors,
            applicable_sectors=applicable_sectors,
            applicable_threat_types=applicable_threats,
            metrics=metrics,
        )

    def _extract_effective_techniques(
        self,
        content: str,
        results: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Extract techniques that were effective."""
        techniques = TECHNIQUE_PATTERN.findall(content)

        # If we have simulation results, filter by success
        if results and 'successful_techniques' in results:
            return results['successful_techniques']

        return list(set(t.upper() for t in techniques))

    def _extract_narratives(self, content: str) -> List[str]:
        """Extract narrative elements that work well."""
        narratives = []

        # Look for story elements
        narrative_patterns = [
            r'(?:the attacker|threat actor).*?(?:\.|$)',
            r'(?:pretending to be|impersonating).*?(?:\.|$)',
            r'(?:urgent|immediate|critical).*?(?:\.|$)',
        ]

        for pattern in narrative_patterns:
            matches = re.findall(pattern, content.lower())
            narratives.extend(matches[:2])

        return narratives[:5]

    def _identify_engagement_patterns(self, content: str) -> List[str]:
        """Identify patterns that drive engagement."""
        patterns = []

        engagement_elements = [
            ('urgency', 'Creates sense of urgency'),
            ('authority', 'Leverages authority figure'),
            ('fear', 'Uses fear motivation'),
            ('curiosity', 'Exploits curiosity'),
            ('reward', 'Offers reward/incentive'),
            ('social proof', 'Uses social proof'),
        ]

        content_lower = content.lower()
        for keyword, pattern in engagement_elements:
            if keyword in content_lower:
                patterns.append(pattern)

        return patterns

    def _extract_sector_insights(
        self,
        content: str,
        sector: Optional[str]
    ) -> Dict[str, Any]:
        """Extract sector-specific insights."""
        insights: Dict[str, Any] = {}

        content_lower = content.lower()

        # Industry-specific elements
        if sector:
            insights['target_sector'] = sector

            # Check for sector-specific elements
            sector_elements = {
                'healthcare': ['patient', 'hipaa', 'medical', 'ehr'],
                'finance': ['transaction', 'wire', 'account', 'trading'],
                'government': ['classified', 'clearance', 'agency'],
            }

            if sector.lower() in sector_elements:
                found = [e for e in sector_elements[sector.lower()] if e in content_lower]
                insights['sector_elements_used'] = found

        return insights

    def _identify_success_factors(
        self,
        content: str,
        results: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Identify what made the scenario successful."""
        factors = []

        # Check for common success factors
        success_indicators = [
            ('credential', 'Credential harvesting'),
            ('click', 'User interaction achieved'),
            ('download', 'Payload delivery'),
            ('execute', 'Code execution'),
            ('access', 'Access obtained'),
        ]

        content_lower = content.lower()
        for keyword, factor in success_indicators:
            if keyword in content_lower:
                factors.append(factor)

        # Add from simulation results
        if results:
            if results.get('success_rate', 0) > 0.5:
                factors.append(f"High success rate: {results['success_rate']:.0%}")

        return factors

    def _determine_applicable_sectors(self, content: str) -> List[str]:
        """Determine which sectors this scenario applies to."""
        sectors = []
        content_lower = content.lower()

        sector_keywords = {
            'healthcare': ['patient', 'hospital', 'medical', 'health'],
            'finance': ['bank', 'payment', 'trading', 'financial'],
            'government': ['government', 'federal', 'agency', 'public sector'],
            'energy': ['utility', 'power', 'energy', 'grid'],
            'technology': ['tech', 'software', 'saas', 'cloud'],
            'retail': ['retail', 'store', 'customer', 'e-commerce'],
        }

        for sector, keywords in sector_keywords.items():
            if any(kw in content_lower for kw in keywords):
                sectors.append(sector)

        return sectors if sectors else ['general']

    def _determine_applicable_threats(self, content: str) -> List[str]:
        """Determine applicable threat types."""
        threats = []
        content_lower = content.lower()

        threat_keywords = {
            'phishing': ['phish', 'email', 'credential'],
            'ransomware': ['ransom', 'encrypt', 'decrypt'],
            'apt': ['apt', 'advanced persistent', 'nation-state'],
            'insider': ['insider', 'employee', 'internal'],
            'supply_chain': ['supply chain', 'vendor', 'third-party'],
            'social_engineering': ['social engineer', 'pretexting', 'vishing'],
        }

        for threat, keywords in threat_keywords.items():
            if any(kw in content_lower for kw in keywords):
                threats.append(threat)

        return threats if threats else ['general']
