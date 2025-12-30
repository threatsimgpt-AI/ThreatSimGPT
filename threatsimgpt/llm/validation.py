"""Content validation and safety filtering for ThreatSimGPT.

This module provides comprehensive validation of generated content,
including safety checks, quality assessment, and compliance verification.
"""

import re
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum

from .models import ContentType, PromptContext

logger = logging.getLogger(__name__)


class SafetyLevel(str, Enum):
    """Safety levels for content validation."""
    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"


@dataclass
class SafetyResult:
    """Result of safety validation."""
    passed: bool
    issues: List[str]
    compliance_flags: List[str]
    safety_score: float  # 0.0 to 1.0, higher is safer
    recommendations: List[str]


@dataclass
class QualityResult:
    """Result of content quality assessment."""
    quality_score: float  # 0.0 to 1.0, higher is better quality
    realism_score: float  # 0.0 to 1.0, higher is more realistic
    effectiveness_score: float  # 0.0 to 1.0, higher predicted effectiveness
    issues: List[str]
    suggestions: List[str]


class SafetyFilter:
    """Safety filter for generated threat simulation content."""

    # Prohibited content patterns (case-insensitive)
    PROHIBITED_PATTERNS = {
        # Actual malicious content
        r'\bdownload\s+and\s+install\b.*\.(exe|bat|scr|com|pif)',
        r'\bclick\s+here\s+to\s+claim\b.*\$\d+',
        r'\byour\s+account\s+will\s+be\s+closed\b.*\bimmediately\b',

        # Real credentials or systems
        r'\bpassword\s*:\s*\w+',
        r'\busername\s*:\s*\w+',
        r'real\s+bank\s+account',
        r'actual\s+credit\s+card',

        # Harmful instructions
        r'\bdelete\s+all\s+files\b',
        r'\bformat\s+hard\s+drive\b',
        r'\bdisable\s+antivirus\b',

        # Inappropriate content
        r'\bexplicit\s+sexual\b',
        r'\bviolent\s+threats\b',
        r'\bhate\s+speech\b',
    }

    # Required educational markers
    REQUIRED_EDUCATIONAL_MARKERS = {
        ContentType.EMAIL_PHISHING: [
            r'training',
            r'simulation',
            r'educational',
            r'security\s+awareness'
        ],
        ContentType.SMS_PHISHING: [
            r'training',
            r'test',
            r'simulation'
        ],
        ContentType.VOICE_SCRIPT: [
            r'training',
            r'script',
            r'exercise'
        ],
        ContentType.PRETEXT_SCENARIO: [
            r'scenario',
            r'training',
            r'exercise'
        ]
    }

    def __init__(self, safety_level: SafetyLevel = SafetyLevel.MODERATE):
        self.safety_level = safety_level
        self.custom_filters: List[str] = []

    async def validate_content(
        self,
        content: str,
        content_type: ContentType,
        context: PromptContext
    ) -> SafetyResult:
        """Validate content for safety and compliance."""

        issues = []
        compliance_flags = []
        recommendations = []
        safety_score = 1.0

        # Check for prohibited patterns
        prohibited_found = self._check_prohibited_patterns(content)
        if prohibited_found:
            issues.extend(prohibited_found)
            safety_score -= 0.3
            recommendations.append("Remove prohibited content patterns")

        # Check for educational markers (less strict for training content)
        if self.safety_level in [SafetyLevel.STRICT, SafetyLevel.MODERATE]:
            marker_issues = self._check_educational_markers(content, content_type)
            if marker_issues:
                compliance_flags.extend(marker_issues)
                safety_score -= 0.1
                recommendations.append("Add clear educational context markers")

        # Check content appropriateness based on target context
        appropriateness_issues = self._check_appropriateness(content, context)
        if appropriateness_issues:
            issues.extend(appropriateness_issues)
            safety_score -= 0.2

        # Check for realistic but not harmful instructions
        instruction_issues = self._check_harmful_instructions(content)
        if instruction_issues:
            issues.extend(instruction_issues)
            safety_score -= 0.4
            recommendations.append("Replace harmful instructions with benign alternatives")

        # Check for excessive realism (actual company/person references)
        realism_issues = self._check_excessive_realism(content)
        if realism_issues:
            compliance_flags.extend(realism_issues)
            safety_score -= 0.1
            recommendations.append("Use fictitious company/person names")

        # Custom filter checks
        custom_issues = self._check_custom_filters(content)
        if custom_issues:
            issues.extend(custom_issues)
            safety_score -= 0.2

        # Determine pass/fail based on safety level
        passed = self._determine_pass_fail(safety_score, issues, compliance_flags)

        return SafetyResult(
            passed=passed,
            issues=issues,
            compliance_flags=compliance_flags,
            safety_score=max(0.0, safety_score),
            recommendations=recommendations
        )

    def _check_prohibited_patterns(self, content: str) -> List[str]:
        """Check for prohibited content patterns."""
        issues = []
        content_lower = content.lower()

        for pattern in self.PROHIBITED_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                issues.append(f"Prohibited pattern detected: {pattern}")

        return issues

    def _check_educational_markers(self, content: str, content_type: ContentType) -> List[str]:
        """Check for required educational context markers."""
        issues = []

        required_markers = self.REQUIRED_EDUCATIONAL_MARKERS.get(content_type, [])
        content_lower = content.lower()

        found_markers = []
        for marker_pattern in required_markers:
            if re.search(marker_pattern, content_lower, re.IGNORECASE):
                found_markers.append(marker_pattern)

        if not found_markers and required_markers:
            issues.append(f"Missing educational context markers for {content_type.value}")

        return issues

    def _check_appropriateness(self, content: str, context: PromptContext) -> List[str]:
        """Check content appropriateness for target context."""
        issues = []

        # Check difficulty level alignment
        if context.difficulty_level <= 3:
            # Low difficulty should be obviously fake
            if not any(marker in content.lower() for marker in ['test', 'training', 'simulation', 'exercise']):
                issues.append("Low difficulty content should include clear test indicators")

        # Check if content matches target sophistication
        if context.target_technical_level == "high" and "click here" in content.lower():
            issues.append("High technical sophistication targets unlikely to fall for basic tactics")

        # Check urgency appropriateness
        if context.urgency_level >= 8 and context.security_awareness_level >= 8:
            if any(word in content.lower() for word in ['immediate', 'urgent', 'now', 'asap']):
                issues.append("High urgency may be inappropriate for security-aware targets")

        return issues

    def _check_harmful_instructions(self, content: str) -> List[str]:
        """Check for genuinely harmful instructions."""
        issues = []
        content_lower = content.lower()

        harmful_instructions = [
            r'delete\s+system\s+files',
            r'disable\s+firewall',
            r'turn\s+off\s+security',
            r'install\s+this\s+software',  # Without training context
            r'enter\s+your\s+real\s+password',
            r'provide\s+actual\s+credentials',
            r'wire\s+money\s+to',
            r'send\s+bitcoin\s+to',
        ]

        for pattern in harmful_instructions:
            if re.search(pattern, content_lower):
                issues.append(f"Potentially harmful instruction: {pattern}")

        return issues

    def _check_excessive_realism(self, content: str) -> List[str]:
        """Check for excessive realism that could cause confusion."""
        issues = []

        # Check for real company names (common ones)
        real_companies = [
            'microsoft', 'google', 'apple', 'amazon', 'facebook',
            'netflix', 'paypal', 'bank of america', 'wells fargo',
            'chase', 'citibank', 'irs', 'social security'
        ]

        content_lower = content.lower()
        for company in real_companies:
            if company in content_lower:
                issues.append(f"Real company name detected: {company}")

        # Check for real URLs
        real_url_patterns = [
            r'https?://(?:www\.)?(microsoft|google|apple|amazon|facebook)\.com',
            r'https?://(?:www\.)?paypal\.com',
            r'https?://(?:www\.)?\w+bank\.com'
        ]

        for pattern in real_url_patterns:
            if re.search(pattern, content_lower):
                issues.append("Real company URL detected")

        return issues

    def _check_custom_filters(self, content: str) -> List[str]:
        """Check against custom filter patterns."""
        issues = []
        content_lower = content.lower()

        for pattern in self.custom_filters:
            if re.search(pattern, content_lower, re.IGNORECASE):
                issues.append(f"Custom filter triggered: {pattern}")

        return issues

    def _determine_pass_fail(self, safety_score: float, issues: List[str], compliance_flags: List[str]) -> bool:
        """Determine if content passes safety validation."""

        if self.safety_level == SafetyLevel.STRICT:
            return safety_score >= 0.9 and not issues
        elif self.safety_level == SafetyLevel.MODERATE:
            return safety_score >= 0.7 and len(issues) <= 2
        else:  # PERMISSIVE
            return safety_score >= 0.5 and len([i for i in issues if 'harmful' in i.lower()]) == 0

    def add_custom_filter(self, pattern: str):
        """Add a custom filter pattern."""
        self.custom_filters.append(pattern)

    def remove_custom_filter(self, pattern: str):
        """Remove a custom filter pattern."""
        if pattern in self.custom_filters:
            self.custom_filters.remove(pattern)


class ContentValidator:
    """Quality validator for generated threat simulation content."""

    def __init__(self):
        self.quality_metrics = {
            'grammar_weight': 0.2,
            'realism_weight': 0.3,
            'effectiveness_weight': 0.3,
            'coherence_weight': 0.2
        }

    async def validate_content(
        self,
        content: str,
        content_type: ContentType,
        context: PromptContext
    ) -> QualityResult:
        """Validate content quality and effectiveness."""

        # Grammar and language quality
        grammar_score = self._assess_grammar_quality(content)

        # Realism assessment
        realism_score = self._assess_realism(content, content_type, context)

        # Effectiveness prediction
        effectiveness_score = self._assess_effectiveness(content, content_type, context)

        # Coherence and structure
        coherence_score = self._assess_coherence(content, content_type)

        # Overall quality score
        quality_score = (
            grammar_score * self.quality_metrics['grammar_weight'] +
            realism_score * self.quality_metrics['realism_weight'] +
            effectiveness_score * self.quality_metrics['effectiveness_weight'] +
            coherence_score * self.quality_metrics['coherence_weight']
        )

        # Identify issues and suggestions
        issues = []
        suggestions = []

        if grammar_score < 0.7:
            issues.append("Grammar and language quality below acceptable threshold")
            suggestions.append("Review content for grammatical errors and clarity")

        if realism_score < 0.6:
            issues.append("Content lacks realistic elements")
            suggestions.append("Add more realistic details and context")

        if effectiveness_score < 0.5:
            issues.append("Content may not be effective for target audience")
            suggestions.append("Adjust psychological triggers and social engineering tactics")

        if coherence_score < 0.6:
            issues.append("Content structure and flow need improvement")
            suggestions.append("Reorganize content for better logical flow")

        return QualityResult(
            quality_score=quality_score,
            realism_score=realism_score,
            effectiveness_score=effectiveness_score,
            issues=issues,
            suggestions=suggestions
        )

    def _assess_grammar_quality(self, content: str) -> float:
        """Assess grammar and language quality."""
        score = 1.0

        # Basic grammar checks
        sentences = content.split('.')

        # Check for very short sentences (might indicate incomplete thoughts)
        short_sentences = [s for s in sentences if len(s.strip()) < 10 and s.strip()]
        if len(short_sentences) > len(sentences) * 0.3:
            score -= 0.2

        # Check for very long sentences (might be run-on)
        long_sentences = [s for s in sentences if len(s) > 200]
        if len(long_sentences) > len(sentences) * 0.2:
            score -= 0.1

        # Check for basic punctuation issues
        if content.count('..') > 2:  # Excessive ellipses
            score -= 0.1

        if content.count('!!') > 1:  # Excessive exclamation
            score -= 0.1

        # Check for capitalization issues
        words = content.split()
        all_caps_words = [w for w in words if w.isupper() and len(w) > 3]
        if len(all_caps_words) > len(words) * 0.1:
            score -= 0.1

        return max(0.0, score)

    def _assess_realism(self, content: str, content_type: ContentType, context: PromptContext) -> float:
        """Assess content realism."""
        score = 0.5  # Base score

        # Content type specific realism checks
        if content_type == ContentType.EMAIL_PHISHING:
            score += self._assess_email_realism(content, context)
        elif content_type == ContentType.SMS_PHISHING:
            score += self._assess_sms_realism(content, context)
        elif content_type == ContentType.VOICE_SCRIPT:
            score += self._assess_voice_realism(content, context)

        # Common realism factors

        # Personalization
        if context.target_role.lower() in content.lower():
            score += 0.1
        if context.target_department.lower() in content.lower():
            score += 0.1
        if context.company_name and context.company_name.lower() in content.lower():
            score += 0.1

        # Appropriate urgency
        urgency_words = ['urgent', 'immediate', 'asap', 'quickly', 'soon']
        urgency_count = sum(1 for word in urgency_words if word in content.lower())
        if context.urgency_level >= 7 and urgency_count >= 1:
            score += 0.1
        elif context.urgency_level <= 3 and urgency_count == 0:
            score += 0.1

        # Professional tone alignment
        if context.tone == "professional" and not any(
            word in content.lower() for word in ['hey', 'hi there', 'sup', 'yo']
        ):
            score += 0.1

        return min(1.0, score)

    def _assess_email_realism(self, content: str, context: PromptContext) -> float:
        """Assess email-specific realism."""
        score = 0.0

        # Check for email structure elements
        if 'subject:' in content.lower():
            score += 0.1
        if 'from:' in content.lower():
            score += 0.1
        if any(greeting in content.lower() for greeting in ['dear', 'hello', 'hi']):
            score += 0.1
        if any(closing in content.lower() for closing in ['sincerely', 'regards', 'best']):
            score += 0.1

        # Check for realistic sender patterns
        if '@' in content and '.' in content:  # Email address format
            score += 0.1

        return score

    def _assess_sms_realism(self, content: str, context: PromptContext) -> float:
        """Assess SMS-specific realism."""
        score = 0.0

        # SMS length check (realistic SMS length)
        if 50 <= len(content) <= 160:
            score += 0.2
        elif len(content) <= 300:  # Extended SMS
            score += 0.1

        # SMS-like language patterns
        if any(word in content.lower() for word in ['text', 'msg', 'reply']):
            score += 0.1

        # Short, direct language
        sentences = content.split('.')
        avg_sentence_length = sum(len(s) for s in sentences) / max(1, len(sentences))
        if avg_sentence_length < 50:
            score += 0.1

        return score

    def _assess_voice_realism(self, content: str, context: PromptContext) -> float:
        """Assess voice script realism."""
        score = 0.0

        # Conversational elements
        if any(word in content.lower() for word in ['hello', 'hi', 'good morning', 'good afternoon']):
            score += 0.1

        # Questions (natural in conversation)
        question_count = content.count('?')
        if 1 <= question_count <= 5:
            score += 0.1

        # Natural speech patterns
        if any(phrase in content.lower() for phrase in ['you know', 'well', 'actually', 'so']):
            score += 0.1

        return score

    def _assess_effectiveness(self, content: str, content_type: ContentType, context: PromptContext) -> float:
        """Assess predicted effectiveness of content."""
        score = 0.5  # Base score

        # Psychological trigger alignment
        trigger_words = {
            'authority': ['manager', 'ceo', 'director', 'compliance', 'security', 'it department'],
            'urgency': ['urgent', 'immediate', 'deadline', 'expire', 'suspend'],
            'fear': ['suspend', 'close', 'lock', 'disable', 'security breach'],
            'curiosity': ['confidential', 'exclusive', 'private', 'special'],
            'helpfulness': ['help', 'assist', 'support', 'verify', 'confirm']
        }

        content_lower = content.lower()
        for trigger_type, words in trigger_words.items():
            if trigger_type in [t.lower() for t in context.psychological_triggers]:
                if any(word in content_lower for word in words):
                    score += 0.1

        # Target sophistication alignment
        if context.target_technical_level == "low":
            # Simple, direct approach should be more effective
            if len(content.split()) < 100:  # Concise
                score += 0.1
        elif context.target_technical_level == "high":
            # More sophisticated approach needed
            if any(word in content_lower for word in ['technical', 'system', 'security', 'compliance']):
                score += 0.1

        # Difficulty level appropriateness
        if context.difficulty_level <= 4:
            # Should be obviously suspicious to trained eye
            if any(marker in content_lower for marker in ['test', 'training', 'simulation']):
                score += 0.1

        return min(1.0, score)

    def _assess_coherence(self, content: str, content_type: ContentType) -> float:
        """Assess content coherence and structure."""
        score = 0.7  # Base score

        # Check for logical flow
        sentences = [s.strip() for s in content.split('.') if s.strip()]

        if len(sentences) >= 3:
            # Check if content has introduction, body, conclusion
            has_intro = any(word in sentences[0].lower() for word in ['dear', 'hello', 'hi', 'greetings'])
            has_conclusion = any(word in sentences[-1].lower() for word in ['sincerely', 'regards', 'thank', 'best'])

            if has_intro:
                score += 0.1
            if has_conclusion:
                score += 0.1

        # Check for topic consistency
        if content_type == ContentType.EMAIL_PHISHING:
            # Email should maintain consistent topic
            if 'subject:' in content.lower():
                # Extract subject and check if body relates to it
                score += 0.1  # Simplified check

        # Check for excessive repetition
        words = content.lower().split()
        unique_words = set(words)
        if len(unique_words) / max(1, len(words)) > 0.7:  # Good vocabulary diversity
            score += 0.1

        return min(1.0, score)
