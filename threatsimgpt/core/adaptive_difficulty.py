"""Adaptive Difficulty Engine for Enhanced Scenario Generation.

Production-grade implementation with comprehensive validation and bounds checking.
Provides intelligent difficulty adjustment based on target characteristics and security posture.
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security awareness levels with defined bounds."""
    VERY_LOW = 1
    LOW = 2
    MEDIUM_LOW = 3
    MEDIUM = 4
    MEDIUM_HIGH = 5
    HIGH = 6
    HIGH_PLUS = 7
    VERY_HIGH = 8
    EXPERT = 9
    MAXIMUM = 10


class IndustryType(Enum):
    """Industry types with difficulty modifiers."""
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    GOVERNMENT = "government"
    EDUCATION = "education"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    ENERGY = "energy"
    TELECOMMUNICATIONS = "telecommunications"


@dataclass
class DifficultyCalculation:
    """Result of difficulty calculation with validation."""
    base_difficulty: float
    security_modifier: float
    industry_modifier: float
    size_modifier: float
    role_modifier: float
    final_difficulty: float
    confidence_score: float
    calculation_factors: Dict[str, float]


class AdaptiveDifficultyEngine:
    """Production-grade adaptive difficulty engine.
    
    Calculates optimal scenario difficulty based on target characteristics,
    security posture, and environmental factors.
    """
    
    # Fixed upper bounds for all calculations
    MAX_DIFFICULTY = 10
    MIN_DIFFICULTY = 1
    MAX_SECURITY_LEVEL = 10
    MAX_MODIFIER_VALUE = 5.0
    MAX_CONFIDENCE = 1.0
    
    def __init__(self):
        """Initialize adaptive difficulty engine."""
        # Initialize modifier dictionaries first
        self.industry_modifiers = {
            IndustryType.FINANCE.value: 1.5,
            IndustryType.HEALTHCARE.value: 1.2,
            IndustryType.TECHNOLOGY.value: 0.8,
            IndustryType.GOVERNMENT.value: 2.0,
            IndustryType.EDUCATION.value: 0.5,
            IndustryType.RETAIL.value: 0.7,
            IndustryType.MANUFACTURING.value: 1.0,
            IndustryType.ENERGY.value: 1.3,
            IndustryType.TELECOMMUNICATIONS.value: 1.1
        }
        
        self.role_modifiers = {
            'system_administrator': 1.8,
            'network_administrator': 1.6,
            'security_analyst': 1.4,
            'database_administrator': 1.3,
            'developer': 1.2,
            'financial_analyst': 1.0,
            'hr_manager': 0.8,
            'marketing_manager': 0.6,
            'sales_representative': 0.5,
            'customer_service': 0.4
        }
        
        self.size_modifiers = {
            'small': 0.7,
            'medium': 1.0,
            'large': 1.3,
            'enterprise': 1.6
        }
        
        # Validate initialization after all attributes are set
        self._validate_initialization()
    
    def _validate_initialization(self) -> None:
        """Validate engine initialization."""
        assert hasattr(self, 'industry_modifiers'), "Industry modifiers not initialized"
        assert hasattr(self, 'role_modifiers'), "Role modifiers not initialized"
        assert hasattr(self, 'size_modifiers'), "Size modifiers not initialized"
        
        # Validate modifier bounds
        for modifier in self.industry_modifiers.values():
            assert -2 <= modifier <= 2, f"Industry modifier {modifier} out of bounds"
        
        for modifier in self.role_modifiers.values():
            assert 0 <= modifier <= 2, f"Role modifier {modifier} out of bounds"
        
        for modifier in self.size_modifiers.values():
            assert 0 <= modifier <= 2, f"Size modifier {modifier} out of bounds"
        
        logger.info("AdaptiveDifficultyEngine initialized with validated modifiers")
    
    def calculate_optimal_difficulty(self, target_profile: Dict) -> DifficultyCalculation:
        """Calculate optimal difficulty with comprehensive validation.
        
        Args:
            target_profile: Target characteristics including security level, industry, etc.
            
        Returns:
            DifficultyCalculation with all factors and final difficulty
            
        Raises:
            AssertionError: If input validation fails
        """
        # Input validation
        assert isinstance(target_profile, dict), "Target profile must be dictionary"
        assert len(target_profile) > 0, "Target profile cannot be empty"
        
        # Validate required fields
        required_fields = ['security_awareness_level', 'industry', 'size', 'role']
        for field in required_fields:
            assert field in target_profile, f"Missing required field: {field}"
        
        # Extract target characteristics
        security_level = target_profile['security_awareness_level']
        industry = target_profile['industry']
        size = target_profile['size']
        role = target_profile['role']
        
        # Validate individual inputs
        assert isinstance(security_level, (int, float)), "Security level must be numeric"
        assert 1 <= security_level <= 10, "Security level out of bounds"
        
        assert isinstance(industry, str), "Industry must be string"
        assert industry.strip(), "Industry cannot be empty"
        
        assert isinstance(size, str), "Size must be string"
        assert size.strip(), "Size cannot be empty"
        
        assert isinstance(role, str), "Role must be string"
        assert role.strip(), "Role cannot be empty"
        
        # Base difficulty
        base_difficulty = 5.0
        assert self.MIN_DIFFICULTY <= base_difficulty <= self.MAX_DIFFICULTY, "Base difficulty out of bounds"
        
        # Security awareness modifier
        security_modifier = (security_level - 5.0) * 0.3
        assert -2.0 <= security_modifier <= 1.5, "Security modifier out of bounds"
        
        # Industry modifier with return value validation
        industry_modifier = self._get_industry_difficulty_modifier(industry)
        
        # Size modifier with validation
        size_modifier = self._get_size_difficulty_modifier(size)
        
        # Role modifier with validation
        role_modifier = self._get_role_difficulty_modifier(role)
        
        # Final calculation with bounds checking
        final_difficulty = base_difficulty + security_modifier + industry_modifier + size_modifier + role_modifier
        final_difficulty = max(self.MIN_DIFFICULTY, min(self.MAX_DIFFICULTY, final_difficulty))
        
        # Confidence score calculation
        confidence_score = self._calculate_confidence_score(target_profile, final_difficulty)
        
        # Create calculation result
        result = DifficultyCalculation(
            base_difficulty=base_difficulty,
            security_modifier=security_modifier,
            industry_modifier=industry_modifier,
            size_modifier=size_modifier,
            role_modifier=role_modifier,
            final_difficulty=final_difficulty,
            confidence_score=confidence_score,
            calculation_factors={
                'security_level': float(security_level),
                'industry': industry_modifier,
                'size': size_modifier,
                'role': role_modifier
            }
        )
        
        # Final validation
        assert self.MIN_DIFFICULTY <= result.final_difficulty <= self.MAX_DIFFICULTY, "Final difficulty out of bounds"
        assert 0 <= result.confidence_score <= 1.0, "Confidence score out of bounds"
        
        logger.info(f"Calculated optimal difficulty: {result.final_difficulty:.2f} for target: {industry} {role}")
        return result
    
    def _get_industry_difficulty_modifier(self, industry: str) -> float:
        """Get industry difficulty modifier with comprehensive validation."""
        # Input validation
        assert isinstance(industry, str), "Industry must be string"
        assert industry.strip(), "Industry cannot be empty"
        
        # Normalize industry name
        normalized_industry = industry.lower().strip()
        
        # Get modifier with default
        modifier = self.industry_modifiers.get(normalized_industry, 0.0)
        
        # Return value validation
        assert isinstance(modifier, (int, float)), "Industry modifier must be numeric"
        assert -2.0 <= modifier <= 2.0, f"Industry modifier {modifier} out of range"
        
        return float(modifier)
    
    def _get_size_difficulty_modifier(self, size: str) -> float:
        """Get size difficulty modifier with validation."""
        # Input validation
        assert isinstance(size, str), "Size must be string"
        assert size.strip(), "Size cannot be empty"
        
        # Normalize size name
        normalized_size = size.lower().strip()
        
        # Get modifier with default
        modifier = self.size_modifiers.get(normalized_size, 1.0)
        
        # Return value validation
        assert isinstance(modifier, (int, float)), "Size modifier must be numeric"
        assert 0 <= modifier <= 2.0, f"Size modifier {modifier} out of range"
        
        return float(modifier)
    
    def _get_role_difficulty_modifier(self, role: str) -> float:
        """Get role difficulty modifier with validation."""
        # Input validation
        assert isinstance(role, str), "Role must be string"
        assert role.strip(), "Role cannot be empty"
        
        # Normalize role name
        normalized_role = role.lower().strip().replace('_', ' ').replace('-', ' ')
        
        # Get modifier with default
        modifier = self.role_modifiers.get(normalized_role, 1.0)
        
        # Return value validation
        assert isinstance(modifier, (int, float)), "Role modifier must be numeric"
        assert 0 <= modifier <= 2.0, f"Role modifier {modifier} out of range"
        
        return float(modifier)
    
    def _calculate_confidence_score(self, target_profile: Dict, final_difficulty: float) -> float:
        """Calculate confidence score for difficulty calculation."""
        # Input validation
        assert isinstance(target_profile, dict), "Target profile must be dictionary"
        assert isinstance(final_difficulty, (int, float)), "Final difficulty must be numeric"
        
        # Factors affecting confidence
        completeness_factors = 0
        total_factors = 0
        
        # Security level completeness
        if 'security_awareness_level' in target_profile:
            completeness_factors += 1
        total_factors += 1
        
        # Industry information completeness
        if 'industry' in target_profile:
            completeness_factors += 1
        total_factors += 1
        
        # Size information completeness
        if 'size' in target_profile:
            completeness_factors += 1
        total_factors += 1
        
        # Role information completeness
        if 'role' in target_profile:
            completeness_factors += 1
        total_factors += 1
        
        # Department information (bonus)
        if 'department' in target_profile:
            completeness_factors += 0.5
        total_factors += 1
        
        # Calculate base confidence
        base_confidence = completeness_factors / total_factors
        
        # Difficulty-based confidence adjustment
        difficulty_confidence = 1.0 - abs(final_difficulty - 5.0) / 10.0
        
        # Final confidence score with bounds checking
        confidence_score = (base_confidence + difficulty_confidence) / 2.0
        confidence_score = max(0.0, min(1.0, confidence_score))
        
        # Return value validation
        assert 0.0 <= confidence_score <= 1.0, "Confidence score out of bounds"
        
        return confidence_score
    
    def adjust_scenario_difficulty(self, scenario, target_difficulty: float):
        """Adjust existing scenario to match target difficulty."""
        # Input validation
        assert hasattr(scenario, 'detection_indicators'), "Scenario must have detection indicators"
        assert hasattr(scenario, 'attack_patterns'), "Scenario must have attack patterns"
        assert isinstance(target_difficulty, (int, float)), "Target difficulty must be numeric"
        assert self.MIN_DIFFICULTY <= target_difficulty <= self.MAX_DIFFICULTY, "Target difficulty out of bounds"
        
        # Calculate current scenario difficulty
        current_difficulty = self._calculate_scenario_difficulty(scenario)
        
        # Calculate adjustment factor
        if current_difficulty > 0:
            adjustment_factor = target_difficulty / current_difficulty
        else:
            adjustment_factor = target_difficulty / 5.0  # Use baseline
        
        # Apply bounds to adjustment factor
        adjustment_factor = max(0.5, min(2.0, adjustment_factor))
        
        # Adjust detection indicators
        for indicator in scenario.detection_indicators:
            self._adjust_indicator_difficulty(indicator, adjustment_factor)
        
        # Adjust attack patterns
        for pattern in scenario.attack_patterns:
            self._adjust_pattern_difficulty(pattern, adjustment_factor)
        
        # Update scenario difficulty level
        scenario.difficulty_level = int(round(target_difficulty))
        
        # Final validation
        assert self.MIN_DIFFICULTY <= scenario.difficulty_level <= self.MAX_DIFFICULTY, "Scenario difficulty out of bounds"
        
        logger.info(f"Adjusted scenario difficulty to {scenario.difficulty_level} (factor: {adjustment_factor:.2f})")
        return scenario
    
    def _calculate_scenario_difficulty(self, scenario) -> float:
        """Calculate current difficulty of a scenario."""
        # Input validation
        assert hasattr(scenario, 'detection_indicators'), "Scenario must have detection indicators"
        assert hasattr(scenario, 'attack_patterns'), "Scenario must have attack patterns"
        
        total_difficulty = 0.0
        indicator_count = 0
        
        # Sum detection indicator difficulties
        for indicator in scenario.detection_indicators:
            if hasattr(indicator, 'detection_difficulty'):
                total_difficulty += indicator.detection_difficulty
                indicator_count += 1
        
        # Add attack pattern difficulties
        pattern_count = 0
        for pattern in scenario.attack_patterns:
            if hasattr(pattern, 'sophistication_level'):
                total_difficulty += pattern.sophistication_level
                pattern_count += 1
        
        # Calculate average difficulty
        total_items = indicator_count + pattern_count
        if total_items > 0:
            average_difficulty = total_difficulty / total_items
        else:
            average_difficulty = 5.0  # Default baseline
        
        # Return value validation
        assert isinstance(average_difficulty, (int, float)), "Average difficulty must be numeric"
        assert 1 <= average_difficulty <= 10, "Average difficulty out of bounds"
        
        return float(average_difficulty)
    
    def _adjust_indicator_difficulty(self, indicator, adjustment_factor: float) -> None:
        """Adjust individual indicator difficulty."""
        # Input validation
        assert hasattr(indicator, 'detection_logic'), "Indicator must have detection logic"
        assert isinstance(adjustment_factor, (int, float)), "Adjustment factor must be numeric"
        assert 0.5 <= adjustment_factor <= 2.0, "Adjustment factor out of bounds"
        
        # Adjust detection difficulty if it exists
        if hasattr(indicator, 'detection_difficulty'):
            current_difficulty = indicator.detection_difficulty
            new_difficulty = current_difficulty * adjustment_factor
            new_difficulty = max(1.0, min(10.0, new_difficulty))
            
            # Update with bounds checking
            indicator.detection_difficulty = new_difficulty
            
            # Validate update
            assert 1.0 <= indicator.detection_difficulty <= 10.0, "Indicator difficulty out of bounds"
    
    def _adjust_pattern_difficulty(self, pattern, adjustment_factor: float) -> None:
        """Adjust individual attack pattern difficulty."""
        # Input validation
        assert hasattr(pattern, 'primary_technique_id'), "Pattern must have technique ID"
        assert isinstance(adjustment_factor, (int, float)), "Adjustment factor must be numeric"
        assert 0.5 <= adjustment_factor <= 2.0, "Adjustment factor out of bounds"
        
        # Adjust sophistication level if it exists
        if hasattr(pattern, 'sophistication_level'):
            current_level = pattern.sophistication_level
            new_level = current_level * adjustment_factor
            new_level = max(1.0, min(10.0, new_level))
            
            # Update with bounds checking
            pattern.sophistication_level = new_level
            
            # Validate update
            assert 1.0 <= pattern.sophistication_level <= 10.0, "Pattern sophistication out of bounds"
    
    def get_difficulty_recommendations(self, target_profile: Dict) -> List[str]:
        """Get difficulty adjustment recommendations."""
        # Input validation
        assert isinstance(target_profile, dict), "Target profile must be dictionary"
        assert len(target_profile) > 0, "Target profile cannot be empty"
        
        recommendations = []
        
        # Analyze security level
        security_level = target_profile.get('security_awareness_level', 5)
        if security_level >= 8:
            recommendations.append("High security awareness detected - consider advanced evasion techniques")
        elif security_level <= 3:
            recommendations.append("Low security awareness detected - basic techniques may be sufficient")
        
        # Analyze industry
        industry = target_profile.get('industry', '').lower()
        if industry == 'finance':
            recommendations.append("Finance industry - focus on financial system bypass techniques")
        elif industry == 'healthcare':
            recommendations.append("Healthcare industry - emphasize HIPAA compliance evasion")
        elif industry == 'government':
            recommendations.append("Government sector - prioritize stealth and persistence")
        
        # Analyze role
        role = target_profile.get('role', '').lower()
        if 'admin' in role:
            recommendations.append("Administrative role - include privilege escalation techniques")
        elif 'analyst' in role:
            recommendations.append("Analyst role - focus on data exfiltration scenarios")
        
        return recommendations
    
    def __repr__(self) -> str:
        """String representation with validation."""
        assert hasattr(self, 'industry_modifiers'), "Engine not properly initialized"
        return f"AdaptiveDifficultyEngine(modifiers={len(self.industry_modifiers)})"
