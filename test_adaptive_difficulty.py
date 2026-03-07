#!/usr/bin/env python3
"""Test adaptive difficulty engine integration with enhanced scenarios."""

import asyncio
import sys
import os
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from threatsimgpt.core.simulator import ThreatSimulator
from threatsimgpt.core.adaptive_difficulty import AdaptiveDifficultyEngine


async def test_adaptive_difficulty():
    """Test adaptive difficulty engine with various target profiles."""
    
    print("🎯 Adaptive Difficulty Engine Test")
    print("=" * 40)
    
    # Initialize simulator with enhanced features
    simulator = ThreatSimulator(enable_enhanced=True)
    
    # Test target profiles with different characteristics
    test_targets = [
        {
            "name": "High Security Financial Analyst",
            "industry": "finance",
            "size": "large",
            "role": "financial_analyst",
            "department": "accounting",
            "security_awareness_level": 8
        },
        {
            "name": "Low Security Education User",
            "industry": "education", 
            "size": "medium",
            "role": "teacher",
            "department": "academics",
            "security_awareness_level": 3
        },
        {
            "name": "Government System Administrator",
            "industry": "government",
            "size": "enterprise", 
            "role": "system_administrator",
            "department": "infrastructure",
            "security_awareness_level": 9
        },
        {
            "name": "Tech Startup Developer",
            "industry": "technology",
            "size": "small",
            "role": "developer", 
            "department": "engineering",
            "security_awareness_level": 6
        }
    ]
    
    results = []
    
    for i, target in enumerate(test_targets, 1):
        print(f"\n📋 Test {i}: {target['name']}")
        print("-" * 30)
        
        try:
            # Test difficulty calculation
            difficulty_calc = simulator.adaptive_difficulty.calculate_optimal_difficulty(target)
            
            print(f"🎯 Calculated Difficulty: {difficulty_calc.final_difficulty:.2f}/10")
            print(f"📊 Confidence Score: {difficulty_calc.confidence_score:.2f}")
            print(f"📈 Security Level Impact: {difficulty_calc.security_modifier:+.2f}")
            print(f"🏢 Industry Impact: {difficulty_calc.industry_modifier:+.2f}")
            print(f"👥 Role Impact: {difficulty_calc.role_modifier:+.2f}")
            print(f"📏 Size Impact: {difficulty_calc.size_modifier:+.2f}")
            
            # Get recommendations
            recommendations = simulator.adaptive_difficulty.get_difficulty_recommendations(target)
            if recommendations:
                print(f"💡 Recommendations:")
                for rec in recommendations[:3]:  # Show top 3
                    print(f"   - {rec}")
            
            # Generate enhanced scenario with adaptive difficulty
            scenario = await simulator.generate_enhanced_scenario_only(
                "phishing", target
            )
            
            # Verify adaptive metadata was applied
            if hasattr(scenario, 'adaptive_metadata'):
                metadata = scenario.adaptive_metadata
                print(f"✅ Adaptive Difficulty Applied: {metadata.get('calculated_difficulty', 'N/A')}")
                print(f"📊 Original vs Adjusted: {metadata.get('original_difficulty', 'N/A')} → {metadata.get('calculated_difficulty', 'N/A')}")
            else:
                print("⚠️  No adaptive metadata found")
            
            # Verify scenario difficulty was set
            if hasattr(scenario, 'difficulty_level'):
                print(f"🎲 Final Scenario Difficulty: {scenario.difficulty_level}/10")
            else:
                print("⚠️  No difficulty level set on scenario")
            
            # Check detection indicators
            if hasattr(scenario, 'detection_indicators'):
                print(f"🔍 Detection Indicators: {len(scenario.detection_indicators)}")
                
                # Count indicators with difficulty
                difficult_indicators = sum(1 for ind in scenario.detection_indicators 
                                     if hasattr(ind, 'detection_difficulty') and ind.detection_difficulty > 6.0)
                print(f"🎯 High Difficulty Indicators: {difficult_indicators}")
            
            results.append({
                'target': target['name'],
                'success': True,
                'calculated_difficulty': difficulty_calc.final_difficulty,
                'confidence': difficulty_calc.confidence_score,
                'scenario_difficulty': getattr(scenario, 'difficulty_level', None),
                'indicators_count': len(getattr(scenario, 'detection_indicators', []))
            })
            
        except Exception as e:
            print(f"❌ Test failed: {str(e)}")
            results.append({
                'target': target['name'],
                'success': False,
                'error': str(e)
            })
    
    # Summary
    print(f"\n📊 Adaptive Difficulty Test Results")
    print("=" * 35)
    
    successful_tests = sum(1 for r in results if r['success'])
    total_tests = len(results)
    
    print(f"✅ Successful Tests: {successful_tests}/{total_tests}")
    print(f"📈 Success Rate: {(successful_tests/total_tests)*100:.1f}%")
    
    if successful_tests > 0:
        successful_results = [r for r in results if r['success']]
        avg_difficulty = sum(r['calculated_difficulty'] for r in successful_results) / len(successful_results)
        avg_confidence = sum(r['confidence'] for r in successful_results) / len(successful_results)
        avg_indicators = sum(r['indicators_count'] for r in successful_results) / len(successful_results)
        
        print(f"📊 Average Calculated Difficulty: {avg_difficulty:.2f}")
        print(f"📊 Average Confidence Score: {avg_confidence:.2f}")
        print(f"🔍 Average Indicators per Scenario: {avg_indicators:.1f}")
        
        # Verify difficulty adjustment worked
        adjustments = sum(1 for r in successful_results 
                        if r.get('scenario_difficulty') and 
                        abs(r['scenario_difficulty'] - r['calculated_difficulty']) < 1.0)
        print(f"🎯 Accurate Difficulty Adjustments: {adjustments}/{successful_tests}")
    
    print(f"\n🎉 Adaptive Difficulty Engine: {'WORKING' if successful_tests == total_tests else 'NEEDS FIX'}")
    return successful_tests == total_tests


def test_standalone_adaptive_engine():
    """Test adaptive difficulty engine standalone."""
    print("\n🔧 Standalone Adaptive Difficulty Engine Test")
    print("=" * 45)
    
    engine = AdaptiveDifficultyEngine()
    
    # Test cases with known inputs and expected outputs
    test_cases = [
        {
            "name": "High Security Finance",
            "input": {
                "security_awareness_level": 8,
                "industry": "finance",
                "size": "large",
                "role": "financial_analyst"
            },
            "expected_difficulty_range": (7.0, 9.0),
            "expected_confidence_min": 0.7
        },
        {
            "name": "Low Security Education", 
            "input": {
                "security_awareness_level": 3,
                "industry": "education",
                "size": "medium", 
                "role": "teacher"
            },
            "expected_difficulty_range": (3.0, 5.0),
            "expected_confidence_min": 0.6
        },
        {
            "name": "Government Admin",
            "input": {
                "security_awareness_level": 9,
                "industry": "government",
                "size": "enterprise",
                "role": "system_administrator"
            },
            "expected_difficulty_range": (8.0, 10.0),
            "expected_confidence_min": 0.8
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\n🧪 Test Case: {test_case['name']}")
        
        try:
            result = engine.calculate_optimal_difficulty(test_case['input'])
            
            # Validate results
            min_expected, max_expected = test_case['expected_difficulty_range']
            min_confidence = test_case['expected_confidence_min']
            
            difficulty_ok = min_expected <= result.final_difficulty <= max_expected
            confidence_ok = result.confidence_score >= min_confidence
            
            test_passed = difficulty_ok and confidence_ok
            
            print(f"   📊 Difficulty: {result.final_difficulty:.2f} (expected: {min_expected}-{max_expected}) {'✅' if difficulty_ok else '❌'}")
            print(f"   📈 Confidence: {result.confidence_score:.2f} (min: {min_confidence}) {'✅' if confidence_ok else '❌'}")
            print(f"   🎯 Test Result: {'PASSED' if test_passed else 'FAILED'}")
            
            if not test_passed:
                all_passed = False
                
        except Exception as e:
            print(f"   ❌ Test Error: {str(e)}")
            all_passed = False
    
    print(f"\n🏆 Standalone Engine Test: {'PASSED' if all_passed else 'FAILED'}")
    return all_passed


if __name__ == "__main__":
    # Load environment
    load_dotenv()
    
    print("🚀 Adaptive Difficulty Engine Integration Test Suite")
    print("Following NASA Power of 10 and SWEBOK v4.0 Standards")
    print()
    
    # Test standalone engine first
    standalone_passed = test_standalone_adaptive_engine()
    
    # Test integration with simulator
    integration_passed = asyncio.run(test_adaptive_difficulty())
    
    # Final results
    print(f"\n🎯 Final Test Results")
    print("=" * 25)
    print(f"🔧 Standalone Engine: {'PASSED' if standalone_passed else 'FAILED'}")
    print(f"🚀 Integration Test: {'PASSED' if integration_passed else 'FAILED'}")
    
    overall_success = standalone_passed and integration_passed
    print(f"🏆 Overall Result: {'SUCCESS' if overall_success else 'FAILURE'}")
    
    sys.exit(0 if overall_success else 1)
