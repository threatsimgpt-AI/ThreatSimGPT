#!/usr/bin/env python3
"""Test script for enhanced template security validation."""

import sys
import time
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from threatsimgpt.security.template_validator import TemplateSecurityValidator

def test_enhanced_validation():
    """Test the enhanced template security validator."""
    
    # Create test template with security issues
    test_template = {
        'metadata': {
            'name': 'test_template',
            'author': 'test_user'
        },
        'description': 'Test template with {{7*command}} injection',
        'target_profile': {
            'role': 'admin'
        }
    }
    
    # Initialize enhanced validator
    validator = TemplateSecurityValidator(
        strict_mode=True,
        enable_caching=True,
        cache_ttl_seconds=60,
        max_cache_size=10
    )
    
    print("Testing enhanced template security validation...")
    print(f"Template: {test_template['metadata']['name']}")
    
    # Test 1: First validation (should detect issues)
    print("\n=== Test 1: First Validation ===")
    start_time = time.time()
    result1 = validator.validate_template(
        test_template,
        user_context={'user': 'temitayo', 'role': 'red_team'}
    )
    duration1 = (time.time() - start_time) * 1000
    
    print(f"Findings: {len(result1.findings)}")
    print(f"Secure: {result1.is_secure}")
    print(f"Duration: {duration1}ms")
    
    # Test 2: Second validation (should use cache)
    print("\n=== Test 2: Cached Validation ===")
    start_time = time.time()
    result2 = validator.validate_template(
        test_template,
        user_context={'user': 'temitayo', 'role': 'red_team'}
    )
    duration2 = (time.time() - start_time) * 1000
    
    print(f"Findings: {len(result2.findings)}")
    print(f"Secure: {result2.is_secure}")
    print(f"Duration: {duration2}ms (cached)")
    
    # Test 3: Valid template
    print("\n=== Test 3: Valid Template ===")
    valid_template = {
        'metadata': {
            'name': 'valid_template',
            'author': 'test_user'
        },
        'description': 'Safe template description',
        'target_profile': {
            'role': 'user'
        }
    }
    
    start_time = time.time()
    result3 = validator.validate_template(
        valid_template,
        user_context={'user': 'temitayo', 'role': 'red_team'}
    )
    duration3 = (time.time() - start_time) * 1000
    
    print(f"Findings: {len(result3.findings)}")
    print(f"Secure: {result3.is_secure}")
    print(f"Duration: {duration3}ms")
    
    # Summary
    print("\n=== Summary ===")
    print(f"Cache working: {duration2 < duration1}")  # Second should be faster
    print(f"Valid template passes: {result3.is_secure}")
    print("Enhanced validation test completed!")

if __name__ == "__main__":
    test_enhanced_validation()
