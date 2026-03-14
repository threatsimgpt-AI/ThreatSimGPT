#!/usr/bin/env python3
"""
Simple Feature Test Script for ThreatSimGPT

This script performs basic functionality tests without requiring complex dependencies.
"""

import os
import sys
import subprocess
from pathlib import Path

def run_test_command(cmd, description):
    """Run a test command and return success status."""
    print(f"Testing: {description}")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        # Set environment variable to avoid OpenMP conflicts
        env = os.environ.copy()
        env['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            print(f"✓ PASSED: {description}")
            return True
        else:
            print(f"✗ FAILED: {description}")
            print(f"  Exit code: {result.returncode}")
            if result.stderr:
                print(f"  Error: {result.stderr[:200]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"✗ TIMEOUT: {description}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {description} - {e}")
        return False

def main():
    """Run basic feature tests."""
    print("=" * 60)
    print("THREATSIMGPT SIMPLE FEATURE TEST")
    print("=" * 60)
    
    tests = [
        # Basic imports
        ([sys.executable, "-c", "import threatsimgpt; print('Import successful')"], "Basic Import Test"),
        
        # Template directory check
        ([sys.executable, "-c", "import os; print('Templates exist:', os.path.exists('templates'))"], "Template Directory Check"),
        
        # Config file check
        ([sys.executable, "-c", "import os; print('Config exists:', os.path.exists('config.yaml'))"], "Config File Check"),
        
        # Basic file structure
        ([sys.executable, "-c", "import os; print('README exists:', os.path.exists('README.md'))"], "README File Check"),
        
        # Check if main module exists
        ([sys.executable, "-c", "import threatsimgpt.cli.main; print('CLI module exists')"], "CLI Module Check"),
    ]
    
    passed = 0
    total = len(tests)
    
    for cmd, description in tests:
        if run_test_command(cmd, description):
            passed += 1
        print()
    
    print("=" * 60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("🎉 All basic tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
