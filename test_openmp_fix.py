#!/usr/bin/env python3
"""
Quick OpenMP Test Script for ThreatSimGPT

This script tests if the OpenMP fix is working properly.
"""

import os
import sys
import subprocess

def test_openmp_fix():
    """Test if OpenMP conflicts are resolved."""
    print("🧪 Testing OpenMP Conflict Resolution")
    print("=" * 40)
    
    # Set environment variables
    env = os.environ.copy()
    env['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
    env['OMP_NUM_THREADS'] = '1'
    env['MKL_NUM_THREADS'] = '1'
    env['OPENBLAS_NUM_THREADS'] = '1'
    env['VECLIB_MAXIMUM_THREADS'] = '1'
    env['SECRET_KEY'] = 'test-key-for-testing'
    
    # Test 1: Basic import
    print("1. Testing basic ThreatSimGPT import...")
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import threatsimgpt; print('✅ Import successful')"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        if result.returncode == 0:
            print("✅ Basic import test passed")
        else:
            print(f"❌ Basic import test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Basic import test error: {e}")
        return False
    
    # Test 2: CLI version command
    print("\n2. Testing CLI version command...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "threatsimgpt", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        if result.returncode == 0 and "ThreatSimGPT" in result.stdout:
            print("✅ CLI version test passed")
        else:
            print(f"❌ CLI version test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ CLI version test error: {e}")
        return False
    
    # Test 3: CLI help command
    print("\n3. Testing CLI help command...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "threatsimgpt", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        if result.returncode == 0 and "ThreatSimGPT" in result.stdout:
            print("✅ CLI help test passed")
        else:
            print(f"❌ CLI help test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ CLI help test error: {e}")
        return False
    
    # Test 4: CLI status command
    print("\n4. Testing CLI status command...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "threatsimgpt", "status"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        if result.returncode == 0 and "Component" in result.stdout:
            print("✅ CLI status test passed")
        else:
            print(f"❌ CLI status test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ CLI status test error: {e}")
        return False
    
    # Test 5: Templates command
    print("\n5. Testing templates command...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "threatsimgpt", "templates", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        if result.returncode == 0 and "templates" in result.stdout:
            print("✅ Templates command test passed")
        else:
            print(f"❌ Templates command test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Templates command test error: {e}")
        return False
    
    print("\n🎉 All OpenMP conflict resolution tests passed!")
    return True

def main():
    """Main test function."""
    success = test_openmp_fix()
    
    if success:
        print("\n✅ OpenMP conflicts are resolved!")
        print("You can now use ThreatSimGPT normally with the environment variables set.")
        print("\nUsage:")
        print("  export KMP_DUPLICATE_LIB_OK=TRUE")
        print("  export OMP_NUM_THREADS=1")
        print("  export MKL_NUM_THREADS=1")
        print("  export OPENBLAS_NUM_THREADS=1")
        print("  export VECLIB_MAXIMUM_THREADS=1")
        print("  python -m threatsimgpt --help")
        sys.exit(0)
    else:
        print("\n❌ OpenMP conflicts are still present!")
        print("Please check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
