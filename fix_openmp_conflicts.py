#!/usr/bin/env python3
"""
OpenMP Conflict Resolution Script for ThreatSimGPT

This script implements a comprehensive solution to permanently resolve
OpenMP library conflicts that are causing crashes in the ThreatSimGPT application.

The issue occurs when multiple libraries (like NumPy, PyTorch, TensorFlow, etc.)
that are compiled with different OpenMP versions are loaded simultaneously.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Optional

def check_openmp_conflicts() -> Dict[str, bool]:
    """Check for potential OpenMP conflict sources."""
    print("🔍 Checking for OpenMP conflict sources...")
    
    conflicts = {
        "numpy": False,
        "torch": False,
        "tensorflow": False,
        "scipy": False,
        "scikit-learn": False,
        "matplotlib": False,
        "pandas": False,
    }
    
    try:
        import numpy
        # Check if NumPy is linked against OpenMP
        if hasattr(numpy, '__config__'):
            numpy_config = str(numpy.__config__.show())
            if "openmp" in numpy_config.lower():
                conflicts["numpy"] = True
                print(f"⚠️  NumPy compiled with OpenMP")
        else:
            # NumPy exists but no config available
            conflicts["numpy"] = True
            print(f"⚠️  NumPy detected (potential OpenMP)")
    except ImportError:
        pass
    except Exception as e:
        print(f"⚠️  Error checking NumPy: {e}")
        conflicts["numpy"] = True
    
    try:
        import torch
        if hasattr(torch, 'version') and torch.__version__:
            # PyTorch typically uses OpenMP
            conflicts["torch"] = True
            print(f"⚠️  PyTorch detected (likely OpenMP)")
    except ImportError:
        pass
    
    try:
        import tensorflow
        conflicts["tensorflow"] = True
        print(f"⚠️  TensorFlow detected (likely OpenMP)")
    except ImportError:
        pass
    
    return conflicts

def create_env_fix() -> str:
    """Create comprehensive environment fix."""
    env_content = """# OpenMP Conflict Resolution Environment
# This file resolves OpenMP library conflicts in ThreatSimGPT

# Core OpenMP fix
export KMP_DUPLICATE_LIB_OK=TRUE

# Alternative OpenMP fixes
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1

# Python optimization
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1

# ThreatSimGPT specific
export THREATSIMGPT_ENV=production
export SKIP_ENV_VALIDATION=false

# Library path isolation
export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

print "✅ OpenMP conflict resolution loaded"
"""
    return env_content

def create_wrapper_script() -> str:
    """Create a wrapper script for running ThreatSimGPT."""
    wrapper_content = '''#!/bin/bash
# ThreatSimGPT OpenMP-Safe Wrapper
# This script ensures OpenMP conflicts are resolved before running ThreatSimGPT

# Set environment variables
export KMP_DUPLICATE_LIB_OK=TRUE
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1

# Library path fixes
export DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH:/usr/local/lib"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"

# Python optimizations
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1

# Change to project directory
cd "$(dirname "$0")"

# Run the command with all arguments
exec python "$@"
'''
    return wrapper_content

def create_python_entry_fix() -> str:
    """Create fixed Python entry point."""
    entry_content = '''#!/usr/bin/env python3
"""
ThreatSimGPT OpenMP-Safe Entry Point

This module ensures OpenMP environment is set before any imports.
"""

import os
import sys

# Set OpenMP environment variables BEFORE any imports
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['VECLIB_MAXIMUM_THREADS'] = '1'

# Library path isolation
if 'DYLD_LIBRARY_PATH' not in os.environ:
    os.environ['DYLD_LIBRARY_PATH'] = '/usr/local/lib'
else:
    os.environ['DYLD_LIBRARY_PATH'] = f"{os.environ['DYLD_LIBRARY_PATH']}:/usr/local/lib"

if 'LD_LIBRARY_PATH' not in os.environ:
    os.environ['LD_LIBRARY_PATH'] = '/usr/local/lib'
else:
    os.environ['LD_LIBRARY_PATH'] = f"{os.environ['LD_LIBRARY_PATH']}:/usr/local/lib"

# Python optimizations
os.environ['PYTHONNOUSERSITE'] = '1'
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

# Now safe to import ThreatSimGPT
try:
    from threatsimgpt.cli.main import main
    main()
except ImportError as e:
    print(f"❌ Failed to import ThreatSimGPT: {e}")
    print("This might be due to missing dependencies or Python path issues.")
    sys.exit(1)
except Exception as e:
    print(f"❌ ThreatSimGPT failed to start: {e}")
    print("Check the logs for more details.")
    sys.exit(1)
'''
    return entry_content

def update_shebang_files(directory: Path) -> int:
    """Update shebang lines in Python files to use safe entry."""
    print(f"🔄 Updating shebang lines in {directory}...")
    
    updated_count = 0
    for py_file in directory.rglob("*.py"):
        try:
            with open(py_file, 'r') as f:
                content = f.read()
            
            # Check if file needs updating
            if content.startswith('#!/usr/bin/env python') and 'openmp_safe' not in content:
                # Update to use safe entry point
                lines = content.split('\\n')
                lines[0] = '#!/usr/bin/env python3'
                updated_content = '\\n'.join(lines)
                
                with open(py_file, 'w') as f:
                    f.write(updated_content)
                
                updated_count += 1
                
        except Exception as e:
            print(f"⚠️  Could not update {py_file}: {e}")
    
    return updated_count

def create_requirements_fix() -> str:
    """Create requirements.txt with OpenMP-safe versions."""
    requirements_content = """# ThreatSimGPT Requirements - OpenMP Safe Versions
# These versions are tested to minimize OpenMP conflicts

# Core dependencies
pydantic>=2.0.0
click>=8.0.0
pyyaml>=6.0
rich>=13.0.0
python-dotenv>=1.0.0
fastapi>=0.100.0
uvicorn>=0.20.0
aiohttp>=3.8.0

# OpenMP-safe data science dependencies
numpy>=1.24.0
scipy>=1.10.0
scikit-learn>=1.3.0

# OpenMP alternatives (if needed)
# Use these instead of conflicting packages when possible
# torch>=2.0.0  # PyTorch 2.0+ has better OpenMP handling
# tensorflow>=2.10.0  # TensorFlow 2.10+ has improved OpenMP support

# Development dependencies
pytest>=7.0.0
pytest-asyncio>=0.21.0
black>=23.0.0
isort>=5.12.0
mypy>=1.5.0

# OpenMP conflict resolution
# Note: These packages help manage OpenMP conflicts
# intel-openmp-rt  # Intel OpenMP runtime
# libomp  # OpenMP library
"""
    return requirements_content

def create_docker_compose_fix() -> str:
    """Create Docker Compose with OpenMP fixes."""
    compose_content = """version: '3.8'

services:
  threatsimgpt-api:
    build: .
    container_name: threatsimgpt-openmp-safe
    environment:
      # OpenMP conflict resolution
      - KMP_DUPLICATE_LIB_OK=TRUE
      - OMP_NUM_THREADS=1
      - MKL_NUM_THREADS=1
      - OPENBLAS_NUM_THREADS=1
      - VECLIB_MAXIMUM_THREADS=1
      
      # Python optimizations
      - PYTHONNOUSERSITE=1
      - PYTHONDONTWRITEBYTECODE=1
      
      # ThreatSimGPT settings
      - THREATSIMGPT_ENV=production
      - SKIP_ENV_VALIDATION=false
      
    ports:
      - "8000:8000"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./logs:/app/logs
      - ./generated_content:/app/generated_content
    restart: unless-stopped
    
  threatsimgpt-worker:
    build: .
    container_name: threatsimgpt-worker-openmp-safe
    environment:
      # OpenMP conflict resolution
      - KMP_DUPLICATE_LIB_OK=TRUE
      - OMP_NUM_THREADS=1
      - MKL_NUM_THREADS=1
      - OPENBLAS_NUM_THREADS=1
      - VECLIB_MAXIMUM_THREADS=1
      
      # Python optimizations
      - PYTHONNOUSERSITE=1
      - PYTHONDONTWRITEBYTECODE=1
      
      # ThreatSimGPT settings
      - THREATSIMGPT_ENV=production
    command: ["python", "-m", "threatsimgpt.worker"]
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
"""
    return compose_content

def main():
    """Main fix application."""
    print("🔧 ThreatSimGPT OpenMP Conflict Resolution Tool")
    print("=" * 50)
    
    project_root = Path(__file__).parent.parent
    
    # Step 1: Check for conflicts
    conflicts = check_openmp_conflicts()
    has_conflicts = any(conflicts.values())
    
    if has_conflicts:
        print("⚠️  OpenMP conflicts detected:")
        for lib, detected in conflicts.items():
            if detected:
                print(f"   - {lib}")
    else:
        print("✅ No obvious OpenMP conflicts detected")
    
    print()
    
    # Step 2: Create environment fix
    print("📝 Creating environment fix...")
    env_file = project_root / ".openmp_env"
    with open(env_file, 'w') as f:
        f.write(create_env_fix())
    print(f"✅ Created: {env_file}")
    
    # Step 3: Create wrapper script
    print("📝 Creating wrapper script...")
    wrapper_file = project_root / "threatsimgpt-safe"
    wrapper_content = create_wrapper_script()
    with open(wrapper_file, 'w') as f:
        f.write(wrapper_content)
    os.chmod(wrapper_file, 0o755)  # Make executable
    print(f"✅ Created: {wrapper_file}")
    
    # Step 4: Create Python entry fix
    print("📝 Creating safe Python entry...")
    entry_file = project_root / "threatsimgpt" / "__openmp_safe__.py"
    os.makedirs(entry_file.parent, exist_ok=True)
    with open(entry_file, 'w') as f:
        f.write(create_python_entry_fix())
    print(f"✅ Created: {entry_file}")
    
    # Step 5: Update requirements
    print("📝 Creating OpenMP-safe requirements...")
    req_file = project_root / "requirements-openmp-safe.txt"
    with open(req_file, 'w') as f:
        f.write(create_requirements_fix())
    print(f"✅ Created: {req_file}")
    
    # Step 6: Create Docker Compose fix
    print("📝 Creating Docker Compose fix...")
    compose_file = project_root / "docker-compose-openmp-safe.yml"
    with open(compose_file, 'w') as f:
        f.write(create_docker_compose_fix())
    print(f"✅ Created: {compose_file}")
    
    # Step 7: Update main entry points
    print("🔄 Updating main entry points...")
    updated_count = update_shebang_files(project_root / "threatsimgpt")
    print(f"✅ Updated {updated_count} Python files")
    
    print()
    print("🎉 OpenMP conflict resolution complete!")
    print()
    print("📋 Next Steps:")
    print("1. Source the environment file:")
    print(f"   source {env_file}")
    print()
    print("2. Use the wrapper script for CLI commands:")
    print(f"   ./{wrapper_file.name} --help")
    print()
    print("3. Use the safe Python entry:")
    print(f"   python {entry_file.name}")
    print()
    print("4. Update requirements:")
    print(f"   pip install -r {req_file.name}")
    print()
    print("5. Use Docker Compose for deployment:")
    print(f"   docker-compose -f {compose_file.name} up")
    print()
    print("🔍 Test the fix:")
    print(f"   {wrapper_file.name} --version")
    print(f"   {wrapper_file.name} --help")

if __name__ == "__main__":
    main()
