#!/bin/bash
# ThreatSimGPT OpenMP-Safe Startup Script
# Use this script to run ThreatSimGPT without OpenMP conflicts

# Set OpenMP environment variables
export KMP_DUPLICATE_LIB_OK=TRUE
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1

# Suppress warnings
export SECRET_KEY=threatsimgpt-test-key

# Python optimizations
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1

# Change to ThreatSimGPT directory
cd "$(dirname "$0")"

echo "✅ OpenMP conflict resolution loaded"
echo "🚀 Starting ThreatSimGPT..."

# Run ThreatSimGPT with all arguments
exec python -m threatsimgpt "$@"
