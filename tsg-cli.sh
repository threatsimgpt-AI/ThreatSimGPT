#!/bin/bash
# ThreatSimGPT CLI Launcher - TSG Environment
# This script activates the tsg conda environment and runs ThreatSimGPT CLI

# Check if tsg environment exists
if ! conda env list | grep -q "tsg"; then
    echo "❌ Error: tsg conda environment not found"
    echo "Please run: conda create -n tsg python=3.11"
    exit 1
fi

# Activate tsg environment
echo "🚀 Activating tsg environment..."
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate tsg

# Set environment variables
export SECRET_KEY=threatsimgpt-production-key-$(date +%s)
export KMP_DUPLICATE_LIB_OK=TRUE
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1

# Change to ThreatSimGPT directory
cd "$(dirname "$0")"

echo "✅ tsg environment activated"
echo "🔧 Environment variables set"
echo "📁 Working directory: $(pwd)"
echo ""
echo "🎯 Available commands:"
echo "   threatsimgpt --help                    # Show all commands"
echo "   threatsimgpt rag --help                # RAG system"
echo "   threatsimgpt intel --help              # Intelligence gathering"
echo "   threatsimgpt simulate --help           # Threat simulation"
echo "   threatsimgpt templates --help          # Template management"
echo "   threatsimgpt status                   # System status"
echo ""

# Run ThreatSimGPT with all arguments
exec threatsimgpt "$@"
