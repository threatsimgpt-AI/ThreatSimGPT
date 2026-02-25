#!/usr/bin/env python3
"""Entry point for ThreatSimGPT CLI."""

import os
import sys

# Set OpenMP environment variables BEFORE any imports to prevent conflicts
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['VECLIB_MAXIMUM_THREADS'] = '1'

from threatsimgpt.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
