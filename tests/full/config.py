"""
Enterprise Test Configuration
=============================

Central configuration for the enterprise test suite.
Defines test categories, thresholds, and runtime settings.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
import os


class TestCategory(Enum):
    """Test category classification."""
    UNIT = "unit"
    INTEGRATION = "integration"
    E2E = "e2e"
    PERFORMANCE = "performance"
    SECURITY = "security"
    PROPERTY = "property"
    MUTATION = "mutation"
    CONTRACT = "contract"
    SMOKE = "smoke"
    REGRESSION = "regression"


class TestPriority(Enum):
    """Test execution priority."""
    CRITICAL = 1  # Must pass for deployment
    HIGH = 2      # Core functionality
    MEDIUM = 3    # Important features
    LOW = 4       # Nice-to-have coverage


@dataclass
class CoverageThresholds:
    """Coverage thresholds for quality gates."""
    line_coverage: float = 80.0
    branch_coverage: float = 75.0
    function_coverage: float = 85.0
    mutation_score: float = 70.0
    
    # Per-module overrides
    module_overrides: Dict[str, float] = field(default_factory=lambda: {
        "core": 90.0,
        "llm": 75.0,
        "cli": 80.0,
        "api": 85.0,
        "safety": 95.0,
        "config": 90.0,
    })


@dataclass
class PerformanceThresholds:
    """Performance regression thresholds."""
    max_response_time_ms: float = 1000.0
    max_memory_mb: float = 512.0
    max_cpu_percent: float = 80.0
    regression_tolerance: float = 0.10  # 10% regression allowed


@dataclass
class MutationTestConfig:
    """Mutation testing configuration."""
    enabled: bool = True
    runner: str = "mutmut"  # or "cosmic-ray"
    min_kill_rate: float = 70.0
    timeout_multiplier: float = 3.0
    
    # Mutation operators to use
    operators: List[str] = field(default_factory=lambda: [
        "arithmetic",      # +, -, *, /, %
        "comparison",      # ==, !=, <, >, <=, >=
        "logical",         # and, or, not
        "assignment",      # =, +=, -=
        "statement",       # delete statements
        "constant",        # change literals
        "exception",       # modify exception handling
        "decorator",       # remove/modify decorators
    ])
    
    # Modules to exclude from mutation testing
    exclude_modules: List[str] = field(default_factory=lambda: [
        "__init__",
        "conftest",
        "test_*",
        "migrations/*",
    ])


@dataclass
class SecurityTestConfig:
    """Security testing configuration."""
    enabled: bool = True
    fuzz_iterations: int = 1000
    input_validation_tests: bool = True
    injection_tests: bool = True
    auth_bypass_tests: bool = True
    
    # Fuzzing targets
    fuzz_targets: List[str] = field(default_factory=lambda: [
        "api.endpoints",
        "cli.commands", 
        "config.loader",
        "templates.parser",
    ])


@dataclass
class EnterpriseTestConfig:
    """Master configuration for enterprise test suite."""
    
    # Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    test_root: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    src_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "src" / "threatsimgpt")
    
    # Test execution settings
    parallel_workers: int = field(default_factory=lambda: os.cpu_count() or 4)
    timeout_seconds: int = 300
    fail_fast: bool = False
    verbose: bool = True
    
    # Category-specific configs
    coverage: CoverageThresholds = field(default_factory=CoverageThresholds)
    performance: PerformanceThresholds = field(default_factory=PerformanceThresholds)
    mutation: MutationTestConfig = field(default_factory=MutationTestConfig)
    security: SecurityTestConfig = field(default_factory=SecurityTestConfig)
    
    # Test markers for pytest
    markers: Dict[str, str] = field(default_factory=lambda: {
        "unit": "Unit tests - fast, isolated, no external deps",
        "integration": "Integration tests - test module interactions",
        "e2e": "End-to-end tests - full workflow testing",
        "performance": "Performance benchmark tests",
        "security": "Security and vulnerability tests",
        "property": "Property-based tests using Hypothesis",
        "mutation": "Mutation testing validation",
        "contract": "API contract tests",
        "smoke": "Quick smoke tests for CI",
        "regression": "Regression tests for fixed bugs",
        "slow": "Tests that take >1s",
        "requires_api_key": "Tests requiring real API keys",
        "requires_db": "Tests requiring database",
        "requires_network": "Tests requiring network access",
    })
    
    # Test data directories
    fixtures_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "fixtures")
    mocks_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "mocks")
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "data")
    
    @classmethod
    def from_env(cls) -> "EnterpriseTestConfig":
        """Create config from environment variables."""
        config = cls()
        
        # Override from environment
        if os.getenv("TEST_PARALLEL_WORKERS"):
            config.parallel_workers = int(os.getenv("TEST_PARALLEL_WORKERS"))
        if os.getenv("TEST_TIMEOUT"):
            config.timeout_seconds = int(os.getenv("TEST_TIMEOUT"))
        if os.getenv("TEST_FAIL_FAST"):
            config.fail_fast = os.getenv("TEST_FAIL_FAST").lower() == "true"
        if os.getenv("TEST_COVERAGE_MIN"):
            config.coverage.line_coverage = float(os.getenv("TEST_COVERAGE_MIN"))
        if os.getenv("TEST_MUTATION_MIN"):
            config.mutation.min_kill_rate = float(os.getenv("TEST_MUTATION_MIN"))
            
        return config


# Global config instance
CONFIG = EnterpriseTestConfig.from_env()
