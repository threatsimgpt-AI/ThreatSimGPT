"""
Enterprise Test Fixtures
========================

Comprehensive pytest fixtures for enterprise-grade testing.
Includes fixtures for all test categories and modules.
"""

import pytest
import asyncio
import os
import sys
import tempfile
import json
from pathlib import Path
from typing import Dict, Any, Generator, AsyncGenerator, List
from unittest.mock import Mock, AsyncMock, MagicMock, patch
from datetime import datetime
from dataclasses import dataclass

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from .factories import (
    ThreatScenarioFactory,
    TargetProfileFactory,
    SimulationResultFactory,
    LLMResponseFactory,
    ConfigFactory,
    TemplateFactory,
    APIRequestFactory,
    Faker,
    reset_all_factories,
)
from .utils import (
    temp_directory,
    temp_yaml_file,
    temp_json_file,
    env_vars,
    MockFactory,
    Timer,
)


# ==========================================
# Session-Scoped Fixtures
# ==========================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Get project root directory."""
    return Path(__file__).parent.parent.parent


@pytest.fixture(scope="session")
def src_root(project_root) -> Path:
    """Get source root directory."""
    return project_root / "src" / "threatsimgpt"


@pytest.fixture(scope="session")
def templates_root(project_root) -> Path:
    """Get templates directory."""
    return project_root / "templates"


@pytest.fixture(scope="session")
def test_data_root() -> Path:
    """Get test data directory."""
    test_data = Path(__file__).parent / "data"
    test_data.mkdir(exist_ok=True)
    return test_data


# ==========================================
# Factory Reset Fixture
# ==========================================

@pytest.fixture(autouse=True)
def reset_factories():
    """Reset all factory sequences before each test."""
    reset_all_factories()
    yield


# ==========================================
# Configuration Fixtures
# ==========================================

@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Basic test configuration."""
    return ConfigFactory.build()


@pytest.fixture
def minimal_config() -> Dict[str, Any]:
    """Minimal configuration for fast tests."""
    return ConfigFactory.minimal()


@pytest.fixture
def production_config() -> Dict[str, Any]:
    """Production-like configuration."""
    return ConfigFactory.production()


@pytest.fixture
def config_file(test_config, tmp_path) -> Path:
    """Create a temporary config file."""
    import yaml
    config_path = tmp_path / "config.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(test_config, f)
    return config_path


# ==========================================
# Mock LLM Fixtures
# ==========================================

@pytest.fixture
def mock_llm_provider():
    """Provide mock LLM provider."""
    return MockFactory.llm_provider()


@pytest.fixture
def mock_llm_provider_failing():
    """Provide mock LLM provider that fails on first call."""
    return MockFactory.llm_provider(fail_on_call=1)


@pytest.fixture
def mock_openai_response():
    """Mock OpenAI API response."""
    return {
        "choices": [{
            "message": {"content": "Mock OpenAI response"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 50,
            "completion_tokens": 100,
            "total_tokens": 150
        },
        "model": "gpt-4"
    }


@pytest.fixture
def mock_anthropic_response():
    """Mock Anthropic API response."""
    return {
        "content": [{"text": "Mock Anthropic response"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 50,
            "output_tokens": 100
        },
        "model": "claude-3-sonnet"
    }


# ==========================================
# Threat Scenario Fixtures
# ==========================================

@pytest.fixture
def simple_scenario() -> Dict[str, Any]:
    """Simple threat scenario."""
    return ThreatScenarioFactory.build()


@pytest.fixture
def phishing_scenario() -> Dict[str, Any]:
    """Phishing scenario."""
    return ThreatScenarioFactory.phishing()


@pytest.fixture
def ransomware_scenario() -> Dict[str, Any]:
    """Ransomware scenario."""
    return ThreatScenarioFactory.ransomware()


@pytest.fixture
def apt_scenario() -> Dict[str, Any]:
    """APT scenario."""
    return ThreatScenarioFactory.apt()


@pytest.fixture
def scenario_batch() -> List[Dict[str, Any]]:
    """Batch of scenarios for bulk testing."""
    return ThreatScenarioFactory.build_batch(10)


# ==========================================
# Target Profile Fixtures
# ==========================================

@pytest.fixture
def target_profile() -> Dict[str, Any]:
    """Basic target profile."""
    return TargetProfileFactory.build()


@pytest.fixture
def executive_target() -> Dict[str, Any]:
    """Executive target profile."""
    return TargetProfileFactory.executive()


@pytest.fixture
def it_admin_target() -> Dict[str, Any]:
    """IT admin target profile."""
    return TargetProfileFactory.it_admin()


# ==========================================
# Simulation Fixtures
# ==========================================

@pytest.fixture
def simulation_result() -> Dict[str, Any]:
    """Successful simulation result."""
    return SimulationResultFactory.build()


@pytest.fixture
def failed_simulation_result() -> Dict[str, Any]:
    """Failed simulation result."""
    return SimulationResultFactory.build(
        status="failed",
        success=False
    )


# ==========================================
# Template Fixtures
# ==========================================

@pytest.fixture
def template_data() -> Dict[str, Any]:
    """Basic template data."""
    return TemplateFactory.build()


@pytest.fixture
def template_file(tmp_path) -> Path:
    """Create a temporary template file."""
    content = TemplateFactory.yaml_content()
    path = tmp_path / "test_template.yaml"
    path.write_text(content)
    return path


@pytest.fixture
def templates_directory(tmp_path) -> Path:
    """Create a temporary templates directory with files."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    
    for name in ["phishing", "ransomware", "bec"]:
        content = TemplateFactory.yaml_content(name=f"test_{name}")
        (templates_dir / f"{name}.yaml").write_text(content)
    
    return templates_dir


# ==========================================
# API Fixtures
# ==========================================

@pytest.fixture
def api_request() -> Dict[str, Any]:
    """API simulate request."""
    return APIRequestFactory.simulate_request()


@pytest.fixture
def generate_request() -> Dict[str, Any]:
    """API generate request."""
    return APIRequestFactory.generate_request()


@pytest.fixture
def mock_http_client():
    """Mock HTTP client for API tests."""
    mock = AsyncMock()
    mock.get = AsyncMock(return_value=MockFactory.async_http_response())
    mock.post = AsyncMock(return_value=MockFactory.async_http_response())
    mock.put = AsyncMock(return_value=MockFactory.async_http_response())
    mock.delete = AsyncMock(return_value=MockFactory.async_http_response())
    return mock


# ==========================================
# Database Fixtures
# ==========================================

@pytest.fixture
def mock_db_session():
    """Mock database session."""
    return MockFactory.database_session()


@pytest.fixture
async def test_database(tmp_path):
    """Create a test SQLite database."""
    db_path = tmp_path / "test.db"
    # Simple SQLite for testing
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    yield conn
    conn.close()


# ==========================================
# File System Fixtures
# ==========================================

@pytest.fixture
def temp_workspace(tmp_path) -> Path:
    """Create a temporary workspace directory."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    
    # Create standard structure
    (workspace / "templates").mkdir()
    (workspace / "output").mkdir()
    (workspace / "logs").mkdir()
    (workspace / "config").mkdir()
    
    return workspace


@pytest.fixture
def mock_filesystem():
    """Mock file system for testing."""
    return MockFactory.file_system({
        "config.yaml": "llm:\n  provider: mock",
        "template.yaml": "name: test\ntype: phishing",
    })


# ==========================================
# Environment Fixtures
# ==========================================

@pytest.fixture
def clean_env():
    """Clean environment without ThreatSimGPT variables."""
    original = {}
    prefixes = ["THREATSIMGPT_", "OPENAI_", "ANTHROPIC_"]
    
    for key in list(os.environ.keys()):
        for prefix in prefixes:
            if key.startswith(prefix):
                original[key] = os.environ.pop(key)
                break
    
    yield
    
    os.environ.update(original)


@pytest.fixture
def mock_env():
    """Mock environment with test API keys."""
    with env_vars(
        THREATSIMGPT_ENV="test",
        OPENAI_API_KEY="sk-test-" + "x" * 45,
        ANTHROPIC_API_KEY="sk-ant-test-" + "x" * 45,
    ):
        yield


# ==========================================
# Performance Testing Fixtures
# ==========================================

@pytest.fixture
def performance_timer():
    """Timer for performance tests."""
    return Timer()


@pytest.fixture
def performance_baseline() -> Dict[str, float]:
    """Baseline performance metrics."""
    return {
        "template_load_ms": 50.0,
        "scenario_generation_ms": 500.0,
        "simulation_step_ms": 100.0,
        "api_response_ms": 200.0,
    }


# ==========================================
# Security Testing Fixtures
# ==========================================

@pytest.fixture
def malicious_inputs() -> List[str]:
    """List of malicious input strings for security testing."""
    return [
        # SQL Injection
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'--",
        
        # XSS
        "<script>alert('xss')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        
        # Command Injection
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        
        # Path Traversal
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f",
        
        # Template Injection
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        
        # LDAP Injection
        "*)(uid=*))(|(uid=*",
        
        # XML Injection
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        
        # Format String
        "%s%s%s%s%s",
        "{0}{1}{2}",
        
        # Unicode attacks
        "\u0000",
        "\uffff",
        "A" * 10000,  # Buffer overflow attempt
    ]


@pytest.fixture
def sensitive_patterns() -> List[str]:
    """Patterns that should never appear in output."""
    return [
        r'password\s*[:=]',
        r'secret\s*[:=]',
        r'api[_-]?key\s*[:=]',
        r'token\s*[:=]',
        r'sk-[a-zA-Z0-9]{40,}',
        r'bearer\s+[a-zA-Z0-9]{20,}',
    ]


# ==========================================
# CLI Testing Fixtures
# ==========================================

@pytest.fixture
def cli_runner():
    """Click CLI test runner."""
    from click.testing import CliRunner
    return CliRunner()


@pytest.fixture
def cli_isolated_filesystem(cli_runner):
    """CLI runner with isolated filesystem."""
    with cli_runner.isolated_filesystem():
        yield cli_runner


# ==========================================
# Async Testing Fixtures
# ==========================================

@pytest.fixture
def async_mock():
    """Generic async mock."""
    return AsyncMock()


@pytest.fixture
async def async_context():
    """Async context for tests."""
    yield {"started": datetime.utcnow()}


# ==========================================
# Logging Fixtures
# ==========================================

@pytest.fixture
def captured_logs(caplog):
    """Fixture for capturing logs."""
    import logging
    caplog.set_level(logging.DEBUG)
    return caplog


# ==========================================
# Snapshot Testing Fixtures
# ==========================================

@pytest.fixture
def snapshot_dir(tmp_path) -> Path:
    """Directory for snapshot testing."""
    snap_dir = tmp_path / "snapshots"
    snap_dir.mkdir()
    return snap_dir


# ==========================================
# Markers Configuration
# ==========================================

def pytest_configure(config):
    """Configure pytest with enterprise markers."""
    markers = {
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
    }
    
    for name, description in markers.items():
        config.addinivalue_line("markers", f"{name}: {description}")


# ==========================================
# Collection Hooks
# ==========================================

def pytest_collection_modifyitems(config, items):
    """Modify test collection for enterprise testing."""
    # Auto-mark slow tests
    for item in items:
        if "slow" in item.nodeid or "e2e" in item.nodeid:
            item.add_marker(pytest.mark.slow)
        
        # Auto-mark integration tests
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
