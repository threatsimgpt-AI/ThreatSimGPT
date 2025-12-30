"""Global test fixtures for ThreatSimGPT test suite."""

import pytest
import asyncio
from pathlib import Path
from typing import Dict, Any, Generator
from unittest.mock import Mock, AsyncMock
from datetime import datetime

import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from threatsimgpt.core.models import (
    ThreatScenario,
    ThreatType,
    SimulationStatus
)
from threatsimgpt.llm.base import BaseLLMProvider, LLMResponse


# ==========================================
# Pytest Configuration
# ==========================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "requires_api_key: Tests requiring API keys")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==========================================
# Mock LLM Provider
# ==========================================

class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider for testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.call_count = 0
        self.responses = []
        self._fail_on_call = None  # For testing error handling
    
    async def generate_content(
        self, 
        prompt: str, 
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """Generate mock response."""
        self.call_count += 1
        
        # Simulate failure if requested
        if self._fail_on_call == self.call_count:
            raise RuntimeError("Mock LLM provider error")
        
        content = f"Mock LLM response #{self.call_count} for prompt: {prompt[:50]}..."
        
        response = LLMResponse(
            content=content,
            provider="mock",
            model="mock-model-v1"
        )
        response.is_real_ai = False
        
        self.responses.append(response)
        return response
    
    def is_available(self) -> bool:
        """Check if provider is available."""
        return True
    
    def set_fail_on_call(self, call_number: int):
        """Set which call number should fail (for error testing)."""
        self._fail_on_call = call_number


@pytest.fixture
def mock_llm_provider():
    """Provide mock LLM provider."""
    return MockLLMProvider()


@pytest.fixture
def mock_llm_manager(mock_llm_provider):
    """Provide mock LLM manager."""
    try:
        from src.threatsimgpt.llm.manager import LLMManager
        manager = LLMManager(config={"default_provider": "mock"})
        manager._providers = {"mock": mock_llm_provider}
        manager._active_provider = mock_llm_provider
        return manager
    except ImportError:
        # Return mock object if LLMManager doesn't exist yet
        mock_manager = Mock()
        mock_manager.generate_content = mock_llm_provider.generate_content
        return mock_manager


# ==========================================
# Test Scenarios
# ==========================================

@pytest.fixture
def simple_threat_scenario():
    """Provide simple threat scenario for testing."""
    return ThreatScenario(
        name="Test Phishing Scenario",
        threat_type=ThreatType.PHISHING,
        description="Basic phishing test scenario",
        severity="medium",
        target_systems=["email"],
        attack_vectors=["social_engineering"]
    )


@pytest.fixture
def complex_threat_scenario():
    """Provide complex threat scenario for testing."""
    return ThreatScenario(
        name="Advanced APT Scenario",
        threat_type=ThreatType.NETWORK_INTRUSION,
        description="Multi-stage advanced persistent threat",
        severity="critical",
        target_systems=["network", "endpoints", "data"],
        attack_vectors=["phishing", "lateral_movement", "data_exfiltration"],
        metadata={
            "mitre_attack": ["T1566.001", "T1078", "T1041"],
            "difficulty": 9,
            "estimated_duration": 120
        }
    )


@pytest.fixture
def sample_threat_scenario() -> dict[str, Any]:
    """Sample threat scenario configuration for testing (legacy)."""
    return {
        "name": "Test Phishing Scenario",
        "description": "A test phishing scenario for unit testing",
        "threat_type": "phishing",
        "delivery_vector": "email",
        "target_profile": {
            "role": "Manager",
            "seniority": "mid",
            "department": "IT",
            "technical_level": "high",
            "industry": "technology",
            "company_size": "medium"
        },
        "difficulty_level": 5,
        "estimated_duration": 30,
        "mitre_attack_techniques": ["T1566.001", "T1566.002"],
        "simulation_parameters": {
            "max_iterations": 3,
            "escalation_enabled": True,
            "response_adaptation": True,
            "time_pressure_simulation": False
        }
    }


# ==========================================
# Test Configuration
# ==========================================

@pytest.fixture
def test_config():
    """Provide test configuration dictionary."""
    return {
        "llm": {
            "default_provider": "mock",
            "mock": {
                "api_key": "test-key",
                "model": "mock-model-v1"
            }
        },
        "simulation": {
            "max_stages": 5,
            "enable_safety_checks": True
        },
        "logging": {
            "level": "DEBUG",
            "enable_console_logging": True
        }
    }


@pytest.fixture
def test_config_file(tmp_path):
    """Create temporary config file for testing."""
    config_path = tmp_path / "test_config.yaml"
    config_content = """
llm:
  default_provider: "mock"
  mock:
    api_key: "test-key"
    model: "mock-model-v1"

simulation:
  max_stages: 5
  enable_safety_checks: true

logging:
  level: "DEBUG"
  enable_console_logging: true
"""
    config_path.write_text(config_content)
    return config_path


@pytest.fixture
def test_database_url() -> str:
    """Test database URL."""
    return "sqlite:///test_threatsimgpt.db"


@pytest.fixture
def test_redis_url() -> str:
    """Test Redis URL."""
    return "redis://localhost:6379/1"


@pytest.fixture
def mock_llm_response() -> str:
    """Mock LLM response for testing (legacy)."""
    return "This is a simulated threat content for testing purposes."


# ==========================================
# Database Fixtures
# ==========================================

@pytest.fixture
def mock_database():
    """Provide mock database connection."""
    db = Mock()
    db.execute = AsyncMock(return_value=[])
    db.fetch = AsyncMock(return_value=[])
    db.fetchrow = AsyncMock(return_value=None)
    db.fetchval = AsyncMock(return_value=None)
    db.close = AsyncMock()
    return db


# ==========================================
# Template Fixtures
# ==========================================

@pytest.fixture
def sample_template_yaml(tmp_path):
    """Create sample YAML template for testing."""
    template_path = tmp_path / "test_template.yaml"
    template_content = """
metadata:
  name: "Test Executive Phishing"
  description: "Test template for executive phishing"
  version: "1.0.0"
  author: "Test Suite"

threat_type: phishing
delivery_vector: email
difficulty_level: 7
estimated_duration: 30

target_profile:
  role: "CEO"
  seniority: "c_level"
  department: "executive"
  technical_level: "moderate"

behavioral_pattern:
  mitre_attack_techniques:
    - "T1566.001"
  psychological_triggers:
    - "authority"
    - "urgency"
"""
    template_path.write_text(template_content)
    return template_path


# ==========================================
# Cleanup Fixtures
# ==========================================

@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Automatically cleanup test files after each test."""
    yield
    # Cleanup happens automatically with tmp_path


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging configuration after each test."""
    import logging
    yield
    # Reset logging to prevent test interference
    logging.getLogger("threatsimgpt").handlers = []
    logging.getLogger("threatsimgpt").setLevel(logging.WARNING)


# Test markers
pytest_plugins = []