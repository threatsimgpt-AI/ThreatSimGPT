# ThreatSimGPT Developer Guide

**Version:** 1.0.0  
**Last Updated:** November 2025

Comprehensive guide for contributing to ThreatSimGPT, understanding the architecture, and developing new features.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Architecture](#project-architecture)
3. [Code Standards](#code-standards)
4. [Testing](#testing)
5. [Contributing](#contributing)
6. [Module Documentation](#module-documentation)

---

## Development Setup

### Prerequisites

- Python 3.11+
- Git
- Poetry (recommended) or pip
- IDE (VS Code, PyCharm recommended)

### Initial Setup

```bash
# Clone repository
git clone https://github.com/threatsimgpt-AI/ThreatSimGPT.git
cd ThreatSimGPT

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
.\.venv\Scripts\Activate.ps1  # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Development Dependencies

```bash
# Code quality
black                 # Code formatting
isort                 # Import sorting
flake8                # Linting
mypy                  # Type checking
bandit                # Security analysis

# Testing
pytest                # Test framework
pytest-cov            # Coverage reporting
pytest-asyncio        # Async test support

# Documentation
sphinx                # Documentation generation
mkdocs                # Alternative docs
```

---

## Project Architecture

### Directory Structure

```
ThreatSimGPT/
├── src/
│   └── threatsimgpt/
│       ├── __init__.py
│       ├── __main__.py          # CLI entry point
│       ├── api/                 # REST API
│       │   ├── __init__.py
│       │   └── main.py          # FastAPI application
│       ├── cli/                 # Command-line interface
│       │   ├── main.py          # CLI commands
│       │   ├── templates.py     # Template management
│       │   ├── simulate.py      # Simulation commands
│       │   └── llm.py           # LLM commands
│       ├── core/                # Core simulation engine
│       │   ├── models.py        # Data models
│       │   ├── simulator.py     # Simulation orchestration
│       │   └── template_manager_pro.py
│       ├── llm/                 # LLM integration
│       │   ├── manager.py       # LLM provider manager
│       │   ├── providers/       # Provider implementations
│       │   ├── enhanced_prompts.py  # Prompt engineering
│       │   ├── validation.py    # Content validation
│       │   └── generation.py    # Content generation
│       ├── config/              # Configuration management
│       │   ├── loader.py
│       │   ├── validator.py
│       │   └── models.py
│       ├── intelligence/        # Threat intelligence
│       │   └── services.py
│       ├── datasets/            # Dataset processors
│       │   └── processors/
│       └── utils/               # Utilities
│           └── logging.py
├── templates/                   # Scenario templates
├── tests/                       # Test suite
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── config.yaml                  # Configuration
└── requirements.txt             # Dependencies
```

### Core Components

#### 1. Simulator Engine (`core/simulator.py`)

The core threat simulation orchestrator:

```python
class ThreatSimulator:
    """Main simulation engine."""
    
    async def execute_simulation(
        self, 
        scenario: ThreatScenario
    ) -> SimulationResult:
        """Execute threat simulation."""
        # Stage execution logic
        # Content generation
        # Validation
```

**Key Methods:**
- `execute_simulation()`: Main simulation orchestration
- `_generate_stage_content()`: LLM content generation
- `_create_scenario_generation_prompt()`: Prompt engineering

#### 2. LLM Manager (`llm/manager.py`)

Manages multiple LLM providers:

```python
class LLMManager:
    """Multi-provider LLM manager."""
    
    async def generate_content(
        self,
        prompt: str,
        scenario_type: str,
        max_tokens: int = 1000
    ) -> LLMResponse:
        """Generate content using configured provider."""
```

**Features:**
- Provider abstraction
- Automatic fallback
- Response validation
- Safety filtering

#### 3. Configuration System (`config/`)

YAML-based configuration with validation:

```python
class ConfigLoader:
    """Load and validate configuration."""
    
    def load_config(
        self, 
        config_path: Path
    ) -> Dict[str, Any]:
        """Load configuration from YAML."""
```

#### 4. Template Manager (`core/template_manager_pro.py`)

Professional template management:

```python
class TemplateManagerPro:
    """Advanced template management."""
    
    def validate_template(
        self, 
        template_path: Path
    ) -> ValidationResult:
        """Validate template against schema."""
```

---

## Code Standards

### Code Formatting

Use Black for consistent formatting:

```bash
# Format all code
black src/ tests/

# Check without modifying
black --check src/ tests/
```

### Import Sorting

Use isort for consistent imports:

```bash
# Sort imports
isort src/ tests/

# Check without modifying
isort --check-only src/ tests/
```

### Type Hints

All functions must have type hints:

```python
from typing import Optional, List, Dict, Any

def generate_content(
    prompt: str,
    max_tokens: int = 1000,
    temperature: float = 0.7
) -> Optional[str]:
    """Generate content with LLM.
    
    Args:
        prompt: The generation prompt
        max_tokens: Maximum tokens to generate
        temperature: Generation temperature (0.0-1.0)
        
    Returns:
        Generated content or None if failed
    """
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def complex_function(
    param1: str,
    param2: int,
    param3: Optional[Dict] = None
) -> List[str]:
    """Short description of function.
    
    Longer description explaining behavior, edge cases,
    and important implementation details.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter  
        param3: Optional parameter description
        
    Returns:
        List of result strings
        
    Raises:
        ValueError: When param2 is negative
        RuntimeError: When processing fails
        
    Example:
        >>> result = complex_function("test", 5)
        >>> print(result)
        ['processed', 'results']
    """
    pass
```

### Linting

Run flake8 for style checking:

```bash
# Lint all code
flake8 src/ tests/

# Configuration in .flake8
[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude = .git,__pycache__,.venv
```

### Type Checking

Use mypy for static type analysis:

```bash
# Check types
mypy src/

# Configuration in setup.cfg
[mypy]
python_version = 3.11
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
```

---

## Testing

### Test Structure

```
tests/
├── conftest.py              # Shared fixtures
├── unit/                    # Unit tests
│   ├── test_simulator.py
│   ├── test_llm_manager.py
│   └── test_validation.py
├── integration/             # Integration tests
│   ├── test_api.py
│   └── test_cli.py
└── e2e/                     # End-to-end tests
    └── test_simulation_flow.py
```

### Writing Tests

```python
import pytest
from threatsimgpt.core.simulator import ThreatSimulator

def test_simulator_initialization():
    """Test simulator creates successfully."""
    simulator = ThreatSimulator()
    assert simulator is not None
    assert simulator.max_stages == 10

@pytest.mark.asyncio
async def test_content_generation():
    """Test LLM content generation."""
    simulator = ThreatSimulator()
    scenario = create_test_scenario()
    
    content = await simulator._generate_stage_content(
        scenario, "phishing", "Generate email"
    )
    
    assert content is not None
    assert len(content) > 0
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_simulator.py

# Run with coverage
pytest --cov=src/threatsimgpt --cov-report=html

# Run specific test
pytest tests/unit/test_simulator.py::test_simulator_initialization

# Run with markers
pytest -m "not slow"
```

### Test Fixtures

Define reusable fixtures in `conftest.py`:

```python
import pytest
from threatsimgpt.core.models import ThreatScenario

@pytest.fixture
def sample_scenario():
    """Create sample threat scenario."""
    return ThreatScenario(
        name="Test Phishing",
        threat_type="phishing",
        description="Test scenario",
        difficulty_level=5
    )

@pytest.fixture
async def llm_manager():
    """Create LLM manager for testing."""
    from threatsimgpt.llm.manager import LLMManager
    return LLMManager()
```

---

## Contributing

### Contribution Workflow

1. **Fork Repository**
   ```bash
   # Fork on GitHub, then clone
   git clone https://github.com/YOUR_USERNAME/ThreatSimGPT.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Write code following standards
   - Add tests for new features
   - Update documentation

4. **Run Quality Checks**
   ```bash
   # Format code
   black src/ tests/
   isort src/ tests/
   
   # Lint
   flake8 src/ tests/
   
   # Type check
   mypy src/
   
   # Security scan
   bandit -r src/
   
   # Run tests
   pytest --cov=src/threatsimgpt
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   # Create pull request on GitHub
   ```

### Commit Message Convention

Use conventional commits:

```
feat: add new feature
fix: bug fix
docs: documentation changes
style: formatting changes
refactor: code refactoring
test: add or update tests
chore: maintenance tasks
```

### Code Review Process

1. Automated checks run on PR
2. Maintainer reviews code
3. Address feedback
4. Approval and merge

---

## Module Documentation

### Adding New LLM Provider

1. **Create Provider Class**

```python
# src/threatsimgpt/llm/providers/my_provider.py

from typing import Optional
from threatsimgpt.llm.base import BaseLLMProvider
from threatsimgpt.llm.models import LLMResponse

class MyProvider(BaseLLMProvider):
    """Custom LLM provider implementation."""
    
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
    
    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7
    ) -> LLMResponse:
        """Generate content using provider."""
        # Implementation
        pass
    
    def is_available(self) -> bool:
        """Check if provider is available."""
        return self.api_key is not None
```

2. **Register Provider**

```python
# src/threatsimgpt/llm/manager.py

from threatsimgpt.llm.providers.my_provider import MyProvider

class LLMManager:
    def __init__(self):
        # Add to providers
        if config.get("my_provider"):
            self.providers["my_provider"] = MyProvider(
                api_key=config["my_provider"]["api_key"],
                model=config["my_provider"]["model"]
            )
```

3. **Add Configuration**

```yaml
# config.yaml
llm:
  my_provider:
    api_key: "${MY_PROVIDER_API_KEY}"
    model: "my-model-name"
    max_tokens: 1000
```

### Adding New CLI Command

1. **Create Command Module**

```python
# src/threatsimgpt/cli/mycommand.py

import click

@click.command()
@click.option('--option', help='Description')
def my_command(option: str):
    """My custom command description."""
    click.echo(f"Executing with: {option}")
```

2. **Register in Main CLI**

```python
# src/threatsimgpt/cli/main.py

from threatsimgpt.cli.mycommand import my_command

@click.group()
def cli():
    """ThreatSimGPT CLI."""
    pass

cli.add_command(my_command)
```

---

## Debugging

### Enable Debug Logging

```yaml
# config.yaml
logging:
  level: "DEBUG"
```

```bash
# Or via environment
export THREATSIMGPT_LOG_LEVEL=DEBUG
```

### Using Python Debugger

```python
# Add breakpoint
import pdb; pdb.set_trace()

# Or Python 3.7+
breakpoint()
```

### VS Code Debug Configuration

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: ThreatSimGPT CLI",
      "type": "python",
      "request": "launch",
      "module": "threatsimgpt.cli.main",
      "args": ["simulate", "-s", "templates/executive_phishing.yaml"],
      "console": "integratedTerminal"
    }
  ]
}
```

---

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Run full test suite
4. Create git tag
5. Build distribution
6. Publish to PyPI

```bash
# Build
python -m build

# Publish
python -m twine upload dist/*
```

---

## Additional Resources

- **API Documentation:** API_DOCUMENTATION.md
- **User Guide:** USER_GUIDE.md
- **Configuration:** CONFIGURATION_REFERENCE.md
- **Security:** SECURITY_GUIDE.md

---

## Support

- **Issues:** https://github.com/threatsimgpt-AI/ThreatSimGPT/issues
- **Discussions:** https://github.com/threatsimgpt-AI/ThreatSimGPT/discussions
- **Email:** threatsimgpt@hotmail.com
