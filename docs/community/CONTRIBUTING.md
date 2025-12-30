# Contributing to ThreatSimGPT

We welcome contributions to ThreatSimGPT! This document provides guidance on how to contribute effectively to the project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a welcoming environment for all contributors.

## Getting Started

### Development Environment Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/your-username/threatsimgpt.git
   cd threatsimgpt
   ```

2. **Set up Python Environment**
   ```bash
   # Ensure you have Python 3.11+ installed
   python --version

   # Create virtual environment
   python -m venv .venv

   # Activate virtual environment
   # On Windows:
   .venv\Scripts\activate
   # On macOS/Linux:
   source .venv/bin/activate

   # Install the project in development mode
   pip install -e .

   # Install development dependencies
   pip install pytest pytest-asyncio pytest-cov pytest-mock black flake8 mypy pre-commit isort bandit safety coverage
   ```

   **Alternative: Using Poetry (if installed)**
   ```bash
   # Install Poetry
   curl -sSL https://install.python-poetry.org | python3 -

   # Install dependencies
   poetry install --with dev,test

   # Activate virtual environment
   poetry shell
   ```

3. **Set up Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

4. **Set up Environment Variables**
   ```bash
   # Copy example environment file (if it exists)
   cp .env.example .env  # On macOS/Linux
   copy .env.example .env  # On Windows
   
   # Or set environment variables directly:
   # For OpenAI
   export OPENAI_API_KEY="your-openai-key-here"  # macOS/Linux
   set OPENAI_API_KEY=your-openai-key-here       # Windows CMD
   $env:OPENAI_API_KEY="your-openai-key-here"    # Windows PowerShell
   
   # For Anthropic
   export ANTHROPIC_API_KEY="your-anthropic-key-here"
   
   # For OpenRouter (recommended for testing multiple models)
   export OPENROUTER_API_KEY="your-openrouter-key-here"
   ```

5. **Run Tests**
   ```bash
   python -m pytest
   ```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Write clean, well-documented code
- Follow the existing code style and patterns
- Add tests for new functionality
- Update documentation as needed

### 3. Run Quality Checks

```bash
# Format code
python -m black src/ tests/
python -m isort src/ tests/

# Run linting
python -m flake8 src/ tests/
python -m mypy src/

# Run security checks
python -m bandit -r src/
python -m safety check

# Run all pre-commit checks (if pre-commit is set up)
pre-commit run --all-files
```

### 4. Run Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=src/threatsimgpt --cov-report=html

# Run specific test types
python -m pytest -m unit          # Unit tests only
python -m pytest -m integration   # Integration tests only
python -m pytest -m e2e          # End-to-end tests only
```

### 5. Commit Your Changes

```bash
git add .
git commit -m "feat: add new threat simulation capability"
```

**Commit Message Format:**
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Test additions or modifications
- `chore:` - Maintenance tasks

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots or examples if applicable

## Code Style Guidelines

### Python Code Style

- **PEP 8 Compliance**: Follow PEP 8 style guidelines
- **Line Length**: Maximum 88 characters (Black formatter)
- **Type Hints**: Use type hints for all function parameters and return values
- **Docstrings**: Use Google-style docstrings for all public functions and classes

### Example Code Style

```python
from typing import List, Optional
import asyncio

async def simulate_threat(
    scenario: ThreatScenario,
    target_profile: TargetProfile,
    safety_check: bool = True,
) -> SimulationResult:
    """Execute a threat simulation scenario.
    
    Args:
        scenario: The threat scenario configuration to execute.
        target_profile: Profile of the simulation target.
        safety_check: Whether to perform safety validation.
        
    Returns:
        The simulation execution result.
        
    Raises:
        SimulationError: If simulation execution fails.
        SafetyViolationError: If safety checks fail.
    """
    if safety_check:
        await validate_safety(scenario)
    
    result = await execute_simulation(scenario, target_profile)
    return result
```

### Documentation Standards

- **README Updates**: Update README.md for user-facing changes
- **API Documentation**: Document all public APIs using docstrings
- **Configuration Documentation**: Document new configuration options
- **Example Updates**: Update examples for new features

## Testing Guidelines

### Test Structure

```
tests/
├── unit/           # Unit tests for individual components
├── integration/    # Integration tests for component interactions
└── e2e/           # End-to-end tests for full workflows
```

### Writing Tests

1. **Unit Tests**: Test individual functions and classes in isolation
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete user workflows

### Test Example

```python
import pytest
from unittest.mock import AsyncMock, patch

from threatsimgpt.core.simulator import ThreatSimulator
from threatsimgpt.config.models import ThreatScenario

@pytest.mark.asyncio
async def test_threat_simulation_success():
    """Test successful threat simulation execution."""
    # Arrange
    scenario = ThreatScenario(
        name="Test Scenario",
        threat_type="phishing",
        # ... other fields
    )
    
    with patch('threatsimgpt.llm.manager.LLMManager') as mock_llm:
        mock_llm.generate.return_value = "Generated threat content"
        simulator = ThreatSimulator(mock_llm)
        
        # Act
        result = await simulator.execute_simulation(scenario)
        
        # Assert
        assert result.status == "completed"
        assert result.content is not None
        mock_llm.generate.assert_called_once()
```

## Project Structure

Understanding the project structure helps in making targeted contributions:

```
threatsimgpt/
├── src/threatsimgpt/          # Main application code
│   ├── api/               # REST API endpoints
│   ├── cli/               # Command-line interface
│   ├── config/            # Configuration management
│   ├── core/              # Core simulation logic
│   ├── llm/               # LLM integration layer
│   ├── safety/            # Safety and ethics enforcement
│   └── utils/             # Utility functions
├── tests/                 # Test suite
├── docs/                  # Documentation
├── templates/             # Threat scenario templates
├── docker/                # Docker configuration
└── scripts/               # Development scripts
```

## Areas for Contribution

### High Priority
- **LLM Provider Integration**: Add support for new LLM providers
- **Safety Improvements**: Enhance content filtering and safety checks
- **Performance Optimization**: Improve simulation execution speed
- **Documentation**: Improve user guides and API documentation

### Medium Priority
- **New Threat Types**: Add support for additional threat categories
- **Reporting Features**: Enhance simulation reporting capabilities
- **CLI Improvements**: Add new command-line features
- **Testing**: Increase test coverage and add edge case testing

### Feature Requests
Check our [GitHub Issues](https://github.com/threatsimgpt-AI/ThreatSimGPT/issues) for current feature requests and bug reports.

## Release Process

1. **Version Bumping**: Use semantic versioning (major.minor.patch)
2. **Changelog**: Update CHANGELOG.md with new features and fixes
3. **Testing**: Ensure all tests pass and coverage is maintained
4. **Documentation**: Update documentation for new features
5. **Release**: Create GitHub release with detailed release notes

## Getting Help

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For questions and community discussion
- **Email**: threatsimgpt@hotmail.com for security-related concerns

## Recognition

Contributors will be recognized in:
- README.md contributor section
- Release notes
- Project documentation

Thank you for contributing to ThreatSimGPT! Your efforts help make cybersecurity training more effective and accessible.