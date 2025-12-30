"""Environment variable validation for ThreatSimGPT.

This module validates that required environment variables are set
and have appropriate values before the application starts.
"""

import os
import sys
import re
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class EnvVar:
    """Environment variable specification."""
    name: str
    required: bool = False
    required_in_production: bool = False
    pattern: Optional[str] = None
    description: str = ""

    def validate(self, environment: str = "development") -> Tuple[bool, str]:
        """Validate the environment variable.

        Args:
            environment: Current environment (development, staging, production)

        Returns:
            Tuple of (is_valid, error_message)
        """
        value = os.getenv(self.name)

        # Check if required
        is_production = environment.lower() == "production"
        is_required = self.required or (self.required_in_production and is_production)

        if is_required and not value:
            return False, f"Missing required environment variable: {self.name}"

        # Check placeholder values
        if value and value.startswith(("your_", "change_this", "changeme", "CHANGE_ME")):
            if is_required:
                return False, f"{self.name} contains placeholder value - please update"
            else:
                logger.warning(f"{self.name} contains placeholder value")

        # Check pattern if specified
        if value and self.pattern:
            if not re.match(self.pattern, value):
                return False, f"{self.name} does not match expected pattern"

        return True, ""


# Required environment variables
REQUIRED_VARS = [
    EnvVar(
        name="SECRET_KEY",
        required_in_production=True,
        pattern=r"^[a-f0-9]{32,}$|^.{32,}$",  # At least 32 chars
        description="Application secret key for session security"
    ),
]

# API Key variables (at least one should be set for LLM functionality)
API_KEY_VARS = [
    EnvVar(
        name="OPENAI_API_KEY",
        pattern=r"^sk-[a-zA-Z0-9]{20,}$",
        description="OpenAI API key"
    ),
    EnvVar(
        name="ANTHROPIC_API_KEY",
        pattern=r"^sk-ant-[a-zA-Z0-9-]+$",
        description="Anthropic Claude API key"
    ),
    EnvVar(
        name="OPENROUTER_API_KEY",
        pattern=r"^sk-or-[a-zA-Z0-9-]+$",
        description="OpenRouter API key"
    ),
    EnvVar(
        name="AZURE_OPENAI_API_KEY",
        description="Azure OpenAI API key"
    ),
]

# Production-required variables
PRODUCTION_VARS = [
    EnvVar(
        name="DATABASE_URL",
        required_in_production=True,
        pattern=r"^postgres(ql)?://",
        description="PostgreSQL connection string"
    ),
    EnvVar(
        name="REDIS_URL",
        required_in_production=True,
        pattern=r"^redis://",
        description="Redis connection string"
    ),
]

# Security configuration variables
SECURITY_VARS = [
    EnvVar(
        name="ENABLE_CONTENT_FILTERING",
        description="Enable content safety filtering"
    ),
    EnvVar(
        name="ENABLE_AUDIT_LOGGING",
        description="Enable audit logging"
    ),
    EnvVar(
        name="API_AUTHENTICATION_ENABLED",
        required_in_production=True,
        description="Enable API authentication"
    ),
]


def validate_environment(
    exit_on_error: bool = True,
    require_llm_key: bool = True
) -> Tuple[bool, List[str]]:
    """Validate all required environment variables.

    Args:
        exit_on_error: If True, exit the process on validation failure
        require_llm_key: If True, require at least one LLM API key

    Returns:
        Tuple of (all_valid, list_of_errors)
    """
    environment = os.getenv("ENVIRONMENT", "development")
    errors: List[str] = []
    warnings: List[str] = []

    logger.info(f"Validating environment variables for: {environment}")

    # Validate required variables
    for var in REQUIRED_VARS:
        is_valid, error = var.validate(environment)
        if not is_valid:
            errors.append(error)

    # Validate production variables
    for var in PRODUCTION_VARS:
        is_valid, error = var.validate(environment)
        if not is_valid:
            errors.append(error)

    # Validate security variables in production
    if environment.lower() == "production":
        for var in SECURITY_VARS:
            is_valid, error = var.validate(environment)
            if not is_valid:
                errors.append(error)

    # Check that at least one LLM API key is set
    if require_llm_key:
        has_llm_key = any(
            os.getenv(var.name) and not os.getenv(var.name, "").startswith("your_")
            for var in API_KEY_VARS
        )

        # Also check for Ollama (local LLM)
        ollama_enabled = os.getenv("OLLAMA_ENABLED", "").lower() in ("true", "1", "yes")

        if not has_llm_key and not ollama_enabled:
            warnings.append(
                "No LLM API key found. Set one of: OPENAI_API_KEY, ANTHROPIC_API_KEY, "
                "OPENROUTER_API_KEY, or enable OLLAMA_ENABLED=true for local models."
            )

    # Log results
    if errors:
        for error in errors:
            logger.error(f"Environment validation failed: {error}")

    if warnings:
        for warning in warnings:
            logger.warning(f"Environment warning: {warning}")

    # Handle errors
    if errors and exit_on_error:
        print("\n" + "=" * 60)
        print("ENVIRONMENT VALIDATION FAILED")
        print("=" * 60)
        for error in errors:
            print(f"  [ERROR] {error}")
        print("\nPlease update your .env file or environment variables.")
        print("See docs/ENV_HANDLING_AUDIT.md for guidance.")
        print("=" * 60 + "\n")
        sys.exit(1)

    all_valid = len(errors) == 0
    return all_valid, errors + warnings


def print_environment_status():
    """Print current environment configuration status."""
    environment = os.getenv("ENVIRONMENT", "development")

    print("\n" + "=" * 60)
    print("THREATSIMGPT ENVIRONMENT STATUS")
    print("=" * 60)
    print(f"Environment: {environment}")
    print("-" * 60)

    # Check API keys
    print("\nLLM API Keys:")
    for var in API_KEY_VARS:
        value = os.getenv(var.name)
        if value and not value.startswith("your_"):
            masked = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
            print(f"  [OK] {var.name}: {masked}")
        else:
            print(f"  [--] {var.name}: Not set")

    # Check Ollama
    ollama = os.getenv("OLLAMA_ENABLED", "false")
    if ollama.lower() in ("true", "1", "yes"):
        print(f"  [OK] OLLAMA_ENABLED: {ollama}")
    else:
        print(f"  [--] OLLAMA_ENABLED: {ollama}")

    # Check security settings
    print("\nSecurity Settings:")
    security_settings = [
        ("ENABLE_CONTENT_FILTERING", "Content Filtering"),
        ("ENABLE_AUDIT_LOGGING", "Audit Logging"),
        ("API_AUTHENTICATION_ENABLED", "API Authentication"),
        ("ENABLE_SAFETY_VALIDATION", "Safety Validation"),
    ]

    for var_name, display_name in security_settings:
        value = os.getenv(var_name, "false")
        status = "[OK]" if value.lower() in ("true", "1", "yes") else "[--]"
        print(f"  {status} {display_name}: {value}")

    # Check database
    print("\nInfrastructure:")
    db_url = os.getenv("DATABASE_URL")
    redis_url = os.getenv("REDIS_URL")

    if db_url:
        # Mask password in URL
        masked_db = re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", db_url)
        print(f"  [OK] DATABASE_URL: {masked_db}")
    else:
        print("  [--] DATABASE_URL: Not set")

    if redis_url:
        print(f"  [OK] REDIS_URL: {redis_url}")
    else:
        print("  [--] REDIS_URL: Not set")

    print("=" * 60 + "\n")


def get_missing_vars() -> List[str]:
    """Get list of missing required environment variables.

    Returns:
        List of missing variable names
    """
    environment = os.getenv("ENVIRONMENT", "development")
    missing = []

    all_vars = REQUIRED_VARS + PRODUCTION_VARS + SECURITY_VARS

    for var in all_vars:
        is_valid, _ = var.validate(environment)
        if not is_valid:
            missing.append(var.name)

    return missing


if __name__ == "__main__":
    # Run validation when executed directly
    print_environment_status()
    is_valid, messages = validate_environment(exit_on_error=False)

    if messages:
        print("\nValidation Messages:")
        for msg in messages:
            print(f"  - {msg}")

    if is_valid:
        print("\n[OK] Environment validation passed!")
    else:
        print("\n[FAIL] Environment validation failed!")
        sys.exit(1)
