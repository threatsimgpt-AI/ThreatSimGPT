"""Comprehensive YAML configuration loader and validator for ThreatSimGPT.

This module provides robust YAML loading, validation, and error reporting
for threat scenario configurations.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import ValidationError
from yaml.constructor import ConstructorError
from yaml.parser import ParserError
from yaml.scanner import ScannerError

from .models import ThreatScenario


logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Base exception for configuration errors."""
    pass


class YAMLSyntaxError(ConfigurationError):
    """YAML syntax or parsing error."""
    pass


class SchemaValidationError(ConfigurationError):
    """Schema validation error with detailed field information."""

    def __init__(self, message: str, errors: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.errors = errors or []


class YAMLConfigLoader:
    """Advanced YAML configuration loader with comprehensive validation."""

    def __init__(self, strict_mode: bool = True, schema_validation: bool = True):
        """Initialize the YAML configuration loader.

        Args:
            strict_mode: If True, reject unknown fields and apply strict validation
            schema_validation: If True, validate against Pydantic schemas
        """
        self.strict_mode = strict_mode
        self.schema_validation = schema_validation
        self._setup_yaml_loader()

    def _setup_yaml_loader(self) -> None:
        """Configure YAML loader with custom constructors."""
        # Use safe loader to prevent code execution
        self.yaml_loader = yaml.SafeLoader

        # Add custom constructors for better error handling
        yaml.add_constructor('tag:yaml.org,2002:timestamp', self._timestamp_constructor, self.yaml_loader)

    def _timestamp_constructor(self, loader, node):
        """Custom timestamp constructor with validation."""
        from datetime import datetime
        try:
            return datetime.fromisoformat(node.value.replace('Z', '+00:00'))
        except ValueError as e:
            raise ConstructorError(
                None, None,
                f"Invalid timestamp format: {node.value}. Expected ISO format.",
                node.start_mark
            )

    def load_config(self, config_path: Union[str, Path]) -> Dict[str, Any]:
        """Load YAML configuration with comprehensive error handling.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            Parsed configuration dictionary

        Raises:
            ConfigurationError: For file access or parsing errors
            YAMLSyntaxError: For YAML syntax errors
        """
        config_path = Path(config_path)

        # Validate file exists and is readable
        if not config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")

        if not config_path.is_file():
            raise ConfigurationError(f"Path is not a file: {config_path}")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # Check for empty file
                if not content.strip():
                    raise ConfigurationError(f"Configuration file is empty: {config_path}")

                # Parse YAML with detailed error reporting
                try:
                    config = yaml.load(content, Loader=self.yaml_loader)
                except (ParserError, ScannerError) as e:
                    self._handle_yaml_syntax_error(e, config_path)
                except ConstructorError as e:
                    raise YAMLSyntaxError(f"YAML construction error in {config_path}: {e}")

                if config is None:
                    raise ConfigurationError(f"Configuration file contains no data: {config_path}")

                logger.info(f"Successfully loaded configuration from {config_path}")
                return config

        except PermissionError:
            raise ConfigurationError(f"Permission denied reading configuration file: {config_path}")
        except UnicodeDecodeError as e:
            raise ConfigurationError(f"Invalid UTF-8 encoding in configuration file {config_path}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Unexpected error loading configuration {config_path}: {e}")

    def _handle_yaml_syntax_error(self, error: Union[ParserError, ScannerError], config_path: Path) -> None:
        """Handle YAML syntax errors with detailed reporting."""
        error_msg = f"YAML syntax error in {config_path}"

        if hasattr(error, 'problem_mark') and error.problem_mark:
            mark = error.problem_mark
            error_msg += f" at line {mark.line + 1}, column {mark.column + 1}"

        if hasattr(error, 'problem') and error.problem:
            error_msg += f": {error.problem}"

        if hasattr(error, 'context') and error.context:
            error_msg += f" (context: {error.context})"

        raise YAMLSyntaxError(error_msg)

    def validate_threat_scenario(self, config: Dict[str, Any]) -> ThreatScenario:
        """Validate configuration against ThreatScenario schema.

        Args:
            config: Configuration dictionary to validate

        Returns:
            Validated ThreatScenario instance

        Raises:
            SchemaValidationError: For validation failures
        """
        if not self.schema_validation:
            # Return unvalidated instance if schema validation is disabled
            return ThreatScenario.parse_obj(config)

        try:
            # Validate using Pydantic model
            scenario = ThreatScenario.parse_obj(config)
            logger.info(f"Successfully validated threat scenario: {scenario.metadata.name}")
            return scenario

        except ValidationError as e:
            # Transform Pydantic errors into detailed error information
            errors = self._format_validation_errors(e.errors())
            error_msg = f"Schema validation failed with {len(errors)} error(s)"

            logger.error(f"Validation failed: {error_msg}")
            for error in errors:
                logger.error(f"  - {error['location']}: {error['message']}")

            raise SchemaValidationError(error_msg, errors)

    def _format_validation_errors(self, pydantic_errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format Pydantic validation errors for better readability."""
        formatted_errors = []

        for error in pydantic_errors:
            formatted_error = {
                'location': ' -> '.join(str(loc) for loc in error['loc']),
                'message': error['msg'],
                'type': error['type'],
                'input_value': error.get('input'),
            }

            # Add context for specific error types
            if error['type'] == 'value_error.missing':
                formatted_error['message'] = "Required field is missing"
            elif error['type'] == 'type_error.enum':
                formatted_error['message'] = f"Invalid value. {error['msg']}"
            elif 'value_error' in error['type'] and 'ctx' in error:
                ctx = error['ctx']
                if 'limit_value' in ctx:
                    formatted_error['message'] += f" (limit: {ctx['limit_value']})"

            formatted_errors.append(formatted_error)

        return formatted_errors

    def load_and_validate_scenario(self, config_path: Union[str, Path]) -> ThreatScenario:
        """Load and validate a threat scenario configuration.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            Validated ThreatScenario instance

        Raises:
            ConfigurationError: For loading or validation errors
        """
        # Load the configuration
        config = self.load_config(config_path)

        # Validate against schema
        return self.validate_threat_scenario(config)

    def validate_config_directory(self, directory_path: Union[str, Path]) -> Dict[str, Any]:
        """Validate all YAML files in a directory.

        Args:
            directory_path: Path to directory containing YAML files

        Returns:
            Dictionary with validation results for each file
        """
        directory_path = Path(directory_path)

        if not directory_path.exists():
            raise ConfigurationError(f"Directory not found: {directory_path}")

        if not directory_path.is_dir():
            raise ConfigurationError(f"Path is not a directory: {directory_path}")

        results = {
            'total_files': 0,
            'valid_files': 0,
            'invalid_files': 0,
            'files': {}
        }

        # Find all YAML files
        yaml_files = list(directory_path.rglob('*.yaml')) + list(directory_path.rglob('*.yml'))
        results['total_files'] = len(yaml_files)

        for yaml_file in yaml_files:
            file_key = str(yaml_file.relative_to(directory_path))

            try:
                scenario = self.load_and_validate_scenario(yaml_file)
                threat_type_val = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
                difficulty_val = scenario.difficulty_level.value if hasattr(scenario.difficulty_level, 'value') else scenario.difficulty_level
                results['files'][file_key] = {
                    'status': 'valid',
                    'scenario_name': scenario.metadata.name,
                    'threat_type': threat_type_val,
                    'difficulty': difficulty_val
                }
                results['valid_files'] += 1

            except (ConfigurationError, SchemaValidationError) as e:
                results['files'][file_key] = {
                    'status': 'invalid',
                    'error': str(e),
                    'error_type': type(e).__name__
                }
                results['invalid_files'] += 1

        logger.info(f"Directory validation complete: {results['valid_files']}/{results['total_files']} files valid")
        return results


# Convenience functions for backward compatibility and ease of use

def load_config(config_path: Union[str, Path], strict_mode: bool = True) -> Dict[str, Any]:
    """Load YAML configuration file.

    Args:
        config_path: Path to the YAML configuration file
        strict_mode: Enable strict validation mode

    Returns:
        Parsed configuration dictionary
    """
    loader = YAMLConfigLoader(strict_mode=strict_mode)
    return loader.load_config(config_path)


def validate_config(config: Dict[str, Any], strict_mode: bool = True) -> ThreatScenario:
    """Validate configuration dictionary against ThreatScenario schema.

    Args:
        config: Configuration dictionary to validate
        strict_mode: Enable strict validation mode

    Returns:
        Validated ThreatScenario instance
    """
    loader = YAMLConfigLoader(strict_mode=strict_mode)
    return loader.validate_threat_scenario(config)


def load_and_validate_scenario(config_path: Union[str, Path], strict_mode: bool = True) -> ThreatScenario:
    """Load and validate a threat scenario configuration file.

    Args:
        config_path: Path to the YAML configuration file
        strict_mode: Enable strict validation mode

    Returns:
        Validated ThreatScenario instance
    """
    loader = YAMLConfigLoader(strict_mode=strict_mode)
    return loader.load_and_validate_scenario(config_path)
