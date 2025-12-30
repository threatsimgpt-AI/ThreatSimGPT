"""Configuration-related exceptions."""


class ConfigurationError(Exception):
    """Configuration error."""
    pass


class ValidationError(Exception):
    """Validation error."""
    pass


class SchemaError(Exception):
    """Schema error."""
    pass
