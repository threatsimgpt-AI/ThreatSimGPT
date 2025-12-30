"""Safety-related exceptions."""


class SafetyViolationError(Exception):
    """Safety violation error."""
    pass


class ContentFilterError(Exception):
    """Content filter error."""
    pass


class PolicyViolationError(Exception):
    """Policy violation error."""
    pass


class ComplianceError(Exception):
    """Compliance error."""
    pass
