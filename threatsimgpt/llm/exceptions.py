"""LLM-related exceptions."""


class LLMError(Exception):
    """Base LLM error."""
    pass


class ProviderError(LLMError):
    """Provider error."""
    pass


class RateLimitError(LLMError):
    """Rate limit error."""
    pass


class CostLimitError(LLMError):
    """Cost limit error."""
    pass
