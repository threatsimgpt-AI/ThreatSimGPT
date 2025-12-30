"""Base classes and utilities for deployment platform integrations.

This module provides abstract base classes and common utilities that eliminate
code duplication across all platform integration implementations.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime

import aiohttp
from pydantic import BaseModel, Field

from . import DeploymentResult, CampaignMetrics
from ..core.exceptions import DeploymentError, AuthenticationError


class BaseIntegration(ABC):
    """Abstract base class for all deployment platform integrations.

    This class provides common functionality for HTTP communication, session
    management, authentication state tracking, and context manager support.
    All platform-specific integrations should inherit from this class.

    Attributes:
        config: Platform configuration dictionary
        _session: Shared aiohttp ClientSession for connection pooling
        _authenticated: Authentication state flag
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize the integration with configuration.

        Args:
            config: Configuration dictionary containing platform-specific settings
        """
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._authenticated = False

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with connection pooling.

        Creates a new session if one doesn't exist or if the existing session
        is closed. Uses a 30-second timeout for all requests.

        Returns:
            Active aiohttp ClientSession instance
        """
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            )
        return self._session

    async def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make HTTP request with standardized error handling.

        Provides consistent error handling, response parsing, and logging
        for all HTTP requests made by integration implementations.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL for the request
            **kwargs: Additional arguments passed to aiohttp (headers, data, json, etc.)

        Returns:
            Parsed JSON response as dictionary, or {"text": content} for non-JSON

        Raises:
            DeploymentError: If the request fails or returns an error status
        """
        session = await self._get_session()

        try:
            async with session.request(method, url, **kwargs) as response:
                # Check for HTTP errors
                if response.status >= 400:
                    error_text = await response.text()
                    raise DeploymentError(
                        f"Request failed with status {response.status}: {error_text}",
                        error_code="HTTP_ERROR"
                    )

                # Parse response based on content type
                if response.content_type == 'application/json':
                    return await response.json()
                else:
                    return {"text": await response.text()}

        except aiohttp.ClientError as e:
            raise DeploymentError(
                f"Request failed: {method} {url} - {str(e)}",
                error_code="HTTP_ERROR"
            ) from e
        except asyncio.TimeoutError as e:
            raise DeploymentError(
                f"Request timeout: {method} {url}",
                error_code="TIMEOUT_ERROR"
            ) from e

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the integration platform.

        Implementations should handle platform-specific authentication flows
        (OAuth, API keys, tokens, etc.) and set self._authenticated = True
        upon successful authentication.

        Returns:
            True if authentication successful, False otherwise

        Raises:
            AuthenticationError: If authentication fails with a clear error
        """
        pass

    @abstractmethod
    async def deploy_content(
        self,
        content: Dict[str, Any],
        targets: List[Dict[str, Any]]
    ) -> DeploymentResult:
        """Deploy content to specified targets through the platform.

        Implementations should handle platform-specific deployment logic,
        including content formatting, target processing, and result tracking.

        Args:
            content: Content to deploy (email, SMS, notification, etc.)
                Common fields: subject, body_html, body_text, sender_email, etc.
            targets: List of target recipients
                Common fields: email, phone, name, user_id, etc.

        Returns:
            DeploymentResult with deployment status, metrics, and tracking IDs

        Raises:
            DeploymentError: If deployment fails
        """
        pass

    async def get_campaign_metrics(
        self,
        campaign_id: str
    ) -> CampaignMetrics:
        """Get metrics for a deployed campaign.

        Default implementation returns basic structure. Override for
        platform-specific metrics collection.

        Args:
            campaign_id: Unique identifier for the campaign

        Returns:
            CampaignMetrics with available metrics
        """
        return CampaignMetrics(
            campaign_id=campaign_id,
            emails_sent=0,
            emails_delivered=0,
            emails_opened=0,
            links_clicked=0,
            credentials_submitted=0,
            metadata={
                "note": "Override get_campaign_metrics() for platform-specific metrics"
            }
        )

    async def validate_configuration(self) -> bool:
        """Validate that the integration is properly configured.

        Default implementation checks for basic config requirements.
        Override for platform-specific validation.

        Returns:
            True if configuration is valid, False otherwise
        """
        return bool(self.config)

    async def cleanup(self):
        """Cleanup resources (close HTTP sessions, etc.).

        Should be called when the integration is no longer needed.
        Automatically called when using context manager.
        """
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        self._authenticated = False

    async def __aenter__(self):
        """Context manager entry - authenticate and prepare for use.

        Usage:
            async with M365Integration(config) as integration:
                result = await integration.deploy_content(...)
        """
        if not self._authenticated:
            await self.authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        await self.cleanup()

    def __repr__(self) -> str:
        """String representation for debugging."""
        auth_status = "authenticated" if self._authenticated else "not authenticated"
        return f"<{self.__class__.__name__} {auth_status}>"
