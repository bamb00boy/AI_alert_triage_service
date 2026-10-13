"""Typed connector errors. `retryable` tells callers whether backing off can help."""

from __future__ import annotations


class ConnectorError(Exception):
    retryable: bool = False

    def __init__(self, connector: str, message: str):
        super().__init__(f"[{connector}] {message}")
        self.connector = connector


class ConfigurationError(ConnectorError):
    """Missing API key, bad base URL, ... Fix the config; retrying won't help."""


class UnsupportedIndicatorError(ConnectorError):
    """The connector cannot look up this indicator type."""


class AuthenticationError(ConnectorError):
    """401/403 from the provider."""


class InvalidResponseError(ConnectorError):
    """The provider answered, but not in the shape we expect."""


class RateLimitedError(ConnectorError):
    retryable = True

    def __init__(self, connector: str, message: str, retry_after: float | None = None):
        super().__init__(connector, message)
        self.retry_after = retry_after


class ConnectorTimeoutError(ConnectorError):
    retryable = True


class UpstreamError(ConnectorError):
    """Transport failure or 5xx (retryable), or an unexpected 4xx (not retryable)."""

    def __init__(self, connector: str, message: str, status: int | None = None, retryable: bool = True):
        super().__init__(connector, message)
        self.status = status
        self.retryable = retryable
