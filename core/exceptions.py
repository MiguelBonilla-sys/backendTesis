"""Custom exception hierarchy for the phishing-detector backend."""


class PhishingDetectorError(Exception):
    """Base exception for all application-level errors."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, detail={self.detail!r})"


class IDNAnalysisError(PhishingDetectorError):
    """Raised when the IDN Agent fails to analyse a domain."""


class LLMTimeoutError(PhishingDetectorError):
    """Raised when the LlamaStack / LLM agent exceeds the configured timeout."""


class ThreatIntelError(PhishingDetectorError):
    """Raised when a Threat Intelligence API call fails."""


class AuthenticationError(PhishingDetectorError):
    """Raised when JWT validation or credential verification fails."""


class DatabaseError(PhishingDetectorError):
    """Raised when a database operation fails."""
