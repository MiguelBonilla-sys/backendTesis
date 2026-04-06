class BackendTesisError(Exception):
    """Base exception for BackendTesis."""


class IDNAnalysisError(BackendTesisError):
    """Raised when IDN analysis fails."""


class LLMInferenceError(BackendTesisError):
    """Raised when LlamaStack inference fails or times out."""


class TIFetchError(BackendTesisError):
    """Raised when a TI API call fails."""


class CacheError(BackendTesisError):
    """Raised when a Redis cache operation fails."""


class ChromaDBError(BackendTesisError):
    """Raised when a ChromaDB operation fails."""


class InvalidURLError(BackendTesisError):
    """Raised when the input URL is malformed or uses a forbidden scheme."""


class AuthError(BackendTesisError):
    """Raised when authentication or token validation fails."""
