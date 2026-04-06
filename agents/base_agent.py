from abc import ABC, abstractmethod

from core.logger import get_logger


class BaseAgent(ABC):
    """Abstract base for all phishing detection agents.

    All agents MUST be stateless — instantiate fresh per request.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.logger = get_logger(f"agent.{name}")

    @abstractmethod
    async def analyze(self, *args, **kwargs) -> dict:
        """Run agent analysis. Subclasses must implement this."""

    def _log_start(self, target: str) -> None:
        self.logger.info(f"[{self.name}] Starting analysis for {target!r}")

    def _log_result(self, target: str, score: float) -> None:
        self.logger.info(f"[{self.name}] Done — {target!r} score={score:.4f}")
