"""Numeric compatibility for agents with request-local availability metadata."""

from __future__ import annotations

from schemas.analyze import AgentTelemetry


class SignalScore(float):
    def __new__(
        cls,
        value: float,
        telemetry: AgentTelemetry,
        components: dict[str, AgentTelemetry] | None = None,
    ):
        result = super().__new__(cls, value)
        result.telemetry = telemetry
        result.components = components or {}
        return result


def telemetry_of(value: float) -> AgentTelemetry:
    # A legacy float (including exactly 0.5) gives no evidence of availability.
    return getattr(value, "telemetry", AgentTelemetry())


class CompletionText(str):
    def __new__(cls, text: str, model: str):
        result = super().__new__(cls, text)
        result.model = model
        return result
