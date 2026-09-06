"""Fixtures de la suite de seguridad."""
from __future__ import annotations

import os

import pytest

from agents.llm_agent import LLMAgent

# Los tests marcados `live` pegan al backend desplegado. Se saltan salvo
# SECURITY_LIVE=1 (necesitan red + el dominio arriba).
LIVE_BASE = os.getenv("SECURITY_LIVE_BASE", "https://back-tesi.mangel.dpdns.org")
_LIVE = os.getenv("SECURITY_LIVE") == "1"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "live: pega al backend desplegado (necesita SECURITY_LIVE=1)"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _LIVE:
        return
    skip = pytest.mark.skip(reason="live: exportá SECURITY_LIVE=1 para correrlos")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def agent() -> LLMAgent:
    return LLMAgent()


@pytest.fixture
def build_prompt(agent: LLMAgent):
    """Helper: construye el prompt del LLM con contexto RAG y cuerpo dados."""

    def _build(*, url: str = "https://xn--pypal-4ve.com/login",
               domain: str = "xn--pypal-4ve.com",
               email_body: str | None = None,
               rag_context: list[str] | None = None,
               idn_summary: str | None = "mixed_script=True, s_idn_local=0.85") -> str:
        return agent._build_prompt(
            url=url, domain=domain, email_body=email_body,
            rag_context=rag_context or [], idn_summary=idn_summary,
        )

    return _build
