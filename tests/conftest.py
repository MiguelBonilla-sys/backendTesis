"""Root conftest — pytest-asyncio configuration for the full test suite."""
from unittest.mock import AsyncMock, PropertyMock

import pytest


@pytest.fixture(autouse=True)
def _stub_llm_gateway_io(request):
    """Evita I/O de red del LLM Gateway durante los tests.

    El lifespan de FastAPI llama ``llm_agent.initialize()`` (→ healthcheck HTTP
    contra el proveedor remoto). Los tests unitarios de ``core/llm_gateway.py``
    y ``agents/llm_agent.py`` traen sus propios mocks y se excluyen aquí.
    """
    if any(name in request.node.nodeid for name in (
        "test_llm_gateway", "test_llm_agent", "test_lifespan",
    )):
        yield
        return

    from unittest.mock import patch

    with patch("core.llm_gateway.llm_gateway.initialize", new_callable=AsyncMock), \
         patch("core.llm_gateway.llm_gateway.aclose", new_callable=AsyncMock), \
         patch("agents.llm_agent.llm_gateway.initialize", new_callable=AsyncMock):
        yield


@pytest.fixture(autouse=True)
def _stub_startup_knowledge_io(request):
    """Los tests del arranque verifican el lifespan con sus propios dobles.

    El resto evita conexiones ChromaDB y la carga del millón de referencias;
    los tests unitarios de IDN siguen usando instancias propias del agente.
    """
    if any(name in request.node.nodeid for name in (
        "test_lifespan", "test_idn_agent", "test_chromadb_storage",
    )):
        yield
        return

    from unittest.mock import patch

    with patch("agents.idn_agent.idn_agent.initialize", new_callable=AsyncMock), \
         patch("agents.idn_agent.idn_agent._ready", True), \
         patch("agents.idn_agent.IDNAgent.has_reference_knowledge",
               new_callable=PropertyMock, return_value=True), \
         patch("models.chromadb_client.init_chromadb", new_callable=AsyncMock):
        yield


@pytest.fixture
def auth_store(monkeypatch):
    """Opt-in auth persistence double; all security checks remain active."""
    from auth import sessions
    from core import rate_limiter
    from tests import auth_helpers

    store = auth_helpers.AuthStore()
    monkeypatch.setattr(auth_helpers, "_active_store", store)
    monkeypatch.setattr(sessions, "get_redis", lambda: store)
    monkeypatch.setattr(sessions, "fetchrow", store.fetchrow)
    monkeypatch.setattr(rate_limiter, "get_redis", lambda: store)
    return store
