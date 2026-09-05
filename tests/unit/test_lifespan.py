"""Exercise the real startup/shutdown sequence with controlled dependencies."""
from contextlib import ExitStack
from unittest.mock import AsyncMock, PropertyMock, patch

import pytest

from main import app, lifespan


@pytest.fixture
def dependencies():
    names = {
        "db": "main.init_db", "redis": "main.init_redis",
        "close_db": "main.close_db", "close_redis": "main.close_redis",
        "idn": "agents.idn_agent.idn_agent.initialize",
        "chroma": "models.chromadb_client.init_chromadb",
        "llm": "agents.llm_agent.llm_agent.initialize",
        "close_llm": "core.llm_gateway.llm_gateway.aclose",
        "theta": "core.calibration.load_effective_theta_from_db",
        "weights": "core.online_calibration.load_effective_weights_from_db",
    }
    with ExitStack() as stack:
        mocks = {key: stack.enter_context(patch(name, new_callable=AsyncMock))
                 for key, name in names.items()}
        stack.enter_context(patch("agents.idn_agent.idn_agent._ready", True))
        mocks["knowledge"] = stack.enter_context(patch(
            "agents.idn_agent.IDNAgent.has_reference_knowledge",
            new_callable=PropertyMock, return_value=True,
        ))
        yield mocks


async def test_initializes_knowledge_before_serving_and_closes_after_error(dependencies):
    with pytest.raises(RuntimeError, match="request error"):
        async with lifespan(app):
            for key in ("db", "redis", "idn", "chroma", "llm", "theta", "weights"):
                dependencies[key].assert_awaited_once()
            raise RuntimeError("request error")
    for key in ("close_db", "close_redis", "close_llm"):
        dependencies[key].assert_awaited_once()


async def test_chroma_down_keeps_detector_available(dependencies):
    dependencies["chroma"].side_effect = RuntimeError("database offline")
    async with lifespan(app):
        dependencies["llm"].assert_awaited_once()


async def test_empty_idn_knowledge_prevents_serving(dependencies):
    dependencies["knowledge"].return_value = False
    with pytest.raises(RuntimeError, match="reference knowledge"):
        async with lifespan(app):
            pytest.fail("must not serve with empty IDN knowledge")
    dependencies["close_db"].assert_awaited_once()


async def test_calibration_outage_keeps_static_configuration(dependencies):
    dependencies["theta"].side_effect = RuntimeError("no calibration")
    async with lifespan(app):
        dependencies["llm"].assert_awaited_once()
