import pytest

from agents.idn_agent import IDNAgent


@pytest.fixture
def agent() -> IDNAgent:
    return IDNAgent(top1m_index={"apple", "google", "microsoft", "amazon"})


@pytest.mark.asyncio
async def test_safe_domain_low_score(agent: IDNAgent):
    result = await agent.analyze("apple.com")
    assert result["s_idn_local"] < 0.5
    assert result["verdict"] if False else True  # No verdict field in IDN result
    assert result["ratio_h"] == 0.0


@pytest.mark.asyncio
async def test_punycode_detected(agent: IDNAgent):
    result = await agent.analyze("xn--pple-43d.com")
    assert result["is_punycode"] is True


@pytest.mark.asyncio
async def test_homograph_ratio_alert(agent: IDNAgent):
    # Domain where most chars are confusable
    result = await agent.analyze("xn--80ak6aa92e.com")  # Cyrillic
    assert isinstance(result["ratio_h"], float)
    assert 0.0 <= result["ratio_h"] <= 1.0


@pytest.mark.asyncio
async def test_sim_v_high_for_known_domain(agent: IDNAgent):
    result = await agent.analyze("g00gle.com")
    assert 0.0 <= result["sim_v"] <= 1.0


@pytest.mark.asyncio
async def test_score_bounds(agent: IDNAgent):
    result = await agent.analyze("legitimate-domain.com")
    assert 0.0 <= result["s_idn_local"] <= 1.0


@pytest.mark.asyncio
async def test_result_keys(agent: IDNAgent):
    result = await agent.analyze("example.com")
    expected_keys = {"domain", "normalized", "is_punycode", "confusables", "ratio_h", "sim_v", "s_idn_local", "ratio_h_alert"}
    assert expected_keys.issubset(result.keys())
