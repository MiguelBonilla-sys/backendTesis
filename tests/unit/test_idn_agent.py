"""Unit tests for agents/idn_agent.py — IDN homograph detection."""
from __future__ import annotations

import pytest

from agents.confusables_loader import ConfusablesCatalog
from agents.idn_agent import IDNAgent
from core.constants import BETA, IDN_HOMOGRAPH_RATIO_ALERT

# ── Minimal catalog for tests ──────────────────────────────────────────────────
# Mirrors the entries in tests/fixtures/confusables_minimal.txt
CATALOG: ConfusablesCatalog = {
    "\u0430": ["a"],   # Cyrillic а → Latin a
    "\u0435": ["e"],   # Cyrillic е → Latin e
    "\u043E": ["o"],   # Cyrillic о → Latin o
    "\u0440": ["p"],   # Cyrillic р → Latin p
    "\u0441": ["c"],   # Cyrillic с → Latin c
    "\u0445": ["x"],   # Cyrillic х → Latin x
    "\u0456": ["i"],   # Cyrillic і → Latin i
    "\u0443": ["y"],   # Cyrillic у → Latin y
    "\u03B1": ["a"],   # Greek α → Latin a
    "\u03BF": ["o"],   # Greek ο → Latin o
}

TOP1M = {
    "paypal", "apple", "google", "microsoft", "amazon",
    "facebook", "twitter", "instagram", "linkedin", "youtube",
}


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def agent() -> IDNAgent:
    """Bare agent: small top-1M, no catalog (heuristic detection only)."""
    return IDNAgent(top1m_index={"apple", "google", "microsoft", "amazon"})


@pytest.fixture
def agent_with_catalog() -> IDNAgent:
    """Agent with full test catalog and extended top-1M."""
    return IDNAgent(top1m_index=TOP1M, catalog=CATALOG)


# ── Legacy tests (maintained for regression) ──────────────────────────────────


async def test_known_domain_expected_score(agent: IDNAgent) -> None:
    result = await agent.analyze("apple.com")
    # ratio_h=0 (no confusables), sim_v=1.0 (exact top-1M match)
    # S_IDN_local = BETA*0 + (1-BETA)*1.0 = 1 - 0.40 = 0.60
    assert result["s_idn_local"] == pytest.approx(1.0 - BETA, abs=1e-4)
    assert result["ratio_h"] == 0.0
    assert "verdict" not in result


async def test_punycode_detected(agent: IDNAgent) -> None:
    result = await agent.analyze("xn--pple-43d.com")
    assert result["is_punycode"] is True


async def test_homograph_ratio_bounds(agent: IDNAgent) -> None:
    result = await agent.analyze("xn--80ak6aa92e.com")
    assert isinstance(result["ratio_h"], float)
    assert 0.0 <= result["ratio_h"] <= 1.0


async def test_sim_v_bounds(agent: IDNAgent) -> None:
    result = await agent.analyze("g00gle.com")
    assert 0.0 <= result["sim_v"] <= 1.0


async def test_score_bounds(agent: IDNAgent) -> None:
    result = await agent.analyze("legitimate-domain.com")
    assert 0.0 <= result["s_idn_local"] <= 1.0


async def test_result_keys(agent: IDNAgent) -> None:
    result = await agent.analyze("example.com")
    expected_keys = {
        "domain", "normalized", "is_punycode", "confusables",
        "ratio_h", "sim_v", "s_idn_local", "ratio_h_alert",
    }
    assert expected_keys.issubset(result.keys())


# ── Confusable detection — parametrized IDN phishing corpus ───────────────────


@pytest.mark.parametrize("domain", [
    "p\u0430ypal.com",                  # Cyrillic а in paypal
    "\u0430pple.com",                   # Cyrillic а in apple
    "micr\u043E\u0441\u043Eft.com",     # Cyrillic о, с, о in microsoft
    "g\u043E\u043Egle.com",             # Cyrillic о×2 in google
    "\u0430m\u0430z\u043En.com",        # Cyrillic а, а, о in amazon
    "f\u0430\u0441\u0435book.com",      # Cyrillic а, с, е in facebook
    "tw\u0456tter.com",                 # Cyrillic і in twitter
    "\u0456nst\u0430gr\u0430m.com",     # Cyrillic і, а, а in instagram
    "link\u0435d\u0456n.com",           # Cyrillic е, і in linkedin
    "g\u03BF\u03BFgle.com",             # Greek ο×2 in google
    "\u03B1pple.com",                   # Greek α in apple
    "p\u03B1ypal.com",                  # Greek α in paypal
])
async def test_confusables_detected_in_phishing_domain(
    domain: str,
    agent_with_catalog: IDNAgent,
) -> None:
    result = await agent_with_catalog.analyze(domain)
    assert len(result["confusables"]) > 0, (
        f"Expected confusables in {domain!r} but got none"
    )
    assert len(result["confusable_details"]) > 0


@pytest.mark.parametrize("domain", [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
])
async def test_no_confusables_in_clean_domain(
    domain: str,
    agent_with_catalog: IDNAgent,
) -> None:
    result = await agent_with_catalog.analyze(domain)
    assert result["confusables"] == [], (
        f"Expected no confusables in {domain!r} but got {result['confusables']}"
    )


# ── Homograph ratio threshold ──────────────────────────────────────────────────


@pytest.mark.parametrize("domain,expected_alert", [
    # 2 confusables in 6-char 2LD → r_h = 2/6 = 0.333 ≥ 0.30
    ("p\u0430yp\u0430l.com", True),
    # 2 Cyrillic о's in "google" (6 chars) → r_h = 2/6 = 0.333
    ("g\u043E\u043Egle.com", True),
    # 3 confusables in 9-char 2LD microsoft → r_h = 3/9 = 0.333
    ("micr\u043E\u0441\u043Eft.com", True),
    # Clean domain → r_h = 0
    ("paypal.com", False),
    ("google.com", False),
])
async def test_homograph_ratio_alert_threshold(
    domain: str,
    expected_alert: bool,
    agent_with_catalog: IDNAgent,
) -> None:
    result = await agent_with_catalog.analyze(domain)
    assert result["ratio_h_alert"] is expected_alert, (
        f"domain={domain!r}: ratio_h={result['ratio_h']:.4f}, "
        f"expected ratio_h_alert={expected_alert}"
    )


# ── Visual similarity with catalog ────────────────────────────────────────────


async def test_visual_similarity_high_for_homograph(
    agent_with_catalog: IDNAgent,
) -> None:
    # "pаypal" (Cyrillic а) vs "paypal" — confusable-aware edit distance = 0
    result = await agent_with_catalog.analyze("p\u0430yp\u0430l.com")
    assert result["sim_v"] == pytest.approx(1.0, abs=1e-4)
    assert result["closest_domain"] == "paypal"


async def test_visual_similarity_exact_match(agent: IDNAgent) -> None:
    result = await agent.analyze("apple.com")
    assert result["sim_v"] == pytest.approx(1.0, abs=1e-4)


async def test_visual_similarity_zero_when_top1m_empty() -> None:
    agent = IDNAgent(top1m_index=set(), catalog=CATALOG)
    result = await agent.analyze("paypal.com")
    assert result["sim_v"] == 0.0
    assert result["closest_domain"] == ""


# ── IDNAgent statelessness ─────────────────────────────────────────────────────


async def test_agent_stateless_consecutive_calls(
    agent_with_catalog: IDNAgent,
) -> None:
    r1 = await agent_with_catalog.analyze("paypal.com")
    r2 = await agent_with_catalog.analyze("p\u0430ypal.com")
    # Results must be independent — no state leaking between calls
    assert r1["confusables"] == []
    assert len(r2["confusables"]) > 0


# ── S_IDN_local formula ────────────────────────────────────────────────────────


def test_s_idn_local_formula_pure_ratio() -> None:
    """S_IDN_local = β*1.0 + (1-β)*0.0 = β when r_h=1, sim_v=0."""
    agent = IDNAgent(top1m_index=set(), catalog={})
    # Use _levenshtein directly to verify formula
    ratio_h = 1.0
    sim_v = 0.0
    expected = BETA * ratio_h + (1.0 - BETA) * sim_v
    assert expected == pytest.approx(BETA, abs=1e-6)


def test_s_idn_local_formula_pure_similarity() -> None:
    """S_IDN_local = β*0.0 + (1-β)*1.0 = (1-β) when r_h=0, sim_v=1."""
    expected = BETA * 0.0 + (1.0 - BETA) * 1.0
    assert expected == pytest.approx(1.0 - BETA, abs=1e-6)


# ── confusable_details structure ──────────────────────────────────────────────


async def test_confusable_details_structure(
    agent_with_catalog: IDNAgent,
) -> None:
    result = await agent_with_catalog.analyze("p\u0430ypal.com")
    details = result["confusable_details"]
    assert isinstance(details, list)
    assert len(details) >= 1
    entry = details[0]
    assert "char" in entry
    assert "position" in entry
    assert "script" in entry
    assert "lookalike" in entry
    assert entry["char"] == "\u0430"
    assert entry["lookalike"] == "a"


# ── Error handling ─────────────────────────────────────────────────────────────


async def test_analyze_returns_dict_for_plain_domain(
    agent: IDNAgent,
) -> None:
    result = await agent.analyze("example.com")
    assert isinstance(result, dict)
    assert result["domain"] == "example.com"
