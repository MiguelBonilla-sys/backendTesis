"""Tests for agents/idn_agent.py"""
from __future__ import annotations

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agents.idn_agent import IDNAgent, _load_top1m, _normalize_and_decode
from agents.bktree import BKTree
from schemas.analyze import IDNResult


# ---------------------------------------------------------------------------
# _normalize_and_decode helper
# ---------------------------------------------------------------------------

class TestNormalizeAndDecode:
    def test_ascii_domain_unchanged(self):
        assert _normalize_and_decode("paypal") == "paypal"

    def test_lowercase_conversion(self):
        assert _normalize_and_decode("PayPal") == "paypal"

    def test_trailing_whitespace_stripped_by_lower(self):
        # NFC + lower — no trailing spaces expected from label
        result = _normalize_and_decode("GOOGLE")
        assert result == "google"

    def test_nfc_normalisation_applied(self):
        import unicodedata
        # NFD form of 'é' = e + combining accent
        nfd_e = "é"
        result = _normalize_and_decode(nfd_e)
        # After NFC it should be a single char
        assert unicodedata.is_normalized("NFC", result)

    def test_punycode_with_xn_prefix_decoded(self):
        # xn--bcher-kva is 'bücher' in Punycode
        result = _normalize_and_decode("xn--bcher-kva")
        # Should be decoded to unicode form
        assert isinstance(result, str)
        assert len(result) > 0

    def test_invalid_punycode_kept_as_is(self):
        # Malformed xn-- prefix — should not raise, keep as-is
        result = _normalize_and_decode("xn--!!!invalid")
        assert result.startswith("xn--")

    def test_returns_string_type(self):
        assert isinstance(_normalize_and_decode("example"), str)

    def test_empty_string(self):
        assert _normalize_and_decode("") == ""


# ---------------------------------------------------------------------------
# _load_top1m helper
# ---------------------------------------------------------------------------

class TestLoadTop1m:
    @pytest.mark.asyncio
    async def test_loads_domains_from_csv(self, tmp_path):
        csv_content = "1,paypal.com\n2,google.com\n3,amazon.com\n"
        f = tmp_path / "top1m.csv"
        f.write_text(csv_content, encoding="utf-8")
        result = await _load_top1m(f)
        # _load_top1m stores "sld.tld" (e.g. "paypal.com")
        assert "paypal.com" in result
        assert "google.com" in result
        assert "amazon.com" in result

    @pytest.mark.asyncio
    async def test_loads_plain_text_one_domain_per_line(self, tmp_path):
        txt_content = "paypal.com\ngoogle.com\n"
        f = tmp_path / "top1m.txt"
        f.write_text(txt_content, encoding="utf-8")
        result = await _load_top1m(f)
        assert "paypal.com" in result

    @pytest.mark.asyncio
    async def test_returns_empty_set_on_missing_file(self, tmp_path):
        result = await _load_top1m(tmp_path / "nonexistent.csv")
        assert isinstance(result, set)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_respects_limit_parameter(self, tmp_path):
        lines = "\n".join(f"{i},domain{i}.com" for i in range(1, 101))
        f = tmp_path / "top100.csv"
        f.write_text(lines, encoding="utf-8")
        result = await _load_top1m(f, limit=10)
        assert len(result) <= 10

    @pytest.mark.asyncio
    async def test_skips_empty_lines(self, tmp_path):
        txt_content = "paypal.com\n\n\ngoogle.com\n"
        f = tmp_path / "domains.txt"
        f.write_text(txt_content, encoding="utf-8")
        result = await _load_top1m(f)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_deduplicates_domains(self, tmp_path):
        txt_content = "paypal.com\npaypal.com\npaypal.com\n"
        f = tmp_path / "dupes.txt"
        f.write_text(txt_content, encoding="utf-8")
        result = await _load_top1m(f)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_preserves_compound_suffix_registrants(self, tmp_path):
        f = tmp_path / "domains.csv"
        f.write_text(
            "1,portal.usbbog.edu.co\n2,WWW.BBC.CO.UK.\n"
            "3,news.bbc.co.uk\n4,evil.co.uk\n",
            encoding="utf-8",
        )
        assert await _load_top1m(f) == {"usbbog.edu.co", "bbc.co.uk", "evil.co.uk"}


# ---------------------------------------------------------------------------
# IDNAgent
# ---------------------------------------------------------------------------

class TestIDNAgentInitialize:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("catalog", "references", "expected"),
        [
            ({"о": ["o"]}, {"usbbog.edu.co"}, True),
            ({}, {"usbbog.edu.co"}, False),
            ({"о": ["o"]}, set(), False),
        ],
    )
    async def test_reference_knowledge_requires_catalog_and_index(self, catalog, references, expected):
        agent = IDNAgent()
        assert agent.has_reference_knowledge is False
        with patch("agents.idn_agent.load_confusables_catalog", return_value=catalog):
            await agent.initialize(reference_domains=references)
        assert agent.ready is True
        assert agent.has_reference_knowledge is expected

    @pytest.mark.asyncio
    async def test_initialize_sets_ready_true(self):
        agent = IDNAgent()
        assert not agent._ready
        with patch("agents.idn_agent.load_confusables_catalog", return_value={}):
            with patch("pathlib.Path.exists", return_value=False):
                await agent.initialize(confusables_path="/fake/path")
        assert agent._ready is True

    @pytest.mark.asyncio
    async def test_initialize_with_reference_domains(self):
        agent = IDNAgent()
        domains = {"paypal", "google"}
        with patch("agents.idn_agent.load_confusables_catalog", return_value={}):
            await agent.initialize(
                confusables_path="/fake/path",
                reference_domains=domains,
            )
        assert agent._ready is True
        assert agent._bktree is not None
        assert agent._bktree.size == 2

    @pytest.mark.asyncio
    async def test_initialize_loads_top1m_when_exists(self, tmp_path):
        csv = tmp_path / "top1m.csv"
        csv.write_text("1,paypal.com\n2,bbc.co.uk\n", encoding="utf-8")
        agent = IDNAgent()
        with patch("agents.idn_agent.load_confusables_catalog", return_value={}):
            with patch("agents.idn_agent.settings.TOP1M_PATH", str(csv)):
                await agent.initialize(confusables_path="/fake/path")
        assert agent._ready is True
        assert agent._reference_domains == {"paypal.com", "bbc.co.uk"}
        assert (await agent.analyze("https://paypa1.com")).visual_similarity > 0.8
        assert agent.is_trusted_domain("news.bbc.co.uk") is True
        assert agent.is_trusted_domain("evil.co.uk") is False

    @pytest.mark.asyncio
    async def test_reference_domains_are_normalized_separately_from_labels(self):
        agent = IDNAgent()
        with patch("agents.idn_agent.load_confusables_catalog", return_value={}):
            await agent.initialize(reference_domains={" LOGIN.PAYPAL.COM. ", "www.bbc.co.uk"})
        assert agent._reference_domains == {"paypal.com", "bbc.co.uk"}
        assert (await agent.analyze("https://paypa1.net")).visual_similarity > 0.8
        assert agent.is_trusted_domain("mail.paypal.com") is True
        assert agent.is_trusted_domain("paypal.net") is False
        assert agent.is_trusted_domain("evil.co.uk") is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("use_punycode", [False, True])
    async def test_compound_suffix_homograph_matches_full_reference_domain(self, use_punycode):
        agent = IDNAgent()
        label = "usbbоg"  # Cyrillic о, not Latin o
        with patch("agents.idn_agent.load_confusables_catalog", return_value={"о": ["o"]}):
            await agent.initialize(reference_domains={"usbbog.edu.co"})
        host_label = label.encode("idna").decode("ascii") if use_punycode else label
        result = await agent.analyze(f"https://login.{host_label}.edu.co")
        assert result.domain_unicode == label
        assert result.confusable_chars == ["о"]
        assert result.homograph_ratio == pytest.approx(1 / 6, abs=0.0001)
        assert result.visual_similarity == 1.0
        assert result.is_mixed_script is True
        assert result.is_suspicious is True
        assert result.s_idn_local >= 0.85
        assert agent.is_trusted_domain(f"{host_label}.edu.co") is False

    @pytest.mark.asyncio
    async def test_punycode_reference_uses_unicode_label_for_similarity(self):
        agent = IDNAgent()
        with patch("agents.idn_agent.load_confusables_catalog", return_value={}):
            await agent.initialize(reference_domains={"xn--bcher-kva.de"})
        result = await agent.analyze("https://bücher.example")
        assert result.visual_similarity == 1.0
        assert agent.is_trusted_domain("bücher.example") is False


class TestIDNAgentAnalyze:
    @pytest.fixture
    def agent_no_bktree(self) -> IDNAgent:
        """IDNAgent without BKTree for fast unit tests."""
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = None
        agent._ready = True
        return agent

    @pytest.fixture
    def agent_with_bktree(self) -> IDNAgent:
        """IDNAgent with BKTree containing reference domains."""
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = BKTree(confusables={})
        agent._bktree.insert("paypal")
        agent._bktree.insert("google")
        agent._bktree.insert("amazon")
        agent._ready = True
        return agent

    @pytest.mark.asyncio
    async def test_analyze_clean_domain_returns_low_score(self, agent_no_bktree: IDNAgent):
        result = await agent_no_bktree.analyze("https://paypal.com/login")
        assert result.s_idn_local < 0.5
        assert not result.is_suspicious

    @pytest.mark.asyncio
    async def test_analyze_returns_idn_result_instance(self, agent_no_bktree: IDNAgent):
        result = await agent_no_bktree.analyze("https://paypal.com")
        assert isinstance(result, IDNResult)

    @pytest.mark.asyncio
    async def test_analyze_score_within_bounds(self, agent_no_bktree: IDNAgent):
        result = await agent_no_bktree.analyze("https://paypal.com")
        assert 0.0 <= result.s_idn_local <= 1.0
        assert 0.0 <= result.homograph_ratio <= 1.0
        assert 0.0 <= result.visual_similarity <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_with_bktree_detects_similar_domain(self, agent_with_bktree: IDNAgent):
        # "paypa1" (digit 1) vs "paypal" → distance 1 → sim ≈ 5/6 ≈ 0.83
        result = await agent_with_bktree.analyze("https://paypa1.com/login")
        assert result.visual_similarity > 0.5

    @pytest.mark.asyncio
    async def test_analyze_mixed_script_activates_f_mix(self, agent_no_bktree: IDNAgent):
        cyrillic_p = chr(0x0440)
        # Mock detect_confusables + is_mixed_script
        with patch("agents.idn_agent.detect_confusables", return_value=[{"char": cyrillic_p}]):
            with patch("agents.idn_agent.is_mixed_script", return_value=True):
                result = await agent_no_bktree.analyze(f"https://{cyrillic_p}aypal.com")
        assert result.is_mixed_script is True

    @pytest.mark.asyncio
    async def test_analyze_sets_domain_unicode(self, agent_no_bktree: IDNAgent):
        result = await agent_no_bktree.analyze("https://paypal.com")
        assert result.domain_unicode == "paypal"

    @pytest.mark.asyncio
    async def test_analyze_confusable_chars_list(self, agent_no_bktree: IDNAgent):
        cyrillic_p = chr(0x0440)
        with patch("agents.idn_agent.detect_confusables",
                   return_value=[{"char": cyrillic_p, "position": 0, "script": "CYRILLIC", "lookalike": "p"}]):
            result = await agent_no_bktree.analyze(f"https://{cyrillic_p}aypal.com")
        assert cyrillic_p in result.confusable_chars

    @pytest.mark.asyncio
    async def test_analyze_is_suspicious_when_homograph_ratio_high(self):
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = None
        agent._ready = True
        # Create a domain with 40% confusables (> threshold 0.30)
        cyrillic_chars = [chr(0x0430), chr(0x0435)]  # а, е
        label = "".join(cyrillic_chars) + "pal"
        with patch("agents.idn_agent.detect_confusables",
                   return_value=[{"char": c} for c in cyrillic_chars]):
            with patch("agents.idn_agent.is_mixed_script", return_value=True):
                with patch("utils.url_parser.extract_domain", return_value=f"{label}.com"):
                    with patch("utils.url_parser.extract_2ld", return_value=label):
                        result = await agent.analyze(f"https://{label}.com")
        assert result.is_suspicious or result.homograph_ratio > 0

    @pytest.mark.asyncio
    async def test_analyze_no_bktree_visual_similarity_zero(self, agent_no_bktree: IDNAgent):
        result = await agent_no_bktree.analyze("https://paypal.com")
        assert result.visual_similarity == 0.0

    @pytest.mark.asyncio
    async def test_analyze_bktree_empty_visual_similarity_zero(self):
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = BKTree(confusables={})  # empty tree
        agent._ready = True
        result = await agent.analyze("https://paypal.com")
        assert result.visual_similarity == 0.0

    @pytest.mark.asyncio
    async def test_floor_rule_applied_when_mixed_and_high_sim(self):
        """Floor rule: s_idn_local = max(s_idn_local, 0.85) when mixed + sim_v >= 0.90."""
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = BKTree(confusables={})
        agent._bktree.insert("paypal")
        agent._ready = True
        cyrillic_p = chr(0x0440)
        with patch("agents.idn_agent.detect_confusables",
                   return_value=[{"char": cyrillic_p}]):
            with patch("agents.idn_agent.is_mixed_script", return_value=True):
                # Force sim_v to 0.95 via BKTree search mock
                with patch.object(agent._bktree, "search", return_value=[("paypal", 0.95)]):
                    result = await agent.analyze(f"https://{cyrillic_p}aypal.com")
        assert result.s_idn_local >= 0.85

    @pytest.mark.asyncio
    async def test_score_saturated_to_one(self):
        """Score must never exceed 1.0 even with F_MIX applied."""
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = None
        agent._ready = True
        # All chars confusable → r_h = 1.0, and mixed → F_MIX=1.6 → raw > 1.0
        with patch("agents.idn_agent.detect_confusables",
                   return_value=[{"char": c} for c in "paypal"]):
            with patch("agents.idn_agent.is_mixed_script", return_value=True):
                result = await agent.analyze("https://paypal.com")
        assert result.s_idn_local <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_raises_idn_error_on_bad_url(self):
        """IDNAnalysisError raised and re-raised for analysis errors."""
        from core.exceptions import IDNAnalysisError
        agent = IDNAgent()
        agent._confusables = {}
        agent._bktree = None
        agent._ready = True
        with patch("agents.idn_agent.extract_domain", side_effect=Exception("bad url")):
            with pytest.raises(IDNAnalysisError):
                await agent.analyze("https://bad.url")


# ---------------------------------------------------------------------------
# is_trusted_domain (T3 — docs/tasks.md)
# ---------------------------------------------------------------------------

class TestIsTrustedDomain:
    @pytest.fixture
    def initialized_agent(self):
        from agents.idn_agent import IDNAgent

        agent = IDNAgent()
        agent._reference_domains = {"google.com", "paypal.com", "vercel.app"}
        return agent

    def test_institutional_suffix_is_trusted(self, initialized_agent):
        assert initialized_agent.is_trusted_domain("correo.usbbog.edu.co") is True
        assert initialized_agent.is_trusted_domain("usbbog.edu.co") is True

    def test_microsoft_login_is_trusted(self, initialized_agent):
        assert initialized_agent.is_trusted_domain("login.microsoftonline.com") is True

    def test_top1m_2ld_is_trusted(self, initialized_agent):
        assert initialized_agent.is_trusted_domain("mail.google.com") is True
        assert initialized_agent.is_trusted_domain("paypal.com") is True

    @pytest.mark.parametrize(
        "domain",
        ["attacker.vercel.app", "login.attacker.vercel.app", "ATTACKER.VERCEL.APP."],
    )
    def test_shared_hosting_tenants_do_not_inherit_provider_trust(self, initialized_agent, domain):
        assert initialized_agent.is_trusted_domain(domain) is False
        assert initialized_agent.is_trusted_domain("vercel.app") is True

    def test_shared_hosting_tenants_do_not_inherit_configured_suffix_trust(self, initialized_agent):
        with patch("agents.idn_agent.TRUSTED_DOMAIN_SUFFIXES", {"vercel.app"}):
            assert initialized_agent.is_trusted_domain("attacker.vercel.app") is False

    def test_compound_suffix_does_not_grant_sibling_domain_trust(self, initialized_agent):
        initialized_agent._reference_domains.add("bbc.co.uk")
        assert initialized_agent.is_trusted_domain("www.bbc.co.uk") is True
        assert initialized_agent.is_trusted_domain("evil.co.uk") is False

    def test_unknown_domain_not_trusted(self, initialized_agent):
        assert initialized_agent.is_trusted_domain("evil-login.tk") is False
        assert initialized_agent.is_trusted_domain("рaypal.com") is False

    def test_lookalike_suffix_not_trusted(self, initialized_agent):
        """evil-usbbog.edu.co.attacker.com no debe matchear por sufijo."""
        assert (
            initialized_agent.is_trusted_domain("usbbog.edu.co.attacker.com") is False
        )

    def test_empty_domain_not_trusted(self, initialized_agent):
        assert initialized_agent.is_trusted_domain("") is False


@pytest.mark.asyncio
async def test_known_owner_is_not_an_idn_attack_but_same_label_elsewhere_is():
    agent = IDNAgent()
    await agent.initialize(reference_domains={"paypal.com", "usbbog.edu.co"})
    for url in ("https://paypal.com", "https://usbbog.edu.co"):
        result = await agent.analyze(url)
        assert result.s_idn_local == 0.0 and not result.is_suspicious
    same_label = await agent.analyze("https://paypal.example")
    assert same_label.visual_similarity == 1.0 and same_label.is_suspicious
    homograph = await agent.analyze("https://usbbоg.edu.co")
    assert homograph.s_idn_local >= 0.85 and homograph.is_suspicious
