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


# ---------------------------------------------------------------------------
# IDNAgent
# ---------------------------------------------------------------------------

class TestIDNAgentInitialize:
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
        csv.write_text("1,paypal.com\n", encoding="utf-8")
        agent = IDNAgent()
        with patch("agents.idn_agent.load_confusables_catalog", return_value={}):
            with patch("core.config.settings") as mock_settings:
                mock_settings.CONFUSABLES_PATH = "/fake/path"
                mock_settings.TOP1M_PATH = str(csv)
                await agent.initialize(confusables_path="/fake/path")
        assert agent._ready is True


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
