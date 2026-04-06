"""Tests for core/config.py — startup validation and settings loading."""

import pytest
from pydantic import ValidationError

from core.config import Settings


def test_default_settings_load():
    """Settings loads with all defaults when no .env present."""
    s = Settings()
    assert s.APP_ENV == "development"
    assert s.REDIS_TTL == 3600
    assert s.ALGORITHM == "HS256"
    assert s.ACCESS_TOKEN_EXPIRE_MINUTES == 30


def test_fusion_params_in_constants():
    """All fusion params are defined as constants, not in config."""
    from core.constants import ALPHA, BETA, GAMMA, THETA
    assert 0.0 < ALPHA < 1.0
    assert 0.0 < BETA < 1.0
    assert 0.0 < GAMMA < 1.0
    assert 0.0 < THETA < 1.0


def test_ti_weights_sum_to_one():
    from core.constants import TI_GSB_WEIGHT, TI_URLSCAN_WEIGHT, TI_VIRUSTOTAL_WEIGHT
    total = TI_VIRUSTOTAL_WEIGHT + TI_URLSCAN_WEIGHT + TI_GSB_WEIGHT
    assert abs(total - 1.0) < 1e-9


def test_verdict_constants():
    from core.constants import VERDICT_PHISHING, VERDICT_SAFE, VERDICT_SUSPICIOUS
    assert VERDICT_PHISHING == "PHISHING"
    assert VERDICT_SUSPICIOUS == "SUSPICIOUS"
    assert VERDICT_SAFE == "SAFE"


def test_default_cors_origins():
    s = Settings()
    assert isinstance(s.CORS_ORIGINS, list)
    assert len(s.CORS_ORIGINS) >= 1


def test_llamastack_defaults():
    s = Settings()
    assert s.LLAMASTACK_URL.startswith("http")
    assert "Llama" in s.LLAMASTACK_MODEL


def test_chromadb_collection_names():
    from core.constants import (
        COLLECTION_EMAIL_EMBEDDINGS,
        COLLECTION_IDN_PATTERNS,
        COLLECTION_TI_SIGNALS,
    )
    assert COLLECTION_EMAIL_EMBEDDINGS == "email_embeddings"
    assert COLLECTION_IDN_PATTERNS == "idn_patterns"
    assert COLLECTION_TI_SIGNALS == "ti_signals"
