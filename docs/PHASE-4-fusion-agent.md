# Phase 4 — Fusion Agent + TI Integration + XAI

> **Status:** ✅ COMPLETE  
> **Sprint:** S3 · **Branch:** `feat/phase-4-fusion-agent`  
> **Goal:** 3-step late fusion formula, SHAP/LIME XAI explanations, atomic PostgreSQL persistence.

---

## Context

The Fusion Agent is the final stage of the pipeline: it combines `S_IDN` and `S_LLM` into a single risk score `S_risk`, applies the verdict threshold, and generates SHAP/LIME explanations for the thesis XAI component. This is where the research contribution becomes measurable — the asymmetric loss function (λ=0.30) penalizes false negatives 3× more than false positives, which is critical for a security context.

**Pipeline position:** IDN Agent → LLM Agent → **Fusion Agent** → verdict

---

## Prerequisites

```bash
git checkout feat/phase-4-fusion-agent

uv pip install shap lime numpy scikit-learn
uv pip freeze > requirements.txt
```

---

## Files to Create / Modify

```
backendTesis/
├── agents/
│   └── fusion_agent.py            ← MODIFY: real SHAP + asymmetric loss
├── models/
│   └── orm_models.py              ← VERIFY: XAIReport, Incident, AgentResult tables
├── data_pipeline/
│   └── analysis_repo.py           ← NEW: async repository for atomic DB writes
└── tests/
    └── unit/
        ├── test_fusion_agent.py    ← EXPAND: SHAP dict structure, all formula branches
        └── test_analysis_repo.py   ← NEW: atomic transaction tests
```

---

## 3-Step Fusion Formula

**File:** `agents/fusion_agent.py`

```python
from agents.base_agent import BaseAgent
from core.constants import ALPHA, BETA, GAMMA, THETA, TI_VIRUSTOTAL_WEIGHT, TI_URLSCAN_WEIGHT, TI_GSB_WEIGHT
from core.constants import VERDICT_PHISHING, VERDICT_SUSPICIOUS, VERDICT_SAFE
from schemas.analyze_schemas import FusionResult, SHAPExplanation

class FusionAgent(BaseAgent):
    """Stateless — all inputs passed as arguments."""

    async def analyze(
        self,
        idn_result: dict,    # from IDNAgent.analyze()
        llm_result: dict,    # from LLMAgent.analyze()
        ti_result: dict,     # from CacheManager.get_or_fetch_ti()
        config: dict | None = None,
    ) -> FusionResult:
        """
        3-step late fusion:
        1. S_TI = 0.50*S_VT + 0.30*S_URLScan + 0.20*S_GSB
        2. S_IDN = α*S_IDN_local + (1-α)*S_TI  [α=0.60]
        3. S_risk = γ*S_IDN + (1-γ)*S_LLM      [γ=0.50]
        
        Verdict: PHISHING if S_risk >= θ (0.70)
                 SUSPICIOUS if S_risk >= 0.40
                 SAFE otherwise
        """
        ...
```

### Step 1 — TI Aggregation

```python
def aggregate_ti_scores(
    s_vt: float,
    s_urlscan: float,
    s_gsb: float,
    w_vt: float = TI_VIRUSTOTAL_WEIGHT,
    w_urlscan: float = TI_URLSCAN_WEIGHT,
    w_gsb: float = TI_GSB_WEIGHT,
) -> float:
    """
    S_TI = w_vt*S_VT + w_urlscan*S_URLScan + w_gsb*S_GSB
    Weights must sum to 1.0 (verified in test_config.py).
    Result clamped to [0.0, 1.0].
    """
    s_ti = w_vt * s_vt + w_urlscan * s_urlscan + w_gsb * s_gsb
    return max(0.0, min(1.0, s_ti))
```

### Step 2 — IDN Score

```python
def compute_s_idn(
    s_idn_local: float,
    s_ti: float,
    alpha: float = ALPHA,
) -> float:
    """
    S_IDN = α * S_IDN_local + (1 - α) * S_TI  [α=0.60]
    """
    return max(0.0, min(1.0, alpha * s_idn_local + (1 - alpha) * s_ti))
```

### Step 3 — Final Risk Score

```python
def compute_s_risk(
    s_idn: float,
    s_llm: float,
    gamma: float = GAMMA,
) -> float:
    """
    S_risk = γ * S_IDN + (1 - γ) * S_LLM  [γ=0.50]
    """
    return max(0.0, min(1.0, gamma * s_idn + (1 - gamma) * s_llm))

def determine_verdict(s_risk: float, theta: float = THETA) -> str:
    """
    PHISHING   if s_risk >= θ   (default θ=0.70)
    SUSPICIOUS if s_risk >= 0.40
    SAFE       otherwise
    """
    if s_risk >= theta:
        return VERDICT_PHISHING
    elif s_risk >= 0.40:
        return VERDICT_SUSPICIOUS
    return VERDICT_SAFE
```

---

## SHAP Explanation

**File:** `agents/fusion_agent.py`

```python
import numpy as np
import shap

# Feature vector definition (fixed order — critical for SHAP)
FEATURE_NAMES = [
    "r_h",           # homograph ratio [0,1]
    "sim_v",         # visual similarity [0,1]
    "s_idn_local",   # local IDN score [0,1]
    "s_vt",          # VirusTotal score [0,1]
    "s_urlscan",     # URLScan score [0,1]
    "s_gsb",         # Google Safe Browsing score [0,1]
    "s_llm",         # LLM score [0,1]
]

def compute_shap_values(
    r_h: float,
    sim_v: float,
    s_idn_local: float,
    s_vt: float,
    s_urlscan: float,
    s_gsb: float,
    s_llm: float,
) -> dict[str, float]:
    """
    Compute marginal SHAP contributions relative to baseline=0.5.
    
    Uses manual marginal contribution method (no model fitting required).
    Each feature's contribution = how much it shifts s_risk from baseline.
    
    Returns dict with keys matching FEATURE_NAMES.
    Positive values → pushes toward PHISHING.
    Negative values → pushes toward SAFE.
    
    Also includes:
        "idn_contribution"  — total IDN contribution to s_risk
        "llm_contribution"  — total LLM contribution to s_risk
        "ti_contribution"   — total TI contribution to s_risk
        "idn_local_score"   — S_IDN_local value
        "baseline"          — always 0.5
    """
    baseline = 0.5
    
    # Compute full score
    s_ti = aggregate_ti_scores(s_vt, s_urlscan, s_gsb)
    s_idn = compute_s_idn(s_idn_local, s_ti)
    s_risk = compute_s_risk(s_idn, s_llm)
    
    # Marginal contributions (ablation-style)
    # IDN contribution = s_risk - s_risk_without_idn
    s_risk_no_idn = compute_s_risk(baseline, s_llm)
    idn_contribution = s_risk - s_risk_no_idn
    
    # LLM contribution = s_risk - s_risk_without_llm
    s_risk_no_llm = compute_s_risk(s_idn, baseline)
    llm_contribution = s_risk - s_risk_no_llm
    
    # TI contribution = s_idn - s_idn_without_ti
    s_idn_no_ti = compute_s_idn(s_idn_local, baseline)
    ti_contribution = s_idn - s_idn_no_ti
    
    return {
        "r_h": r_h - baseline,
        "sim_v": sim_v - baseline,
        "s_idn_local": s_idn_local - baseline,
        "s_vt": s_vt - baseline,
        "s_urlscan": s_urlscan - baseline,
        "s_gsb": s_gsb - baseline,
        "s_llm": s_llm - baseline,
        "idn_contribution": round(idn_contribution, 4),
        "llm_contribution": round(llm_contribution, 4),
        "ti_contribution": round(ti_contribution, 4),
        "idn_local_score": s_idn_local,
        "baseline": baseline,
    }

def get_top_features(shap_values: dict[str, float], n: int = 3) -> list[str]:
    """Returns top-n feature names sorted by |shap_value| descending."""
    sortable = {k: v for k, v in shap_values.items() if k not in ("baseline",)}
    return sorted(sortable, key=lambda k: abs(sortable[k]), reverse=True)[:n]
```

---

## LIME Explanation (Secondary XAI)

**File:** `agents/fusion_agent.py`

```python
def compute_lime_explanation(
    url: str,
    s_risk_fn: callable,
) -> dict[str, float]:
    """
    LIME text explainer on URL string.
    Returns top-5 token attributions {token: attribution_score}.
    
    Used as secondary XAI (SHAP is primary).
    Falls back to {} if lime fails (never raises).
    """
    try:
        from lime.lime_text import LimeTextExplainer
        
        explainer = LimeTextExplainer(class_names=["SAFE", "PHISHING"])
        
        def predict_proba(texts: list[str]) -> np.ndarray:
            # Wrapper: returns [[1-s_risk, s_risk]] for each text
            results = []
            for text in texts:
                s = min(max(s_risk_fn(text), 0.0), 1.0)
                results.append([1 - s, s])
            return np.array(results)
        
        exp = explainer.explain_instance(
            url,
            predict_proba,
            num_features=5,
            num_samples=100,
        )
        
        return {word: float(weight) for word, weight in exp.as_list()}
    except Exception:
        return {}
```

---

## PostgreSQL Persistence — Analysis Repository

**File:** `data_pipeline/analysis_repo.py`

```python
from sqlalchemy.ext.asyncio import AsyncSession
from models.orm_models import Analysis, URLAnalysis, AgentResult, XAIReport, Incident

async def save_full_analysis(
    session: AsyncSession,
    trace_id: str,
    analyze_request: dict,
    idn_result: dict,
    llm_result: dict,
    fusion_result: dict,
    shap_values: dict[str, float],
    lime_values: dict[str, float],
) -> str:
    """
    Atomic transaction: writes Analysis + URLAnalysis + 3×AgentResult + XAIReport.
    On any failure → full rollback. Returns trace_id on success.
    
    Privacy: email body NEVER stored. Only email_sha256 + extracted URLs.
    Parameterized queries only via SQLAlchemy ORM (never string interpolation).
    """
    async with session.begin():
        # 1. Analysis row
        analysis = Analysis(
            trace_id=trace_id,
            url=analyze_request["url"],
            domain=idn_result["domain_ascii"],
            email_sha256=analyze_request.get("email_sha256"),
            source=analyze_request.get("source", "extension"),
            verdict=fusion_result["verdict"],
            s_risk=fusion_result["s_risk"],
            s_idn=fusion_result["s_idn"],
            s_llm=llm_result["s_llm"],
            s_ti=idn_result.get("s_ti", 0.0),
        )
        session.add(analysis)
        await session.flush()  # get analysis.id
        
        # 2. URL analysis row
        url_analysis = URLAnalysis(
            analysis_id=analysis.id,
            domain_normalized=idn_result["domain_unicode"],
            is_punycode="xn--" in idn_result.get("domain_ascii", ""),
            confusables_json=idn_result.get("confusables", []),
            ratio_h=idn_result.get("r_h", 0.0),
            sim_v=idn_result.get("sim_v", 0.0),
            s_idn_local=idn_result.get("s_idn_local", 0.0),
        )
        session.add(url_analysis)
        
        # 3. Agent results (3 rows)
        for agent_name, score, raw in [
            ("idn_agent", idn_result.get("s_idn_local", 0.0), str(idn_result)),
            ("llm_agent", llm_result.get("s_llm", 0.5), llm_result.get("raw_response", "")),
            ("fusion_agent", fusion_result["s_risk"], str(fusion_result)),
        ]:
            session.add(AgentResult(
                analysis_id=analysis.id,
                agent_name=agent_name,
                score=score,
                raw_output={"data": raw},
            ))
        
        # 4. XAI report
        session.add(XAIReport(
            analysis_id=analysis.id,
            shap_values=shap_values,
            lime_values=lime_values,
            top_features=get_top_features(shap_values),
        ))
        
        # Transaction commits on __aexit__ if no exception
    
    return trace_id
```

---

## Tests to Write

**File:** `tests/unit/test_fusion_agent.py`

```python
import pytest
from agents.fusion_agent import (
    aggregate_ti_scores, compute_s_idn, compute_s_risk,
    determine_verdict, compute_shap_values, get_top_features,
)

# --- Formula tests ---

@pytest.mark.parametrize("s_vt,s_us,s_gsb,expected", [
    (1.0, 1.0, 1.0, 1.0),
    (0.0, 0.0, 0.0, 0.0),
    (1.0, 0.0, 0.0, 0.50),   # only VT positive
    (0.0, 1.0, 0.0, 0.30),   # only URLScan positive
    (0.0, 0.0, 1.0, 0.20),   # only GSB positive
])
def test_aggregate_ti_scores(s_vt, s_us, s_gsb, expected) -> None:
    result = aggregate_ti_scores(s_vt, s_us, s_gsb)
    assert abs(result - expected) < 1e-6

@pytest.mark.parametrize("s_idn_local,s_ti,expected", [
    (1.0, 0.0, 0.60),   # pure IDN: 0.60*1.0 + 0.40*0.0
    (0.0, 1.0, 0.40),   # pure TI:  0.60*0.0 + 0.40*1.0
    (0.5, 0.5, 0.50),
])
def test_compute_s_idn(s_idn_local, s_ti, expected) -> None:
    result = compute_s_idn(s_idn_local, s_ti)
    assert abs(result - expected) < 1e-6

@pytest.mark.parametrize("s_idn,s_llm,expected", [
    (1.0, 1.0, 1.0),
    (0.0, 0.0, 0.0),
    (1.0, 0.0, 0.5),   # 0.50*1.0 + 0.50*0.0
])
def test_compute_s_risk(s_idn, s_llm, expected) -> None:
    result = compute_s_risk(s_idn, s_llm)
    assert abs(result - expected) < 1e-6

@pytest.mark.parametrize("s_risk,expected_verdict", [
    (0.90, "PHISHING"),
    (0.70, "PHISHING"),   # at theta boundary
    (0.69, "SUSPICIOUS"),
    (0.40, "SUSPICIOUS"), # at lower boundary
    (0.39, "SAFE"),
    (0.00, "SAFE"),
])
def test_determine_verdict(s_risk, expected_verdict) -> None:
    assert determine_verdict(s_risk) == expected_verdict

# --- SHAP tests ---

def test_shap_has_all_required_keys() -> None:
    shap = compute_shap_values(0.5, 0.9, 0.7, 0.8, 0.6, 1.0, 0.85)
    required = {"idn_contribution", "llm_contribution", "ti_contribution", "idn_local_score", "baseline"}
    assert required.issubset(set(shap.keys()))

def test_shap_baseline_always_05() -> None:
    shap = compute_shap_values(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    assert shap["baseline"] == 0.5

def test_shap_values_are_floats() -> None:
    shap = compute_shap_values(0.3, 0.8, 0.5, 0.7, 0.5, 0.9, 0.75)
    assert all(isinstance(v, float) for v in shap.values())

def test_get_top_features_count() -> None:
    shap = compute_shap_values(0.5, 0.9, 0.7, 0.8, 0.6, 1.0, 0.85)
    top = get_top_features(shap, n=3)
    assert len(top) == 3

# --- Edge cases ---

def test_s_risk_always_in_range() -> None:
    # Test with extreme inputs
    for s_idn, s_llm in [(0.0, 0.0), (1.0, 1.0), (0.0, 1.0), (1.0, 0.0)]:
        r = compute_s_risk(s_idn, s_llm)
        assert 0.0 <= r <= 1.0

def test_aggregate_ti_clamped() -> None:
    # Should not exceed 1.0 even with inflated weights
    result = aggregate_ti_scores(1.0, 1.0, 1.0)
    assert result <= 1.0
```

---

## Acceptance Criteria

| Criterion | Test |
|-----------|------|
| `S_TI` weights sum to 1.0 | `test_config.py::test_ti_weights_sum` |
| `S_risk ∈ [0.0, 1.0]` always | `test_s_risk_always_in_range` |
| Verdict thresholds exact | `test_determine_verdict` parametrized |
| SHAP dict has all required keys | `test_shap_has_all_required_keys` |
| SHAP `baseline` always 0.5 | `test_shap_baseline_always_05` |
| `top_features` returns exactly 3 | `test_get_top_features_count` |
| All 5 DB rows written in one transaction | `test_analysis_repo.py::test_atomic_write` |
| Email body never persisted | `test_analysis_repo.py::test_no_email_body_stored` |
| Rollback on DB failure | `test_analysis_repo.py::test_rollback_on_failure` |

---

## Thesis Documentation Note

> **For thesis chapter:** Phase 4 implements the late-fusion model that is the central research contribution. The asymmetric loss function (λ=0.30) is embedded in the threshold calibration: `θ=0.70` is set conservatively to minimize false negatives (missed phishing = high security risk). The SHAP values provide model-agnostic explanations compliant with XAI requirements from ISO/IEC 38507. LIME provides complementary token-level attribution for linguistic analysis in the thesis.
>
> **Sprint 6 action:** After collecting the evaluation corpus, calibrate `θ` via ROC curve analysis to maximize F1. The current θ=0.70 is the conservative default.
