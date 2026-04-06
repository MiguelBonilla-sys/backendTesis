# Phase 2 — IDN Agent

> **Status:** 🔴 TODO  
> **Sprint:** S1 · **Branch:** `feat/phase-2-idn-agent`  
> **Goal:** Full 5-stage IDN detection algorithm with TI enrichment, Redis caching, and unit tests ≥ 90% coverage.

---

## Context

The IDN (Internationalized Domain Name) Agent is the **core research contribution** of this thesis. It detects homograph phishing attacks — domains that use visually similar Unicode characters from different scripts (e.g., Cyrillic `а` instead of Latin `a`) to impersonate legitimate domains.

**Research basis:** RFC 5890/5891 (IDNA2008), Unicode TR#39 (confusables), Unicode UTS#46 (mapping)

---

## Prerequisites

```bash
git checkout feat/phase-2-idn-agent

# Install additional deps
uv pip install tldextract pybktree python-Levenshtein httpx[asyncio] vt-py
uv pip freeze > requirements.txt
```

---

## Files to Create / Modify

```
backendTesis/
├── agents/
│   ├── confusables_loader.py      ← NEW: parse Unicode TR#39 confusables.txt
│   ├── bktree.py                  ← NEW: BK-tree for visual similarity
│   └── idn_agent.py               ← MODIFY: integrate confusables + bktree
├── data_pipeline/
│   └── threat_intel.py            ← MODIFY: add WhoisXML client
├── data/
│   └── confusables.txt            ← DOWNLOAD: from unicode.org/Public/security/
└── tests/
    └── unit/
        └── test_idn_agent.py      ← EXPAND: ≥10 parametrized IDN phishing domains
```

---

## 5-Stage Algorithm

### Stage 1 — Unicode NFC Normalization + Punycode Decoding

**File:** `agents/idn_agent.py`

```python
import unicodedata
import tldextract

def normalize_domain(url: str) -> dict[str, str] | None:
    """
    Extract 2LD from URL, apply NFC normalization, decode Punycode.
    Returns {"unicode": "äpple.com", "ascii": "xn--pple-43d.com"} or None on error.
    """
    # 1. Extract using tldextract (handles eTLDs correctly)
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    # 2. Detect and decode Punycode (xn-- prefix)
    if "xn--" in domain:
        domain_unicode = domain.encode("ascii").decode("idna")
    else:
        domain_unicode = domain
    
    # 3. Apply NFC normalization
    domain_unicode = unicodedata.normalize("NFC", domain_unicode)
    
    return {"unicode": domain_unicode, "ascii": domain.encode("idna").decode("ascii")}
```

**Acceptance criteria:**
- `normalize_domain("https://xn--pple-43d.com")` → `{"unicode": "äpple.com", "ascii": "xn--pple-43d.com"}`
- Malformed URL → returns `None`, never raises
- Pure ASCII domain → returns both forms equal

---

### Stage 2 — TR#39 Confusable Detection

**File:** `agents/confusables_loader.py`

```python
# Download source: https://www.unicode.org/Public/security/latest/confusables.txt
# Format: <codepoint> ; <target_codepoints> ; <type> # <comments>

def load_confusables(path: str) -> dict[str, list[str]]:
    """
    Parse confusables.txt → {char: [lookalike_chars]}.
    Keys are single Unicode characters. Values are characters that look the same.
    """
    ...

def detect_confusables(domain_unicode: str, catalog: dict[str, list[str]]) -> list[dict]:
    """
    Returns list of confusable characters found in domain.
    Each entry: {"char": "а", "position": 1, "script": "Cyrillic", "lookalike": "a"}
    
    Only flags chars where the lookalike exists in a DIFFERENT Unicode script.
    Target scripts: CYRILLIC, GREEK, ARMENIAN, CHEROKEE, COPTIC (frozenset in constants).
    """
    ...
```

**File:** `agents/idn_agent.py` — integrate loader

```python
# Module-level singleton — load once at import
_CONFUSABLES_CATALOG: dict[str, list[str]] = {}

def _load_catalog() -> None:
    global _CONFUSABLES_CATALOG
    path = settings.CONFUSABLES_PATH  # env var pointing to data/confusables.txt
    _CONFUSABLES_CATALOG = load_confusables(path)
```

**Acceptance criteria:**
- `detect_confusables("pаypal.com", catalog)` (Cyrillic `а` at position 1) → `[{"char": "а", "position": 1, "script": "Cyrillic", "lookalike": "a"}]`
- Pure Latin domain → `[]`
- Mixed script only flagged when a different-script lookalike exists in catalog

---

### Stage 3 — Homograph Ratio

**File:** `agents/idn_agent.py`

```python
def compute_homograph_ratio(domain_2ld: str, confusables: list[dict]) -> float:
    """
    r_h = len(confusables) / len(domain_2ld)
    Clamped to [0.0, 1.0].
    Alert threshold: r_h >= 0.30 (from literature [36]).
    """
    if not domain_2ld:
        return 0.0
    r_h = len(confusables) / len(domain_2ld)
    return max(0.0, min(1.0, r_h))
```

**Acceptance criteria:**
- `r_h = 0.0` for clean domain
- `r_h >= 0.30` sets `homograph_alert=True` in `IDNResult`
- Always returns float in `[0.0, 1.0]`

---

### Stage 4 — Visual Similarity vs Top-1M Index

**File:** `agents/bktree.py`

```python
class BKTree:
    """
    BK-tree with custom edit distance for visual similarity.
    Substitution cost = 0 for confusable character pairs (from TR#39 catalog).
    """
    def __init__(self, catalog: dict[str, list[str]]) -> None: ...
    def add(self, word: str) -> None: ...
    def query(self, word: str, max_dist: int) -> list[tuple[str, int]]: ...

def levenshtein_confusable(a: str, b: str, catalog: dict[str, list[str]]) -> int:
    """Edit distance where substituting a confusable pair costs 0."""
    ...
```

**File:** `agents/idn_agent.py`

```python
# Top-1M domains loaded once at startup (from DOMAIN_INDEX_PATH env var)
_TOP_1M: list[str] = []

def compute_visual_similarity(
    domain_2ld: str,
    confusables: list[dict],
    top1m: list[str],
    catalog: dict[str, list[str]],
    max_candidates: int = 1000,
) -> tuple[float, str]:
    """
    Returns (sim_v, closest_domain).
    sim_v = 1 - edit_distance(d, d_ref) / max(len(d), len(d_ref))
    Checks first max_candidates entries. Early-exit at sim_v >= 0.95.
    """
    best_sim = 0.0
    best_match = ""
    for ref in top1m[:max_candidates]:
        dist = levenshtein_confusable(domain_2ld, ref, catalog)
        max_len = max(len(domain_2ld), len(ref))
        sim = 1.0 - dist / max_len if max_len > 0 else 1.0
        if sim > best_sim:
            best_sim = sim
            best_match = ref
        if best_sim >= 0.95:  # early exit
            break
    return best_sim, best_match
```

**Acceptance criteria:**
- `compute_visual_similarity("pаypal", ..., catalog)` vs "paypal" in top-1M → `sim_v >= 0.95`
- Runs in < 100ms for single domain against 1000 candidates
- Returns `(0.0, "")` when `top1m` is empty

---

### Stage 5 — Local IDN Score

**File:** `agents/idn_agent.py`

```python
def compute_s_idn_local(r_h: float, sim_v: float, beta: float | None = None) -> float:
    """
    S_IDN_local = β * r_h + (1 - β) * sim_v
    β from config (default BETA = 0.40 from core/constants.py).
    Returns float in [0.0, 1.0].
    """
    b = beta if beta is not None else BETA
    return max(0.0, min(1.0, b * r_h + (1 - b) * sim_v))
```

---

## TI Clients (Threat Intelligence)

**File:** `data_pipeline/threat_intel.py` — add/verify these clients:

```python
class ThreatIntelService:
    async def _virustotal(self, domain: str) -> float:
        """
        GET https://www.virustotal.com/api/v3/domains/{domain}
        Score = malicious_votes / total_votes (normalized [0,1]).
        Returns 0.0 on missing key. Raises TIFetchError on API failure.
        Header: X-Apikey: {settings.VIRUSTOTAL_API_KEY}
        """
        ...

    async def _urlscan(self, url: str) -> float:
        """
        POST https://urlscan.io/api/v1/scan/
        Poll GET https://urlscan.io/api/v1/result/{uuid}/
        Returns verdict score [0,1]. Returns 0.0 if scan not found.
        Header: API-Key: {settings.URLSCAN_API_KEY}
        """
        ...

    async def _gsb(self, url: str) -> float:
        """
        POST https://safebrowsing.googleapis.com/v4/threatMatches:find
        Returns 1.0 if match found (PHISHING/MALWARE), 0.0 otherwise.
        Key: {settings.GSB_API_KEY}
        """
        ...

    async def fetch_all(self, domain: str, url: str) -> TIResult:
        """
        Calls all 3 APIs concurrently via asyncio.gather.
        Never raises — each source returns 0.0 on failure (graceful degradation).
        """
        vt, urlscan, gsb = await asyncio.gather(
            self._virustotal(domain),
            self._urlscan(url),
            self._gsb(url),
            return_exceptions=True,
        )
        # Handle exceptions → replace with 0.0, log warning
        ...
```

**Redis cache layer** (`data_pipeline/cache_manager.py`):

```python
async def get_or_fetch_ti(
    domain: str, ti_service: ThreatIntelService, url: str
) -> TIResult:
    """
    1. Check Redis key f"ti:{domain}" → return if hit
    2. On miss: call ti_service.fetch_all(domain, url)
    3. Store in Redis with TTL=3600s
    """
    ...
```

---

## IDN Agent — Full Orchestration

**File:** `agents/idn_agent.py`

```python
from agents.base_agent import BaseAgent
from schemas.analyze_schemas import IDNAnalysisResult

class IDNAgent(BaseAgent):
    """Stateless — instantiated per request, no shared mutable state."""

    async def analyze(self, url: str) -> IDNAnalysisResult:
        """
        Runs all 5 stages and returns IDNAnalysisResult.
        
        Returns:
            IDNAnalysisResult with fields:
                domain_unicode: str
                domain_ascii: str
                confusables: list[dict]
                r_h: float
                sim_v: float
                closest_domain: str
                homograph_alert: bool  # r_h >= 0.30
                s_idn_local: float
        """
        ...
```

---

## Tests to Write

**File:** `tests/unit/test_idn_agent.py`

```python
import pytest
from agents.idn_agent import normalize_domain, compute_homograph_ratio, compute_s_idn_local

# Parametrized with known IDN phishing domains
@pytest.mark.parametrize("url,expected_alert", [
    ("https://xn--pаypal-4ve.com", True),    # Cyrillic а in paypal
    ("https://xn--micrsft-3ya.com", True),    # Cyrillic mixed in microsoft
    ("https://xn--gogIe-0ra.com", True),      # Greek omicron in google
    ("https://xn--amzon-bta.com", True),      # Cyrillic in amazon
    ("https://xn--facbook-pxa.com", True),    # Cyrillic in facebook
    ("https://xn--aplle-cua.com", True),      # Greek in apple
    ("https://xn--twltter-i1a.com", True),    # Cyrillic in twitter
    ("https://paypal.com", False),            # clean
    ("https://google.com", False),            # clean
    ("https://microsoft.com", False),         # clean
])
async def test_homograph_alert(url: str, expected_alert: bool) -> None:
    ...

def test_homograph_ratio_threshold() -> None:
    # r_h >= 0.30 triggers alert
    assert compute_homograph_ratio("pаypаl", [{"char": "а"}, {"char": "а"}]) >= 0.30

def test_s_idn_local_formula() -> None:
    # S_IDN_local = 0.40 * r_h + 0.60 * sim_v
    score = compute_s_idn_local(r_h=1.0, sim_v=0.0, beta=0.40)
    assert abs(score - 0.40) < 1e-6

def test_normalize_domain_punycode() -> None:
    result = normalize_domain("https://xn--pple-43d.com")
    assert result is not None
    assert "ä" in result["unicode"]

def test_normalize_domain_malformed() -> None:
    assert normalize_domain("not-a-url") is None

def test_ti_cache_hit_skips_api_calls(respx_mock) -> None:
    # When Redis has cached result, TI APIs should NOT be called
    ...

def test_concurrent_ti_calls(respx_mock) -> None:
    # All 3 TI APIs called in single asyncio.gather (not sequentially)
    ...
```

**Coverage target:** `pytest tests/unit/test_idn_agent.py --cov=agents/idn_agent --cov=agents/confusables_loader --cov=agents/bktree --cov-fail-under=90`

---

## Acceptance Criteria

| Criterion | How to Verify |
|-----------|---------------|
| `normalize_domain("https://xn--pple-43d.com")` returns unicode form | `test_normalize_domain_punycode` |
| Cyrillic 'а' in "pаypal" detected as confusable | `test_homograph_alert` parametrized |
| `r_h >= 0.30` on ≥10 known IDN phishing domains | `test_homograph_alert` |
| Visual similarity vs paypal `>= 0.95` | `test_visual_similarity_paypal` |
| Redis cache hit skips TI API calls | `test_ti_cache_hit_skips_api_calls` |
| All 3 TI APIs called concurrently (not sequentially) | `test_concurrent_ti_calls` |
| `S_IDN_local ∈ [0.0, 1.0]` always | `test_s_idn_local_formula` |
| Agent is stateless | no `self.` mutations between `analyze()` calls |
| `bandit -r agents/` passes | `bandit -r agents/ --severity-level medium` |

---

## Thesis Documentation Note

> **For thesis chapter:** Phase 2 implements the 5-stage IDN detection algorithm from literature [36], [42]. The confusable detection uses Unicode TR#39 as the authoritative catalog. The BK-tree enables sub-linear search against the top-1M domain index while maintaining accuracy. Homograph ratio threshold `r_h ≥ 0.30` is derived from [36].
>
> **Algorithm complexity:** O(k · L²) where k = BK-tree candidate count (~1000) and L = domain length. Typically < 100ms per domain.
