# Phase 2 — IDN Agent

> **Status:** 🟢 DONE
> **Sprint:** S1 · **Branch:** `feat/phase-2-idn-agent`
> **Goal:** Full 5-stage IDN detection algorithm with TI enrichment, Redis caching, and unit tests ≥ 90% coverage.
> **Last updated:** 2026-04-09

---

## Context

The IDN (Internationalized Domain Name) Agent is the **core research contribution** of this thesis. It detects homograph phishing attacks — domains that use visually similar Unicode characters from different scripts (e.g., Cyrillic `а` instead of Latin `a`) to impersonate legitimate domains.

**Research basis:** RFC 5890/5891 (IDNA2008), Unicode TR#39 (confusables), Unicode UTS#46 (mapping)

---

## Implementation Status

| Sub-task | File | Status |
|---|---|---|
| 5-stage IDN algorithm | `agents/idn_agent.py` | ✅ Done |
| Base agent interface | `agents/base_agent.py` | ✅ Done |
| TR#39 confusables parser (dedicated) | `agents/confusables_loader.py` | ✅ Done |
| BK-tree visual similarity | `agents/bktree.py` | ✅ Done |
| Confusables data file | `data/confusables.txt` | ✅ Done (present in repository) |
| Unit tests (≥10 parametrized domains) | `tests/unit/test_idn_agent.py` | ✅ Done (12 IDN + 5 clean domains) |
| Unit tests for confusables_loader | `tests/unit/test_confusables_loader.py` | ✅ Done (24 tests) |
| Unit tests for bktree | `tests/unit/test_bktree.py` | ✅ Done (20 tests) |
| Integrate confusables_loader into IDNAgent | `agents/idn_agent.py` | ✅ Done |
| Test fixtures | `tests/fixtures/confusables_minimal.txt`, `domains/` | ✅ Done |

---

## Prerequisites

```bash
git checkout feat/phase-2-idn-agent

# Install Phase 2 deps (if not already in requirements.txt)
uv pip install tldextract pybktree python-Levenshtein httpx[asyncio] vt-py
uv pip freeze > requirements.txt

# Download confusables catalog
curl -o data/confusables.txt \
  https://www.unicode.org/Public/security/latest/confusables.txt
```

---

## Current Implementation

### Architecture (runtime-aligned)

Phase 2 is implemented with the planned modular split and wired at startup:

- `agents/confusables_loader.py` parses TR#39 and exposes `load_confusables()` + `detect_confusables()`
- `agents/bktree.py` provides `levenshtein_confusable()` and `BKTree`
- `agents/idn_agent.py` orchestrates the 5-stage algorithm and consumes both modules
- `main.py` initializes module-level singletons with:
  - `init_catalog(settings.CONFUSABLES_PATH)`
  - `init_top1m(load_top1m(..., limit=1000))`

The previous document text that described these items as pending is now obsolete.

### `agents/idn_agent.py` — Runtime behavior

```python
from agents.bktree import levenshtein_confusable
from agents.confusables_loader import detect_confusables

confusable_entries = detect_confusables(normalized, self._catalog)
sim_v, closest = self._sim_v(second_level)

if self._catalog:
    ed = levenshtein_confusable(d, ref, self._catalog)
else:
    ed = self._levenshtein(d, ref)
```

> `analyze()` receives a domain string (not full URL). URL sanitization and extraction happen in `core/security.py` / `routers/analyze_router.py`.

---

## 5-Stage Algorithm — Implemented

### Stage 1 — Unicode NFC + Punycode awareness

- `unicodedata.normalize("NFC", domain.lower().strip())`
- `is_punycode(domain)` reported in output

### Stage 2 — TR#39 confusable detection (catalog-driven)

- Uses `detect_confusables(normalized, catalog)` from `confusables_loader.py`
- Includes heuristic fallback only when catalog is empty/missing
- Returns structured entries in `confusable_details`:
  - `{"char", "position", "script", "lookalike"}`

### Stage 3 — Homograph ratio

- `r_h = confusable_chars_in_2LD / len(2LD)`
- Alert threshold: `IDN_HOMOGRAPH_RATIO_ALERT = 0.30`

### Stage 4 — Visual similarity vs top-1M

- Evaluates first 1000 domains from top-1M index
- Early-exit at `sim_v >= 0.95`
- Uses confusable-aware distance (`levenshtein_confusable`) when catalog is loaded

### Stage 5 — Local score

- `S_IDN_local = BETA * r_h + (1 - BETA) * sim_v`
- `BETA = 0.40` from `core/constants.py`

---

## Test Evidence (current branch)

### Phase 2 unit suites

- `tests/unit/test_idn_agent.py`: 28 tests
- `tests/unit/test_confusables_loader.py`: 24 tests
- `tests/unit/test_bktree.py`: 20 tests

Executed command:

```bash
python -m pytest \
  tests/unit/test_idn_agent.py \
  tests/unit/test_confusables_loader.py \
  tests/unit/test_bktree.py \
  --cov-reset \
  --cov=agents.idn_agent \
  --cov=agents.confusables_loader \
  --cov=agents.bktree \
  --cov-fail-under=90 -q
```

Result:

- 86 passed, 0 failed
- Coverage total (these 3 modules): 92.89%
- Module coverage:
  - `agents/idn_agent.py`: 91%
  - `agents/confusables_loader.py`: 89%
  - `agents/bktree.py`: 100%

### TI/cache tests linked to Phase 2 scope

Executed command:

```bash
python -m pytest tests/unit/test_cache_manager.py tests/unit/test_threat_intel.py --no-cov -q
```

Result:

- 27 passed, 0 failed

### Consolidated Phase 2 test batch

Executed command:

```bash
python -m pytest \
  tests/unit/test_idn_agent.py \
  tests/unit/test_confusables_loader.py \
  tests/unit/test_bktree.py \
  tests/unit/test_cache_manager.py \
  tests/unit/test_threat_intel.py \
  --no-cov -q
```

Result:

- 113 passed, 0 failed

### Security check

Executed command:

```bash
python -m bandit -r agents/ --severity-level medium
```

Result:

- No issues identified (Medium/High: 0)

---

## Acceptance Criteria

| Criterion | Verification | Status |
|---|---|---|
| Confusable parser TR#39 implemented | `tests/unit/test_confusables_loader.py` | ✅ |
| BK-tree + confusable-aware distance implemented | `tests/unit/test_bktree.py` | ✅ |
| ≥10 IDN phishing domains covered | `tests/unit/test_idn_agent.py` (12 parametrized IDN) | ✅ |
| `r_h >= 0.30` alert behavior | `test_homograph_ratio_alert_threshold` | ✅ |
| Visual similarity high for homograph pairs | `test_visual_similarity_high_for_homograph` | ✅ |
| Redis cache hit skips TI API fetch | `tests/unit/test_cache_manager.py` | ✅ |
| TI calls executed concurrently | `ThreatIntelService.fetch_all` + `tests/unit/test_threat_intel.py` | ✅ |
| `S_IDN_local ∈ [0.0, 1.0]` | `test_score_bounds` | ✅ |
| Agent stateless behavior | `test_agent_stateless_consecutive_calls` | ✅ |
| Security scan (`bandit -r agents/`) | `python -m bandit -r agents/ --severity-level medium` | ✅ |

---

## Thesis Documentation Note

> **For thesis chapter:** Phase 2 implements the 5-stage IDN detection algorithm from literature [36], [42], with TR#39-driven confusable detection and confusable-aware edit distance.
>
> **Implementation note (updated):** The runtime implementation no longer relies solely on the `unicodedata.name()` heuristic. It uses `confusables_loader.py` + `bktree.py` integrated into `IDNAgent`, with heuristic fallback only when catalog data is unavailable.
>
> **Complexity note:** Similarity stage remains bounded by first-1000 comparisons with early exit at `sim_v >= 0.95`; practical latency remains suitable for online scoring.
