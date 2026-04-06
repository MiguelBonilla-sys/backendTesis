# Phase 3 — LLM Agent + ChromaDB RAG

> **Status:** 🔴 TODO  
> **Sprint:** S2 · **Branch:** `feat/phase-3-llm-agent`  
> **Goal:** LlamaStack inference with ChromaDB RAG context injection, returns `S_LLM ∈ [0.0, 1.0]` + reasoning trace.

---

## Context

The LLM Agent uses Llama 3.1 8B Instruct (GGUF quantized, running locally via LlamaStack) to evaluate the semantic phishing probability of a URL. It enriches the prompt with relevant context retrieved from ChromaDB (RAG pattern). The agent is the second stage of the 3-agent pipeline: IDN Agent → **LLM Agent** → Fusion Agent.

**Key constraint:** LlamaStack runs locally at `http://llamastack:5001` — no external LLM API calls.

---

## Prerequisites

```bash
git checkout feat/phase-3-llm-agent

# LlamaStack must be running before testing
# Check: curl http://localhost:5001/v1/models
# Model name: Llama-3.1-8B-Instruct-GGUF (or as configured in LLAMASTACK_MODEL env)

uv pip install sentence-transformers chromadb tiktoken
uv pip freeze > requirements.txt
```

---

## Files to Create / Modify

```
backendTesis/
├── agents/
│   ├── rag_retriever.py           ← NEW: ChromaDB query helpers
│   ├── prompt_builder.py          ← NEW: prompt template + token counting
│   └── llm_agent.py               ← MODIFY: integrate RAG + real LlamaStack call
├── models/
│   └── chromadb_client.py         ← MODIFY: add get_similar_emails, get_idn_patterns
└── tests/
    └── unit/
        ├── test_llm_agent.py       ← NEW: mock LlamaStack + respx
        ├── test_rag_retriever.py   ← NEW: mock ChromaDB responses
        └── test_prompt_builder.py  ← NEW: token count, prompt structure
```

---

## Stage 3.1 — ChromaDB RAG Context Retrieval

**File:** `agents/rag_retriever.py`

```python
from sentence_transformers import SentenceTransformer
import chromadb

# Singleton embedding model — load once
_EMBED_MODEL: SentenceTransformer | None = None

def get_embed_model() -> SentenceTransformer:
    global _EMBED_MODEL
    if _EMBED_MODEL is None:
        _EMBED_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    return _EMBED_MODEL

async def get_similar_emails(
    url: str,
    chroma_client: chromadb.HttpClient,
    k: int = 3,
) -> list[dict]:
    """
    Query 'email_embeddings' collection for top-k similar phishing patterns.
    Returns list of {"content": str, "metadata": dict, "distance": float}.
    Returns [] if collection empty — never raises.
    
    Collection: email_embeddings (all-MiniLM-L6-v2, 384d)
    """
    model = get_embed_model()
    embedding = model.encode(url).tolist()
    
    collection = chroma_client.get_collection("email_embeddings")
    results = collection.query(
        query_embeddings=[embedding],
        n_results=k,
        include=["documents", "metadatas", "distances"],
    )
    # Transform to list of dicts
    ...

async def get_idn_pattern_context(
    domain: str,
    chroma_client: chromadb.HttpClient,
    k: int = 3,
) -> list[dict]:
    """
    Query 'idn_patterns' collection for similar known IDN phishing patterns.
    Collection: idn_patterns (all-MiniLM-L6-v2, 384d)
    """
    ...
```

**File:** `models/chromadb_client.py` — verify `ensure_collections()` creates all 3:

```python
COLLECTIONS = [
    {
        "name": "email_embeddings",
        "metadata": {"hnsw:space": "cosine"},
        "embedding_dim": 384,    # all-MiniLM-L6-v2
    },
    {
        "name": "idn_patterns",
        "metadata": {"hnsw:space": "cosine"},
        "embedding_dim": 384,    # all-MiniLM-L6-v2
    },
    {
        "name": "ti_signals",
        "metadata": {"hnsw:space": "cosine"},
        "embedding_dim": 1536,   # text-embedding-3-small
    },
]
```

---

## Stage 3.2 — Prompt Template

**File:** `agents/prompt_builder.py`

```python
import tiktoken

MAX_PROMPT_TOKENS = 4096  # Hard limit for Llama 3.1 8B context window

SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing URL detection, 
with expertise in IDN (Internationalized Domain Name) homograph attacks. 
Your task is to analyze URLs and return a phishing probability score.

You MUST respond with valid JSON only, in this exact format:
{"s_llm": <float between 0.0 and 1.0>, "reasoning": "<one sentence explanation>"}

Where s_llm = 1.0 means definitely phishing, 0.0 means definitely safe."""

def build_prompt(
    url: str,
    idn_summary: dict,
    email_context: list[dict],
    idn_patterns: list[dict],
) -> str:
    """
    Build LlamaStack-compatible prompt with RAG context.
    Truncates RAG context to stay under MAX_PROMPT_TOKENS.
    
    Args:
        url: The URL being analyzed
        idn_summary: dict with r_h, sim_v, confusables, homograph_alert, domain_unicode
        email_context: top-3 similar emails from ChromaDB
        idn_patterns: top-3 IDN patterns from ChromaDB
    
    Returns:
        Formatted prompt string ready for LlamaStack
    """
    enc = tiktoken.get_encoding("cl100k_base")
    
    # Build context section (truncate if needed)
    context_parts = []
    for item in email_context[:3]:
        context_parts.append(f"Similar phishing pattern: {item['content'][:200]}")
    
    idn_analysis = f"""
IDN Analysis Results:
- Domain: {idn_summary.get('domain_unicode', url)}
- Homograph alert: {idn_summary.get('homograph_alert', False)}
- Homograph ratio (r_h): {idn_summary.get('r_h', 0.0):.3f}
- Visual similarity to known domain: {idn_summary.get('sim_v', 0.0):.3f}
- Confusable characters found: {len(idn_summary.get('confusables', []))}
"""
    
    user_prompt = f"""
Analyze this URL for phishing:
URL: {url}

{idn_analysis}

Similar phishing patterns from database:
{chr(10).join(context_parts) if context_parts else "No similar patterns found."}

Respond with JSON only.
"""
    
    # Check token count, truncate if needed
    total = len(enc.encode(SYSTEM_PROMPT)) + len(enc.encode(user_prompt))
    if total > MAX_PROMPT_TOKENS:
        # Truncate context parts progressively
        ...
    
    return user_prompt

def count_tokens(text: str) -> int:
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))
```

---

## Stage 3.3 — LlamaStack Inference

**File:** `agents/llm_agent.py`

```python
import asyncio
import json
import re
import httpx
from agents.base_agent import BaseAgent
from agents.rag_retriever import get_similar_emails, get_idn_pattern_context
from agents.prompt_builder import build_prompt, SYSTEM_PROMPT
from core.config import settings
from core.constants import LLAMASTACK_TIMEOUT_SECONDS
from schemas.analyze_schemas import LLMAnalysisResult

class LLMAgent(BaseAgent):
    """Stateless LLM inference agent with ChromaDB RAG."""

    async def analyze(
        self,
        url: str,
        idn_result: dict,
        chroma_client,
    ) -> LLMAnalysisResult:
        """
        1. Retrieve RAG context from ChromaDB
        2. Build prompt with IDN analysis summary
        3. Call LlamaStack /v1/chat/completions
        4. Parse JSON response → s_llm
        5. Fallback: s_llm=0.5 on timeout or parse failure
        """
        # 1. RAG retrieval
        try:
            email_ctx = await get_similar_emails(url, chroma_client, k=3)
            idn_ctx = await get_idn_pattern_context(idn_result.get("domain_unicode", ""), chroma_client, k=3)
        except Exception:
            email_ctx, idn_ctx = [], []
        
        # 2. Build prompt
        prompt = build_prompt(url, idn_result, email_ctx, idn_ctx)
        
        # 3. LlamaStack call
        payload = {
            "model": settings.LLAMASTACK_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 200,
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await asyncio.wait_for(
                    client.post(
                        f"{settings.LLAMASTACK_URL}/v1/chat/completions",
                        json=payload,
                        timeout=LLAMASTACK_TIMEOUT_SECONDS,
                    ),
                    timeout=LLAMASTACK_TIMEOUT_SECONDS,
                )
            raw = response.json()["choices"][0]["message"]["content"]
            return parse_llm_response(raw)
        
        except asyncio.TimeoutError:
            return LLMAnalysisResult(s_llm=0.5, reasoning="LlamaStack timeout", llm_degraded=True, raw_response="")
        except Exception as exc:
            return LLMAnalysisResult(s_llm=0.5, reasoning=f"LLM error: {type(exc).__name__}", llm_degraded=True, raw_response="")
```

---

## Stage 3.4 — Response Parsing

**File:** `agents/llm_agent.py`

```python
def parse_llm_response(raw: str) -> LLMAnalysisResult:
    """
    Parse LlamaStack response. Tries JSON first, regex fallback.
    Validates s_llm ∈ [0.0, 1.0]. Returns neutral 0.5 on any failure.
    
    Expected format: {"s_llm": 0.87, "reasoning": "..."}
    """
    # Strategy 1: direct JSON parse
    try:
        data = json.loads(raw.strip())
        s_llm = float(data["s_llm"])
        s_llm = max(0.0, min(1.0, s_llm))
        return LLMAnalysisResult(
            s_llm=s_llm,
            reasoning=data.get("reasoning", ""),
            llm_degraded=False,
            raw_response=raw,
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        pass
    
    # Strategy 2: regex extraction
    match = re.search(r'"s_llm"\s*:\s*([0-9.]+)', raw)
    if match:
        try:
            s_llm = max(0.0, min(1.0, float(match.group(1))))
            return LLMAnalysisResult(s_llm=s_llm, reasoning="", llm_degraded=False, raw_response=raw)
        except ValueError:
            pass
    
    # Fallback
    return LLMAnalysisResult(s_llm=0.5, reasoning="Parse failure", llm_degraded=True, raw_response=raw)
```

---

## Schema Updates

**File:** `schemas/analyze_schemas.py` — ensure `LLMAnalysisResult` has:

```python
class LLMAnalysisResult(BaseModel):
    s_llm: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""
    llm_degraded: bool = False
    raw_response: str = ""
```

---

## Tests to Write

**File:** `tests/unit/test_llm_agent.py`

```python
import pytest
import respx
import httpx
from agents.llm_agent import LLMAgent, parse_llm_response

# --- parse_llm_response tests ---

def test_parse_valid_json() -> None:
    result = parse_llm_response('{"s_llm": 0.87, "reasoning": "Cyrillic chars detected"}')
    assert abs(result.s_llm - 0.87) < 1e-6
    assert not result.llm_degraded

def test_parse_json_clamps_above_1() -> None:
    result = parse_llm_response('{"s_llm": 1.5, "reasoning": "test"}')
    assert result.s_llm == 1.0

def test_parse_json_clamps_below_0() -> None:
    result = parse_llm_response('{"s_llm": -0.1, "reasoning": "test"}')
    assert result.s_llm == 0.0

def test_parse_regex_fallback() -> None:
    raw = 'Based on analysis, "s_llm": 0.75 is the score.'
    result = parse_llm_response(raw)
    assert abs(result.s_llm - 0.75) < 1e-6

def test_parse_complete_failure_returns_neutral() -> None:
    result = parse_llm_response("I cannot determine this.")
    assert result.s_llm == 0.5
    assert result.llm_degraded is True

# --- LLMAgent integration with mocked LlamaStack ---

@respx.mock
async def test_llm_agent_success() -> None:
    respx.post("http://llamastack:5001/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={
            "choices": [{"message": {"content": '{"s_llm": 0.92, "reasoning": "homograph detected"}'}}]
        })
    )
    agent = LLMAgent()
    result = await agent.analyze("https://pаypal.com", {"r_h": 0.5}, mock_chroma_client)
    assert result.s_llm > 0.5
    assert not result.llm_degraded

@respx.mock
async def test_llm_agent_timeout_fallback() -> None:
    respx.post("http://llamastack:5001/v1/chat/completions").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    agent = LLMAgent()
    result = await agent.analyze("https://pаypal.com", {"r_h": 0.5}, mock_chroma_client)
    assert result.s_llm == 0.5
    assert result.llm_degraded is True
```

**File:** `tests/unit/test_prompt_builder.py`

```python
from agents.prompt_builder import build_prompt, count_tokens, MAX_PROMPT_TOKENS

def test_prompt_under_token_limit() -> None:
    prompt = build_prompt("https://paypal.com", {}, [], [])
    assert count_tokens(prompt) < MAX_PROMPT_TOKENS

def test_prompt_includes_url() -> None:
    url = "https://test-phishing.com"
    prompt = build_prompt(url, {}, [], [])
    assert url in prompt

def test_prompt_includes_idn_summary() -> None:
    idn = {"r_h": 0.5, "sim_v": 0.95, "homograph_alert": True}
    prompt = build_prompt("https://test.com", idn, [], [])
    assert "0.500" in prompt or "0.5" in prompt
```

---

## LlamaStack API Reference

```bash
# Verify LlamaStack is running (from inside Docker network or locally)
curl http://localhost:5001/v1/models

# Test inference manually
curl -X POST http://localhost:5001/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Llama-3.1-8B-Instruct-GGUF",
    "messages": [
      {"role": "system", "content": "You are a phishing detector. Reply with JSON only: {\"s_llm\": 0.0}"},
      {"role": "user", "content": "Is paypal.com phishing?"}
    ],
    "temperature": 0.1
  }'
```

---

## Acceptance Criteria

| Criterion | Test |
|-----------|------|
| Valid JSON → `s_llm` parsed correctly | `test_parse_valid_json` |
| `s_llm` always clamped to `[0.0, 1.0]` | `test_parse_json_clamps_*` |
| Regex fallback works on partial JSON | `test_parse_regex_fallback` |
| Complete parse failure → `s_llm=0.5, degraded=True` | `test_parse_complete_failure_returns_neutral` |
| LlamaStack timeout → `s_llm=0.5, llm_degraded=True` | `test_llm_agent_timeout_fallback` |
| Prompt always < 4096 tokens | `test_prompt_under_token_limit` |
| ChromaDB empty collection → no crash | Empty mock returns `[]` |
| Agent is stateless | No `self.` state mutations |

---

## Thesis Documentation Note

> **For thesis chapter:** Phase 3 implements the RAG-augmented LLM inference stage. ChromaDB's cosine similarity search (HNSW index) retrieves the top-3 most similar phishing patterns to contextualize the LLM prompt, improving precision on semantically similar attacks. The `temperature=0.1` setting minimizes hallucination variance. The 5-second timeout with neutral fallback (`s_llm=0.5`) ensures graceful degradation when LlamaStack is unavailable, which is critical for a locally-hosted model.
