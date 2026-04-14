"""Prompt builder with tiktoken token budgeting — Phase 3 (Sprint S2).

Constructs the phishing detection prompt for LlamaStack (Llama 3.1 8B Instruct)
and enforces a hard token budget to avoid context overflow.

Pipeline position: IDN Agent → [LLM Agent uses PromptBuilder] → Fusion Agent

────────────────────────────────────────────────────────────────────────────────
DESIGN DECISIONS — DO NOT CHANGE without updating backendTesis/CLAUDE.md
────────────────────────────────────────────────────────────────────────────────
1. MAX_PROMPT_TOKENS = 4096.
   - Keeps latency under the p95 < 3s target.
   - Llama 3.1 8B context window is 131072 tokens, but longer prompts → slower
     inference; 4096 is the operational budget for prompt + completion combined.

2. Tiktoken encoding: "cl100k_base" (GPT-4 BPE).
   - Used as approximation for Llama 3.1 8B's BPE tokenizer (different vocabulary
     but similar token counts for English/Unicode text ±5%).
   - DO NOT switch to a different encoding without recalibrating the budget.

3. Response format: "SCORE: <float> | REASON: <text>"
   - This EXACT string appears in the prompt as the expected output format.
   - LLMAgent._parse_score() uses re.search(r"SCORE:\\s*([\d.]+)", text) to extract.
   - DO NOT change the format without updating LLMAgent._parse_score().

4. Body truncation: hard cap at 500 chars BEFORE token counting.
   - Prevents prompt bloat from very long email bodies.
   - Applied unconditionally regardless of token budget.

5. RAG context truncation: progressive, removes items from the END (index -1 first).
   - Items at index 0 = highest cosine similarity → kept last.
   - Loop iterates from len(rag_context) down to 0 (inclusive).
   - Edge case: even 0 RAG items exceeds budget → returns the minimal prompt as-is.

6. Return type: tuple[str, int] — (prompt_str, token_count).
   - token_count is computed from the RETURNED prompt (always matches).
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import tiktoken

from core.logger import get_logger

# ── Token budget ───────────────────────────────────────────────────────────────
# 4096 tokens leaves headroom for LlamaStack system overhead + 512-token completion.
# See LLAMASTACK_MAX_TOKENS in core/constants.py for the completion token cap.
MAX_PROMPT_TOKENS: int = 4096

# Tiktoken BPE encoding — cl100k_base matches GPT-4 tokenizer.
# Used as approximation for Llama 3.1 8B (vocabulary differs; counts are ~±5%).
_TIKTOKEN_ENCODING: str = "cl100k_base"

logger = get_logger("prompt_builder")


def count_tokens(text: str, encoding: str = _TIKTOKEN_ENCODING) -> int:
    """Count BPE tokens in text using tiktoken.

    Args:
        text: Input string. May be empty.
        encoding: tiktoken encoding name. Default: "cl100k_base".

    Returns:
        int: Token count. 0 for empty string.

    Note:
        Each call creates a new tiktoken.Encoding instance (cached internally by
        tiktoken via functools.cache — not expensive after the first call).
    """
    if not text:
        return 0
    enc = tiktoken.get_encoding(encoding)
    return len(enc.encode(text))


def build_prompt(
    domain: str,
    email_body: str | None,
    s_idn: float,
    rag_context: list[str],
    max_tokens: int = MAX_PROMPT_TOKENS,
) -> tuple[str, int]:
    """Build the phishing detection prompt with progressive RAG context truncation.

    Constructs the prompt that LLMAgent._call_llamastack() sends to LlamaStack.
    Ensures the prompt fits within max_tokens by progressively removing RAG context
    items from the end (lowest similarity first) until the budget is met.

    Prompt structure:
    ┌─────────────────────────────────────────────────────────┐
    │ You are a phishing detection expert.                    │
    │ Similar past phishing emails:                           │
    │ - <rag_context[0]>                                      │
    │ - <rag_context[1]>                                      │
    │ - <rag_context[2]>                                      │
    │                                                         │
    │ Domain: <domain>                                        │
    │ IDN homograph score: <s_idn:.2f> (0=safe, 1=phishing)  │
    │ Email body snippet: <email_body[:500] or Not provided.> │
    │                                                         │
    │ Output a phishing risk score 0.0–1.0 and brief reasoning│
    │ Format: SCORE: <float> | REASON: <text>                 │
    └─────────────────────────────────────────────────────────┘

    IMPORTANT — "Format: SCORE: <float> | REASON: <text>" is parsed by
    LLMAgent._parse_score() via re.search(r"SCORE:\\s*([\\d.]+)", text).
    This line MUST appear verbatim in the returned prompt.

    Args:
        domain: The 2LD domain under analysis (e.g., "pаypal.com" with Cyrillic а).
        email_body: Raw email body text. Truncated to 500 chars. None is handled.
        s_idn: IDN local score from IDNAgent.analyze() — float in [0.0, 1.0].
        rag_context: List of similar past phishing email snippets from ChromaDB.
                     Ordered by descending cosine similarity (index 0 = most similar).
        max_tokens: Hard token budget for the prompt. Default: MAX_PROMPT_TOKENS (4096).

    Returns:
        tuple[str, int]: (prompt_string, token_count).
            - prompt_string: The complete prompt, fits within max_tokens.
            - token_count: Actual token count of prompt_string (always ≤ max_tokens,
                           except the documented edge case below).

    Edge cases:
        - rag_context=[] → ctx_str="None." → prompt always within budget.
        - email_body=None or "" → body="Not provided."
        - Very long domain (>500 chars): not truncated (unrealistic for 2LD domains).
        - If even the empty-context prompt exceeds max_tokens (pathological case),
          returns the minimal prompt without raising, and logs a warning.
    """
    # Step 1: Truncate email body to 500 chars unconditionally.
    # "Not provided." is the canonical fallback for None/empty body.
    body: str = (email_body or "")[:500] or "Not provided."

    # Step 2: Try full RAG context first, then progressively remove items from end.
    # rag_context[0] = most similar → kept last (removed only when necessary).
    for ctx_len in range(len(rag_context), -1, -1):
        trimmed: list[str] = rag_context[:ctx_len]
        ctx_str: str = "\n".join(f"- {c}" for c in trimmed) if trimmed else "None."

        # Build the prompt with the current context length.
        # WARNING: The "Format: SCORE: <float> | REASON: <text>" line is parsed by
        # LLMAgent._parse_score(). Do NOT modify this string without updating that method.
        prompt = (
            "You are a phishing detection expert.\n"
            f"Similar past phishing emails:\n{ctx_str}\n\n"
            f"Domain: {domain}\n"
            f"IDN homograph score: {s_idn:.2f} (0=safe, 1=phishing)\n"
            f"Email body snippet: {body}\n\n"
            "Output a phishing risk score 0.0–1.0 and brief reasoning.\n"
            "Respond in ONE line only.\n"
            "Format: SCORE: <float> | REASON: <text>"
        )

        token_count: int = count_tokens(prompt)

        if token_count <= max_tokens:
            if ctx_len < len(rag_context):
                logger.debug(
                    f"RAG context truncated from {len(rag_context)} → {ctx_len} items "
                    f"for domain={domain!r} (tokens: {token_count}/{max_tokens})"
                )
            return prompt, token_count

    # Edge case: even ctx_len=0 (no RAG context) still exceeds budget.
    # This should never happen for realistic inputs (pathological domain or body).
    logger.warning(
        f"Prompt for domain={domain!r} exceeds token budget "
        f"({token_count} > {max_tokens}) even with empty RAG context. "
        f"Returning as-is."
    )
    return prompt, token_count
