"""Tests for agents/prompt_builder.py — Phase 3 (Sprint S2).

Unit tests for the prompt builder and tiktoken token counter.
No mocks needed — prompt_builder is pure Python (no I/O, no DB).

Coverage targets:
  - count_tokens: empty string, positive output, longer text → more tokens
  - build_prompt structure: required fields present (domain, score, format line)
  - build_prompt body handling: None, empty, long (truncation at 500 chars)
  - build_prompt RAG context: with content, empty → "None."
  - build_prompt token budget: typical input < 4096, custom max_tokens respected
  - build_prompt progressive truncation: large RAG context gets trimmed to fit budget
  - build_prompt return type: tuple[str, int]
  - build_prompt token_count matches actual prompt tokens

────────────────────────────────────────────────────────────────────────────────
IMPORTANT — DO NOT CHANGE these assertions without a design review:
  - "SCORE:" and "REASON:" must appear in every prompt (LLMAgent._parse_score dependency)
  - "Not provided." must be the fallback for None/empty email body
  - Token count returned must always equal count_tokens(prompt)
────────────────────────────────────────────────────────────────────────────────
"""

import pytest

from agents.prompt_builder import MAX_PROMPT_TOKENS, build_prompt, count_tokens


# ── count_tokens ───────────────────────────────────────────────────────────────

def test_count_tokens_empty_string_returns_zero() -> None:
    assert count_tokens("") == 0


def test_count_tokens_returns_positive_int_for_non_empty() -> None:
    result = count_tokens("Hello, world!")
    assert isinstance(result, int)
    assert result > 0


def test_count_tokens_longer_text_produces_more_tokens() -> None:
    short = count_tokens("phishing")
    long = count_tokens("phishing " * 100)
    assert long > short


def test_count_tokens_consistent_on_same_input() -> None:
    """Token counting must be deterministic."""
    text = "paypal.com account suspended verify now"
    assert count_tokens(text) == count_tokens(text)


def test_count_tokens_unicode_domain() -> None:
    """Cyrillic/Greek characters in domain name must be tokenized without error."""
    result = count_tokens("pаypal.com")  # 'а' is Cyrillic U+0430
    assert isinstance(result, int)
    assert result > 0


# ── build_prompt — return type ────────────────────────────────────────────────

def test_build_prompt_returns_tuple() -> None:
    result = build_prompt("evil.com", None, 0.5, [])
    assert isinstance(result, tuple)
    assert len(result) == 2


def test_build_prompt_first_element_is_non_empty_string() -> None:
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    assert isinstance(prompt, str)
    assert len(prompt) > 0


def test_build_prompt_second_element_is_positive_int() -> None:
    _, token_count = build_prompt("evil.com", None, 0.5, [])
    assert isinstance(token_count, int)
    assert token_count > 0


# ── build_prompt — required prompt content ────────────────────────────────────

def test_build_prompt_contains_domain() -> None:
    """Domain must appear in the prompt for LLM context."""
    prompt, _ = build_prompt("pаypal.com", None, 0.0, [])
    assert "pаypal.com" in prompt


def test_build_prompt_contains_idn_score_formatted_to_two_decimal_places() -> None:
    """IDN score must be formatted as 0.87 (2 decimal places) per :.2f format spec."""
    prompt, _ = build_prompt("evil.com", "body", 0.87, [])
    assert "0.87" in prompt


def test_build_prompt_contains_score_format_line() -> None:
    """SCORE: must appear in the prompt — LLMAgent._parse_score() depends on this.
    DO NOT remove this assertion or change the format string in prompt_builder.py."""
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    assert "SCORE:" in prompt


def test_build_prompt_contains_reason_format_line() -> None:
    """REASON: must appear after SCORE: — required by the output format spec."""
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    assert "REASON:" in prompt


def test_build_prompt_score_and_reason_on_same_format_line() -> None:
    """'SCORE: <float> | REASON: <text>' must appear on the same line."""
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    # Find the format instruction line
    format_line = next(
        (line for line in prompt.splitlines() if "SCORE:" in line),
        None,
    )
    assert format_line is not None, "No line containing 'SCORE:' found in prompt"
    assert "REASON:" in format_line, "'REASON:' must be on the same line as 'SCORE:'"


def test_build_prompt_contains_phishing_detection_instruction() -> None:
    """Prompt must identify the task clearly for the LLM."""
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    assert "phishing" in prompt.lower()


# ── build_prompt — email body handling ───────────────────────────────────────

def test_build_prompt_none_body_shows_not_provided() -> None:
    """None email_body → 'Not provided.' must appear in prompt."""
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    assert "Not provided." in prompt


def test_build_prompt_empty_string_body_shows_not_provided() -> None:
    """Empty string email_body → 'Not provided.' must appear in prompt."""
    prompt, _ = build_prompt("evil.com", "", 0.5, [])
    assert "Not provided." in prompt


def test_build_prompt_normal_body_appears_in_prompt() -> None:
    """Non-empty email body must appear verbatim in the prompt."""
    body = "Urgent: your account has been suspended."
    prompt, _ = build_prompt("evil.com", body, 0.5, [])
    assert body in prompt


def test_build_prompt_body_truncated_at_500_chars() -> None:
    """Email body longer than 500 chars must be truncated to exactly 500 chars."""
    long_body = "x" * 1000
    prompt, _ = build_prompt("evil.com", long_body, 0.5, [])
    assert "x" * 500 in prompt
    assert "x" * 501 not in prompt


def test_build_prompt_body_exactly_500_chars_not_truncated() -> None:
    """Email body of exactly 500 chars must appear in full."""
    exact_body = "y" * 500
    prompt, _ = build_prompt("evil.com", exact_body, 0.5, [])
    assert exact_body in prompt


def test_build_prompt_body_under_500_chars_not_truncated() -> None:
    """Email body shorter than 500 chars must appear verbatim."""
    short_body = "Click the link to verify: http://evil.com/reset"
    prompt, _ = build_prompt("evil.com", short_body, 0.5, [])
    assert short_body in prompt


# ── build_prompt — RAG context handling ──────────────────────────────────────

def test_build_prompt_empty_rag_context_shows_none() -> None:
    """rag_context=[] → 'None.' must appear as the context section value."""
    prompt, _ = build_prompt("evil.com", None, 0.5, [])
    assert "None." in prompt


def test_build_prompt_rag_context_items_appear_in_prompt() -> None:
    """Each RAG context snippet must appear in the prompt."""
    rag = ["past phishing: account suspended", "urgent verify credentials"]
    prompt, _ = build_prompt("evil.com", "body", 0.5, rag)
    assert "past phishing: account suspended" in prompt
    assert "urgent verify credentials" in prompt


def test_build_prompt_rag_items_prefixed_with_dash() -> None:
    """Each RAG context item must be formatted as '- <snippet>'."""
    rag = ["snippet A"]
    prompt, _ = build_prompt("evil.com", None, 0.5, rag)
    assert "- snippet A" in prompt


# ── build_prompt — token budget ───────────────────────────────────────────────

def test_build_prompt_typical_input_under_max_tokens() -> None:
    """A realistic phishing analysis request must fit within MAX_PROMPT_TOKENS (4096)."""
    domain = "pаypal.com"  # Cyrillic 'а' (U+0430)
    body = (
        "Your account has been suspended due to suspicious activity. "
        "Please verify your identity at http://pаypal.com/secure/verify "
        "within 24 hours to avoid permanent closure."
    )
    rag = [
        "Phishing: 'account suspended click verify' → paypal homograph",
        "Phishing: 'urgent action required' → bank login page",
        "Phishing: 'identity verification needed' → credential harvest",
    ]
    _, token_count = build_prompt(domain, body, 0.85, rag)
    assert token_count <= MAX_PROMPT_TOKENS


def test_build_prompt_no_rag_no_body_under_max_tokens() -> None:
    """Minimal input (no RAG, no body) must always be well under MAX_PROMPT_TOKENS."""
    _, token_count = build_prompt("example.com", None, 0.0, [])
    assert token_count <= MAX_PROMPT_TOKENS
    # Should be well under budget — baseline prompt is ~60 tokens
    assert token_count < 200


def test_build_prompt_token_count_matches_actual_count() -> None:
    """The returned token_count must equal count_tokens(returned_prompt)."""
    prompt, token_count = build_prompt(
        "suspicious.com",
        "Please verify your credentials immediately.",
        0.6,
        ["Context: similar phishing email detected"],
    )
    actual = count_tokens(prompt)
    assert token_count == actual, (
        f"Returned token_count={token_count} does not match "
        f"count_tokens(prompt)={actual}"
    )


def test_build_prompt_progressive_truncation_respects_custom_max_tokens() -> None:
    """Progressive truncation must produce a prompt ≤ custom max_tokens."""
    # 50 large RAG items would normally exceed 256 tokens
    large_rag = [f"very long phishing snippet number {i}: " + "x" * 80 for i in range(50)]
    _, token_count = build_prompt("evil.com", "body", 0.5, large_rag, max_tokens=256)
    assert token_count <= 256


def test_build_prompt_progressive_truncation_on_large_rag() -> None:
    """When large RAG context exceeds budget, items are removed from the end."""
    huge_rag = ["RAG item " + "x" * 200] * 30
    prompt, token_count = build_prompt(
        "evil.com", "body", 0.5, huge_rag, max_tokens=512
    )
    assert token_count <= 512
    # The full 30 items would clearly exceed 512 tokens — at least some must be removed
    full_prompt, full_count = build_prompt("evil.com", "body", 0.5, huge_rag)
    assert full_count > 512  # sanity check: full prompt IS over 512
    # Truncated prompt has fewer RAG items
    assert prompt.count("RAG item") < 30


def test_build_prompt_truncation_keeps_most_similar_items_first() -> None:
    """Progressive truncation removes items from the END (index -1 first).
    RAG context is ordered by descending cosine similarity, so index 0 is the
    most relevant and must be kept when truncation occurs."""
    rag = [
        "MOST_SIMILAR: urgent paypal verify",                    # index 0 — must survive
        "SECOND: account suspended",                             # index 1
        "THIRD: " + "x" * 300,                                  # index 2 — long, removed first
    ]
    prompt, token_count = build_prompt("evil.com", "body", 0.5, rag, max_tokens=200)
    assert token_count <= 200
    if token_count < count_tokens(build_prompt("evil.com", "body", 0.5, rag)[0]):
        # Truncation occurred — MOST_SIMILAR must still be in the prompt
        assert "MOST_SIMILAR" in prompt


def test_build_prompt_custom_max_tokens_parameter_is_respected() -> None:
    """The max_tokens parameter overrides MAX_PROMPT_TOKENS."""
    _, token_count_tight = build_prompt("evil.com", None, 0.5, [], max_tokens=100)
    _, token_count_default = build_prompt("evil.com", None, 0.5, [])
    # With max_tokens=100, the prompt may be smaller (if RAG gets trimmed)
    # At minimum, the return value must be ≤ 100
    assert token_count_tight <= 100


# ── build_prompt — idn score edge values ─────────────────────────────────────

def test_build_prompt_idn_score_zero() -> None:
    """s_idn=0.0 must format as '0.00'."""
    prompt, _ = build_prompt("safe.com", None, 0.0, [])
    assert "0.00" in prompt


def test_build_prompt_idn_score_one() -> None:
    """s_idn=1.0 must format as '1.00'."""
    prompt, _ = build_prompt("evil.com", None, 1.0, [])
    assert "1.00" in prompt


def test_build_prompt_idn_score_mid() -> None:
    """s_idn=0.5 must format as '0.50'."""
    prompt, _ = build_prompt("suspicious.com", None, 0.5, [])
    assert "0.50" in prompt
