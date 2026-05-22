# ---------------------------------------------------------------------------
# Threat Intelligence aggregation weights  (must sum to 1.0)
# ---------------------------------------------------------------------------
W_VT: float = 0.50
W_URLSCAN: float = 0.30
W_GSB: float = 0.20

# ---------------------------------------------------------------------------
# IDN scoring parameters
# ---------------------------------------------------------------------------
BETA: float = 0.40          # weight of homograph ratio in S_IDN_local
F_MIX: float = 1.6          # mixed-script multiplier
ALPHA: float = 0.60         # weight of S_IDN_local vs S_TI when computing S_IDN
GAMMA: float = 0.50         # weight of S_IDN vs S_LLM when computing S_risk
THETA: float = 0.70         # risk threshold above which verdict = PHISHING
LAMBDA: float = 0.30        # false-negative penalty weight in fusion loss
HOMOGRAPH_THRESHOLD: float = 0.30   # r_h alert threshold
SIM_V_EARLY_EXIT: float = 0.95      # early-exit visual-similarity cutoff in BKTree

# ---------------------------------------------------------------------------
# LLM / LlamaStack
# ---------------------------------------------------------------------------
LLM_TIMEOUT_S: float = 10.0
LLM_FALLBACK_SCORE: float = 0.5

# ---------------------------------------------------------------------------
# ChromaDB collection names
# ---------------------------------------------------------------------------
COLLECTION_EMAIL: str = "email_embeddings"
COLLECTION_IDN: str = "idn_patterns"
COLLECTION_TI: str = "ti_signals"
RAG_TOP_K: int = 3

# ---------------------------------------------------------------------------
# Redis key prefixes
# ---------------------------------------------------------------------------
TI_CACHE_PREFIX: str = "ti:"
IDN_CACHE_PREFIX: str = "idn:"
