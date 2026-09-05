# ---------------------------------------------------------------------------
# Threat Intelligence aggregation weights  (must sum to 1.0)
# ---------------------------------------------------------------------------
W_VT: float = 0.50
W_URLSCAN: float = 0.30
W_GSB: float = 0.20
W_WHOIS: float = 0.10       # additive WhoisXML modifier (domain age) — does not alter paper weights

# ---------------------------------------------------------------------------
# IDN scoring parameters
# ---------------------------------------------------------------------------
BETA: float = 0.40          # weight of homograph ratio in S_IDN_local
F_MIX: float = 1.6          # mixed-script multiplier
ALPHA: float = 0.60         # weight of S_IDN_local vs S_TI when computing S_IDN
GAMMA: float = 0.50         # weight of S_IDN vs S_LLM when computing S_risk (base)
GAMMA_IDN_BOOST: float = 0.25  # added to GAMMA when IDN dominance is triggered
GAMMA_IDN_MAX: float = 0.80    # cap for effective gamma under IDN dominance
# IDN dominance: activated when is_mixed_script=True AND s_idn_local >= threshold
# Rationale: LLM receives Punycode URLs and cannot decode homoglyphs — its score
# is structurally unreliable for IDN attacks. IDN Agent has domain-specific authority.
IDN_DOMINANCE_THRESHOLD: float = 0.50  # min s_idn_local to trigger dominance
THETA: float = 0.70         # risk threshold above which verdict = PHISHING
HOMOGRAPH_THRESHOLD: float = 0.30   # r_h alert threshold
SIM_V_EARLY_EXIT: float = 0.95      # early-exit visual-similarity cutoff in BKTree

# ---------------------------------------------------------------------------
# Email context signal weights (additive boost to s_risk)
# ---------------------------------------------------------------------------
EMAIL_MISMATCH_WEIGHT: float = 0.35   # sender domain ≠ return-path → strong spoofing indicator
EMAIL_URGENCY_WEIGHT: float = 0.30    # urgency_score coefficient (multiplied by urgency_score)
EMAIL_ATTACHMENT_WEIGHT: float = 0.25 # suspicious attachment
EMAIL_BOOST_CAP: float = 0.50         # max additive contribution from email signals to s_risk

# ---------------------------------------------------------------------------
# LLM Gateway (proveedor remoto OpenAI-compatible)
# ---------------------------------------------------------------------------
# 20 s: DeepSeek Flash remoto responde en ~1-3 s a este tamaño de prompt.
# El LLM es el único paso serializado del pipeline (services/analysis.py),
# así que este timeout define el peor caso de latencia de la request.
LLM_TIMEOUT_S: float = 20.0
LLM_FALLBACK_SCORE: float = 0.5

# ---------------------------------------------------------------------------
# HuggingFace Inference API
# ---------------------------------------------------------------------------
HF_WEIGHT: float = 0.40        # weight of HF classifier in blended s_llm
HF_TIMEOUT_S: float = 10.0
HF_FALLBACK_SCORE: float = 0.5

# ---------------------------------------------------------------------------
# ChromaDB collection names
# ---------------------------------------------------------------------------
COLLECTION_EMAIL: str = "email_embeddings"
COLLECTION_IDN: str = "idn_patterns"
COLLECTION_TI: str = "ti_signals"
COLLECTION_BASELINE: str = "usb_baseline"
COLLECTION_KNOWLEDGE: str = "security_knowledge"
RAG_TOP_K: int = 3

# ---------------------------------------------------------------------------
# RAG retrieval — ponderación por procedencia (T11, anti-envenenamiento)
# ---------------------------------------------------------------------------
# Los documentos auto-ingestados (sin confirmación humana) pesan menos en el
# re-ranking del retrieval: un FP auto-ingestado no debe reforzar futuros FPs.
# Tiers de auto-ingesta (LEARN_FROM_EVERY_ANALYSIS): el peso baja con la
# incertidumbre del veredicto que originó el documento.
#   auto_high : s_risk >= AUTO_INGEST_THRESHOLD  (0.90) — casi seguro phishing
#   auto_mid  : SUSPICIOUS band                          — señal parcial
#   auto_low  : LEGITIMATE                                — aprende qué es benigno
SOURCE_WEIGHTS: dict[str, float] = {
    "admin_confirmed": 1.0,
    "institutional_baseline": 0.9,
    "official_reference": 0.9,
    "seed_corpus": 0.8,
    "auto_ingest": 0.6,   # legacy — equivale a auto_high
    "auto_high": 0.6,
    "auto_mid": 0.4,
    "auto_low": 0.3,
    "quarantine": 0.0,    # candidato a envenenamiento — no influye en el RAG
}
SOURCE_WEIGHT_DEFAULT: float = 0.8   # documentos sin metadato source (legacy)
RAG_CANDIDATE_FACTOR: int = 2        # candidatos pedidos = RAG_TOP_K * factor

# Recuperación híbrida (denso + BM25 léxico + Reciprocal Rank Fusion).
# El canal léxico rescata dominios homógrafos (`xn--pypal-4ve`) y tokens de
# marca (`paypal`, `1xbet`, `usbbog`) que el vector denso difumina.
RAG_RRF_K: int = 60                  # constante estándar de RRF: 1/(k + rank)
RAG_BM25_INDEX_TTL_S: float = 300.0  # refresco del índice BM25 (se invalida en upsert)

# ---------------------------------------------------------------------------
# Web Probe Agent
# ---------------------------------------------------------------------------
# Gate anti-FP (T3, docs/tasks.md): el boost del probe solo aplica cuando ya
# existe sospecha pasiva (s_base + s_email >= gate). Una página legítima de
# login tiene password field — sin este gate, PROBE_LOGIN_WEIGHT dispara FPs.
# Debe ser > 0.25: con LLM neutral (0.5) y resto en 0, la base es exactamente
# (1-γ)·0.5 = 0.25 — el estado "no sé nada" no cuenta como sospecha.
PROBE_GATE_THRESHOLD: float = 0.30
# Dominios confiables por sufijo: el boost del probe se anula para ellos.
# El top-1M (Tranco/Majestic) se chequea aparte vía IDNAgent.is_trusted_domain.
TRUSTED_DOMAIN_SUFFIXES: frozenset[str] = frozenset(
    {
        "usbbog.edu.co",
        "usb.edu.co",
        "microsoftonline.com",
        "google.com",
        "outlook.com",
        "office.com",
    }
)
PROBE_TIMEOUT_S: float = 8.0
PROBE_MAX_RESPONSE_BYTES: int = 65_536     # 64 KB — enough to find login forms
PROBE_MAX_REDIRECTS: int = 5
PROBE_LOGIN_WEIGHT: float = 0.45           # login form with password field
PROBE_REDIRECT_WEIGHT: float = 0.25        # domain changed on redirect
PROBE_BRAND_WEIGHT: float = 0.35           # brand impersonation in page content
PROBE_FORM_ACTION_WEIGHT: float = 0.20     # form action points to external domain
PROBE_BOOST_CAP: float = 0.60              # max additive contribution from probe to s_risk

# ---------------------------------------------------------------------------
# Redis key prefixes
# ---------------------------------------------------------------------------
TI_CACHE_PREFIX: str = "ti:"
IDN_CACHE_PREFIX: str = "idn:"
