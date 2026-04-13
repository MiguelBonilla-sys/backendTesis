# ── Fusion weights ────────────────────────────────────────────────────────────
# S_IDN_local = β*r_h + (1-β)*sim_v
BETA: float = 0.40

# S_IDN = α*S_IDN_local + (1-α)*S_TI
ALPHA: float = 0.60

# S_risk = γ*S_IDN + (1-γ)*S_LLM
GAMMA: float = 0.50

# ── TI aggregation weights ────────────────────────────────────────────────────
# S_TI = 0.50*VT + 0.30*URLScan + 0.20*GSB
TI_VIRUSTOTAL_WEIGHT: float = 0.50
TI_URLSCAN_WEIGHT: float = 0.30
TI_GSB_WEIGHT: float = 0.20

# ── Decision thresholds ───────────────────────────────────────────────────────
THETA: float = 0.70          # S_risk >= θ → PHISHING
SUSPICIOUS_THRESHOLD: float = 0.50  # S_risk >= 0.50 → SUSPICIOUS

# ── IDN detection ─────────────────────────────────────────────────────────────
IDN_HOMOGRAPH_RATIO_ALERT: float = 0.30   # r_h >= 0.30 → alert

# ── LLM / RAG ─────────────────────────────────────────────────────────────────
RAG_TOP_K: int = 3
LLAMASTACK_TIMEOUT_SECONDS: float = 120.0
LLAMASTACK_MAX_TOKENS: int = 512

# ── ChromaDB collections ──────────────────────────────────────────────────────
COLLECTION_EMAIL_EMBEDDINGS: str = "email_embeddings"   # all-MiniLM-L6-v2 (384d)
COLLECTION_IDN_PATTERNS: str = "idn_patterns"           # all-MiniLM-L6-v2 (384d)
COLLECTION_TI_SIGNALS: str = "ti_signals"               # all-MiniLM-L6-v2 (384d)

# ── Verdicts ──────────────────────────────────────────────────────────────────
VERDICT_PHISHING: str = "PHISHING"
VERDICT_SUSPICIOUS: str = "SUSPICIOUS"
VERDICT_SAFE: str = "SAFE"
