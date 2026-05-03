"""
baseline_monolithic.py — Monolithic URL-only phishing classifier (Sprint 6 baseline).

Stateless LogisticRegression over char TF-IDF + hand-crafted URL features.
Used as comparison baseline against the 3-agent system in Sprint 6 validation.
No TI APIs, no LLM, no IDN agent pipeline.
"""

from __future__ import annotations

import math
import pickle
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


_SUSPICIOUS_KEYWORDS = frozenset([
    "login", "verify", "account", "confirm", "update", "secure",
    "bank", "paypal", "amazon", "google", "microsoft", "apple",
    "signin", "password", "credential", "auth", "wallet",
])
_KNOWN_TLDS = frozenset(["com", "org", "net", "edu", "gov", "io", "co", "uk"])


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_url_features(url: str) -> list[float]:
    """Extract 12 hand-crafted URL features as a normalized numeric vector."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")
        path = parsed.path.lower()
        query = parsed.query
    except Exception:
        return [0.0] * 12

    sld = domain.split(".")[0] if "." in domain else domain
    tld = domain.split(".")[-1] if "." in domain else ""

    return [
        min(len(url) / 200.0, 1.0),
        min(len(domain) / 50.0, 1.0),
        min(domain.count(".") / 5.0, 1.0),
        min(sum(1 for c in domain if c in "-_@%~") / 10.0, 1.0),
        1.0 if "xn--" in domain else 0.0,
        1.0 if any(c.isdigit() for c in sld) else 0.0,
        min((len(path.split("/")) - 1) / 10.0, 1.0),
        min(len(query) / 100.0, 1.0) if query else 0.0,
        1.0 if "@" in url else 0.0,
        min(_shannon_entropy(domain) / 5.0, 1.0),
        1.0 if any(kw in path for kw in _SUSPICIOUS_KEYWORDS) else 0.0,
        1.0 if tld in _KNOWN_TLDS else 0.0,
    ]


class BaselineClassifier:
    """Monolithic LogisticRegression baseline over URL features only."""

    def __init__(self, model_path: str | None = None) -> None:
        self._tfidf = None
        self._clf = None
        self._fitted = False
        if model_path is not None:
            self.load(model_path)

    def fit(self, urls: list[str], labels: list[int]) -> None:
        import numpy as np
        import scipy.sparse as sp
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        self._tfidf = TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 4),
            max_features=5000,
            sublinear_tf=True,
        )
        tfidf_X = self._tfidf.fit_transform(urls)
        hcf = np.array([extract_url_features(u) for u in urls], dtype=np.float32)
        X = sp.hstack([tfidf_X, sp.csr_matrix(hcf)])

        self._clf = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            C=1.0,
            solver="lbfgs",
        )
        self._clf.fit(X, labels)
        self._fitted = True

    def predict_proba(self, url: str) -> float:
        """Return P(phishing) in [0.0, 1.0]."""
        if not self._fitted or self._tfidf is None or self._clf is None:
            raise RuntimeError("Model not fitted. Call fit() or load() first.")
        import numpy as np
        import scipy.sparse as sp

        tfidf_X = self._tfidf.transform([url])
        hcf = np.array([extract_url_features(url)], dtype=np.float32)
        X = sp.hstack([tfidf_X, sp.csr_matrix(hcf)])
        return float(self._clf.predict_proba(X)[0][1])

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"tfidf": self._tfidf, "clf": self._clf}, f)

    def load(self, path: str) -> None:
        with open(path, "rb") as f:
            data = pickle.load(f)  # noqa: S301
        self._tfidf = data["tfidf"]
        self._clf = data["clf"]
        self._fitted = True
