"""Shared eligibility rules for retrieved evidence; source is not a verdict."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.config import settings
from core.constants import SOURCE_WEIGHT_DEFAULT, SOURCE_WEIGHTS


def eligible_document(document: dict) -> bool:
    """Exclude empty, quarantined and expired evidence before ranking."""
    if not isinstance(document, dict) or not str(document.get("document") or "").strip():
        return False
    metadata = document.get("metadata") or {}
    if SOURCE_WEIGHTS.get(metadata.get("source"), SOURCE_WEIGHT_DEFAULT) <= 0:
        return False
    if metadata.get("status") in {"quarantine", "rejected", "expired", "deleted"}:
        return False
    expires_at = metadata.get("expires_at")
    if not expires_at and metadata.get("source") in {"auto_ingest", "auto_high", "auto_mid", "auto_low"}:
        try:
            ingested = datetime.fromisoformat(str(metadata.get("ingested_at", "")).replace("Z", "+00:00"))
            if ingested.tzinfo is None:
                ingested = ingested.replace(tzinfo=UTC)
            expires_at = (ingested + timedelta(days=settings.AUTO_INGEST_RETENTION_DAYS)).isoformat()
        except ValueError:
            return False
    if expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            return expiry > datetime.now(UTC)
        except ValueError:
            return False  # expiry declared but invalid: do not trust indefinitely
    return True
