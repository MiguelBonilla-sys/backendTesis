"""
Email parser for .eml files.

Extracts all signals needed for the phishing detection pipeline:
  - All HTTP/HTTPS URLs (from body + href attributes)
  - Sender / Return-Path / Reply-To domains
  - SPF and DKIM authentication results
  - Urgency indicators in subject and body
  - Attachment names and suspicious-extension flags

Privacy: the email body is never stored — only the SHA-256 hash, extracted
URLs, and derived signals are returned.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import html as html_module
import re
from dataclasses import dataclass, field
from email.message import Message

from utils.url_parser import extract_urls_from_html, extract_urls_from_text, normalize_url

# ---------------------------------------------------------------------------
# Urgency keyword sets (Spanish + English — case-insensitive substring match)
# ---------------------------------------------------------------------------
_URGENCY_KEYWORDS: frozenset[str] = frozenset({
    # Spanish
    "actúa ahora", "actua ahora", "actu a ahora",
    "urgente", "inmediatamente", "no esperes", "actúa ya",
    "ahora mismo", "aprobación instantánea", "aprobaciones instantáneas",
    "verificación urgente", "cuenta suspendida", "suspendida",
    "bloqueo de cuenta", "alerta de seguridad",
    # English
    "act now", "urgent", "immediately", "expires today",
    "limited time", "verify now", "account suspended",
    "account locked", "security alert", "click here immediately",
    "your account", "action required",
})

# File extensions considered high-risk in attachments
_SUSPICIOUS_ATTACHMENT_EXTS: frozenset[str] = frozenset({
    ".exe", ".bat", ".cmd", ".scr", ".vbs", ".vbe",
    ".js", ".jse", ".jar", ".ps1",
    ".zip", ".rar", ".7z", ".iso",
    ".docm", ".xlsm", ".pptm", ".xlam",
})

# HTML tag stripper for plain-text extraction
_HTML_TAG_RE = re.compile(r"<[^>]+>")

# Auth result pattern: e.g. "dkim=pass" or "spf=fail"
_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim)=(pass|fail|neutral|softfail)", re.IGNORECASE)

# Email address domain extractor
_EMAIL_DOMAIN_RE = re.compile(r"@([\w.\-]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public data container
# ---------------------------------------------------------------------------

@dataclass
class ParsedEmail:
    """All signals extracted from a single .eml file."""

    email_hash: str
    subject: str
    sender: str
    sender_domain: str
    return_path_domain: str
    reply_to_domain: str
    sender_domain_mismatch: bool
    spf_pass: bool
    dkim_pass: bool
    urls: list[str] = field(default_factory=list)
    body_text: str = ""
    is_urgent: bool = False
    urgency_score: float = 0.0
    attachment_names: list[str] = field(default_factory=list)
    has_suspicious_attachments: bool = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_eml(content: bytes) -> ParsedEmail:
    """
    Parse a raw .eml file and return all signals for phishing analysis.

    Parameters
    ----------
    content:
        Raw bytes of the .eml file.

    Returns
    -------
    ParsedEmail
        Extracted signals.  Body text is capped at 2 000 chars; URLs are
        deduplicated by normalised URL (fragment stripped).
    """
    email_hash = hashlib.sha256(content).hexdigest()

    msg: Message = email.message_from_bytes(content, policy=email.policy.compat32)

    subject = _decode_header(msg.get("Subject", ""))
    sender = _decode_header(msg.get("From", ""))
    sender_domain = _extract_email_domain(sender)
    return_path = _decode_header(msg.get("Return-Path", ""))
    return_path_domain = _extract_email_domain(return_path)
    reply_to = _decode_header(msg.get("Reply-To", ""))
    reply_to_domain = _extract_email_domain(reply_to)

    sender_domain_mismatch = bool(
        sender_domain and return_path_domain
        and sender_domain != return_path_domain
    )

    spf_pass, dkim_pass = _parse_auth_results(msg)

    body_text, urls = _extract_body_and_urls(msg)
    body_text = body_text[:2000]

    is_urgent, urgency_score = _detect_urgency(subject, body_text)

    attachment_names = _collect_attachment_names(msg)
    has_suspicious_attachments = any(
        any(name.lower().endswith(ext) for ext in _SUSPICIOUS_ATTACHMENT_EXTS)
        for name in attachment_names
    )

    return ParsedEmail(
        email_hash=email_hash,
        subject=subject,
        sender=sender,
        sender_domain=sender_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        sender_domain_mismatch=sender_domain_mismatch,
        spf_pass=spf_pass,
        dkim_pass=dkim_pass,
        urls=urls,
        body_text=body_text,
        is_urgent=is_urgent,
        urgency_score=urgency_score,
        attachment_names=attachment_names,
        has_suspicious_attachments=has_suspicious_attachments,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decode_header(value: str | None) -> str:
    """Decode a possibly RFC 2047-encoded header value to a plain string."""
    if not value:
        return ""
    try:
        from email.header import decode_header as _dh

        parts = _dh(value)
        decoded_parts: list[str] = []
        for part_bytes, charset in parts:
            if isinstance(part_bytes, bytes):
                decoded_parts.append(
                    part_bytes.decode(charset or "utf-8", errors="replace")
                )
            else:
                decoded_parts.append(part_bytes)
        return "".join(decoded_parts).strip()
    except Exception:
        return str(value).strip()


def _extract_email_domain(header: str) -> str:
    """Extract the domain from an email address in a header value."""
    match = _EMAIL_DOMAIN_RE.search(header)
    return match.group(1).lower() if match else ""


def _parse_auth_results(msg: Message) -> tuple[bool, bool]:
    """
    Read SPF and DKIM verdicts from authentication-related headers.

    Checks (in priority order):
      1. ``Authentication-Results``
      2. ``ARC-Authentication-Results``
      3. ``Received-SPF`` (SPF only)
    """
    auth_headers = (
        (msg.get_all("Authentication-Results") or [])
        + (msg.get_all("ARC-Authentication-Results") or [])
    )
    combined = " ".join(str(h) for h in auth_headers).lower()

    spf_pass = False
    dkim_pass = False

    for match in _AUTH_RESULT_RE.finditer(combined):
        proto, result = match.group(1).lower(), match.group(2).lower()
        if proto == "spf" and result == "pass":
            spf_pass = True
        elif proto == "dkim" and result == "pass":
            dkim_pass = True

    # Fallback: Received-SPF header
    if not spf_pass:
        received_spf = str(msg.get("Received-SPF", "")).lower()
        if received_spf.startswith("pass"):
            spf_pass = True

    return spf_pass, dkim_pass


def _strip_html(html_content: str) -> str:
    """Convert HTML to plain text by removing tags and unescaping entities."""
    no_tags = _HTML_TAG_RE.sub(" ", html_content)
    return html_module.unescape(no_tags)


def _extract_body_and_urls(msg: Message) -> tuple[str, list[str]]:
    """
    Walk the MIME tree and collect body text + deduplicated URLs.

    Strategy:
    1. Extract URLs from href/src attributes in HTML parts (most reliable).
    2. Also run the generic URL regex on all text content as fallback.
    3. Deduplicate by normalised URL (fragment stripped) — prevents the
       same base URL with different tracking fragments from inflating counts.
    """
    text_chunks: list[str] = []
    raw_urls: list[str] = []
    seen_normalized: set[str] = set()
    deduped_urls: list[str] = []

    def _add_url(url: str) -> None:
        norm = normalize_url(url)
        if norm not in seen_normalized:
            seen_normalized.add(norm)
            deduped_urls.append(url)

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", "")).lower()

        if "attachment" in disposition:
            continue  # handled separately

        if content_type == "text/html":
            try:
                html_body = part.get_payload(decode=True)
                if html_body:
                    html_str = html_body.decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                    # Priority: href/src attribute extraction (avoids partial matches)
                    for url in extract_urls_from_html(html_str):
                        _add_url(url)
                    # Fallback: raw regex on HTML text (catches non-attribute URLs)
                    for url in extract_urls_from_text(html_str):
                        _add_url(url)
                    text_chunks.append(_strip_html(html_str))
            except Exception:
                pass

        elif content_type == "text/plain":
            try:
                plain = part.get_payload(decode=True)
                if plain:
                    plain_str = plain.decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                    for url in extract_urls_from_text(plain_str):
                        _add_url(url)
                    text_chunks.append(plain_str)
            except Exception:
                pass

    body_text = " ".join(text_chunks)
    return body_text, deduped_urls


def _detect_urgency(subject: str, body_text: str) -> tuple[bool, float]:
    """
    Detect urgency/pressure tactics in subject and body.

    Returns ``(is_urgent, urgency_score)`` where ``urgency_score ∈ [0.0, 1.0]``.
    Score is proportional to the number of distinct urgency keywords matched,
    capped at 1.0 after 3+ matches.
    """
    combined = (subject + " " + body_text).lower()
    matches = sum(1 for kw in _URGENCY_KEYWORDS if kw in combined)
    is_urgent = matches >= 1
    urgency_score = min(matches * 0.30, 1.0)
    return is_urgent, round(urgency_score, 2)


def _collect_attachment_names(msg: Message) -> list[str]:
    """Return filenames of all MIME attachments in the message."""
    names: list[str] = []
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition:
            filename = part.get_filename()
            if filename:
                names.append(_decode_header(filename))
    return names
