"""Message forensics from RFC 5322 headers (RFS-04).

Only an allowlist of headers is kept (no To/Cc/Bcc, no body). The delivery IP is
the first public address found walking the ``Received`` chain from the top: the
top hops are stamped by the receiving provider, so that address is the sender's
outbound server as the receiver observed it. Lower hops are written by earlier
servers and are only declarations; they are kept in the headers but not trusted.
Input is bounded (size, header count, line length) and parsed with linear-time
patterns.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.message import Message
from email.parser import HeaderParser
from email.utils import parsedate_to_datetime

MAX_RAW_HEADERS = 65_536
MAX_RECEIVED_HOPS = 30
MAX_VALUE_CHARS = 1_000

ALLOWED_HEADERS = (
    "Received", "From", "Return-Path", "Reply-To", "Message-ID", "Date",
    "Authentication-Results", "Received-SPF", "DKIM-Signature", "X-Originating-IP",
)
_ALLOWED_LOWER = {name.lower(): name for name in ALLOWED_HEADERS}
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{3,45})\]")
_PAREN_IP = re.compile(r"\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)")
_DKIM_TAG = re.compile(r"(?:^|;)\s*([ds])=([^;\s]{1,255})")


@dataclass(frozen=True)
class Forensics:
    header_source: str = "none"
    mail_date: datetime | None = None
    origin_ip: str | None = None
    message_id: str | None = None
    headers: list[list[str]] = field(default_factory=list)

    @property
    def headers_json(self) -> str | None:
        return json.dumps(self.headers, ensure_ascii=False) if self.headers else None


def _public_ip(candidate: str) -> str | None:
    try:
        ip = ipaddress.ip_address(candidate.strip().rstrip("."))
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def delivery_ip(received: list[str]) -> str | None:
    for raw_hop in received[:MAX_RECEIVED_HOPS]:
        hop = " ".join(raw_hop[: MAX_VALUE_CHARS * 4].split())
        from_part = hop.split(" by ", 1)[0]
        for pattern in (_BRACKET_IP, _PAREN_IP):
            for match in pattern.finditer(from_part[:MAX_VALUE_CHARS]):
                ip = _public_ip(match.group(1))
                if ip:
                    return ip
    return None


def _clean(value: str) -> str:
    return " ".join(str(value).split())[:MAX_VALUE_CHARS]


def _allowed_headers(msg: Message) -> list[list[str]]:
    kept: list[list[str]] = []
    for name, value in msg.items()[: MAX_RECEIVED_HOPS * 3]:
        canonical = _ALLOWED_LOWER.get(name.lower())
        if canonical is None:
            continue
        value = _clean(value)
        if canonical == "DKIM-Signature":
            tags = dict(_DKIM_TAG.findall(value))
            value = "; ".join(f"{k}={tags[k]}" for k in ("d", "s") if k in tags)
        kept.append([canonical, value])
    return kept


def from_message(msg: Message, header_source: str) -> Forensics:
    date = None
    if msg.get("Date"):
        try:
            date = parsedate_to_datetime(str(msg["Date"]))
        except (TypeError, ValueError, IndexError):
            date = None
    message_id = _clean(msg["Message-ID"]) if msg.get("Message-ID") else None
    return Forensics(
        header_source=header_source,
        mail_date=date if date is None or date.tzinfo else None,
        origin_ip=delivery_ip([str(v) for v in msg.get_all("Received", [])]),
        message_id=message_id or None,
        headers=_allowed_headers(msg),
    )


def from_raw(raw_headers: str | None, header_source: str | None) -> Forensics:
    """Forensics from a header block (Outlook add-in, Gmail original). Never raises."""
    if not raw_headers or not header_source:
        return Forensics()
    try:
        msg = HeaderParser().parsestr(raw_headers[:MAX_RAW_HEADERS], headersonly=True)
    except Exception:
        return Forensics(header_source=header_source)
    return from_message(msg, header_source)
