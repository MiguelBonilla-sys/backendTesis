"""Bounded offline probes executed only in the frozen, isolated container."""
import json
import os
import signal
import time
from html.parser import HTMLParser

if os.environ.get("T33_ISOLATED") != "1":
    raise SystemExit("Requires explicit isolated environment")

from services.alerts import AlertIncident, render_alert
from services.mailer import _header_safe
from utils.email_parser import parse_eml
from utils.mail_forensics import from_raw


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.event_attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.event_attributes += [(k, v) for k, v in attrs if k.lower().startswith("on")]


attack = '<img src=x onerror="alert(33)"><script>alert(33)</script>\r\nBcc: extra@example.test'
subject, text, html = render_alert(AlertIncident(
    incident_id='test\" onclick="alert(33)', url=attack, domain=attack,
    verdict="PHISHING", s_risk=0.9, reasons=[attack], category=attack, origin_isp=attack))
parsed = Tags()
parsed.feed(html)
mail = {"payload": attack, "rendered_html": html, "sanitized_subject": _header_safe(subject),
        "unsafe_tags": [tag for tag in parsed.tags if tag in {"img", "script", "svg"}],
        "event_attributes": parsed.event_attributes,
        "crlf_in_subject": any(c in _header_safe(subject) for c in "\r\n")}
raw = f"From: {attack.split(chr(13))[0]}\r\nReceived: from sender ([8.8.8.8]) by mx.example.test\r\n"
headers = from_raw(raw, "outlook-addin")


def timeout(signum, frame):
    raise TimeoutError("bounded parser deadline")


signal.signal(signal.SIGALRM, timeout)
measurements = []
for kind in ("html_unclosed_tags", "plain_control", "received_bounded"):
    for size in (1024, 4096, 16384, 65536, 131072):
        start = time.perf_counter()
        signal.setitimer(signal.ITIMER_REAL, 2)
        timed_out = False
        try:
            if kind == "received_bounded":
                from_raw("Received: " + "<" * size, "outlook-addin")
            else:
                content_type = "text/html" if kind == "html_unclosed_tags" else "text/plain"
                parse_eml((f"Content-Type: {content_type}; charset=utf-8\r\n\r\n" + "<" * size).encode())
        except TimeoutError:
            timed_out = True
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        # parse_eml catches exceptions internally: elapsed >=2s also proves deadline reached.
        elapsed = time.perf_counter() - start
        measurements.append({"kind": kind, "payload_bytes": size, "elapsed_seconds": elapsed,
                             "deadline_seconds": 2, "deadline_reached": timed_out or elapsed >= 2})
print(json.dumps({"mail": mail, "header_fixture": {"raw": raw, "parsed": headers.headers},
                  "timings": measurements, "timing_limitations": "Shared VM; bounded samples, not production throughput benchmark"}, indent=2))
