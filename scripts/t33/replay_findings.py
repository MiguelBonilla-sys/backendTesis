"""Small reproducible requests for findings; no stress or external lookups."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
from local_client import BASE, login, opener, request, sanitize

student, admin = login("student"), login("admin")
rows = []
for method, path, body, token in (
    ("GET", "/api/v1/incidents/not-a-uuid", None, admin),
    ("POST", "/api/v1/report", {"url": "0" * 254}, student),
    ("POST", "/api/v1/report", {"url": "0" * 2048}, student),
    ("POST", "/api/v1/report", {"url": "https://synthetic.example.test/t33-replay"}, student),
):
    status, response = request(method, path, body, token)
    rows.append({"method": method, "path": path, "body": body, "status": status, "response": sanitize(response)})
for size in (16384,):
    boundary = "t33-fixed-synthetic-boundary"
    content = b"Content-Type: text/html; charset=utf-8\r\n\r\n" + b"<" * size
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="t33.eml"\r\n'
            'Content-Type: message/rfc822\r\n\r\n').encode() + content + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(BASE + "/api/v1/analyze_eml", data=body, method="POST", headers={
        "Authorization": "Bearer " + student, "Content-Type": "multipart/form-data; boundary=" + boundary})
    start = time.perf_counter()
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    except TimeoutError:
        rows.append({"method": "POST", "path": "/api/v1/analyze_eml", "payload_bytes": size,
                     "timeout_seconds": 5, "classification": "Inconclusive HTTP timing: content-only pipeline also invokes unavailable LLM. Use parser_probes.py to isolate parser cost."})
        continue
    elapsed = time.perf_counter() - start
    rows.append({"method": "POST", "path": "/api/v1/analyze_eml", "fixture": "Content-Type: text/html + '<' repeated size times",
                 "payload_bytes": size, "elapsed_seconds": elapsed, "status": response.status,
                 "response": json.loads(response.read())})
Path(sys.argv[1]).write_text(json.dumps({"base": BASE, "observed_at": datetime.now(timezone.utc).isoformat(), "replays": rows}, indent=2))
