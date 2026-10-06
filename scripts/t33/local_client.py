"""Local-only T33 helpers. Credentials and response tokens never enter reports."""
import json
import os
from pathlib import Path
import shlex
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("T33_BASE", "http://127.0.0.1:18002")
url = urllib.parse.urlsplit(BASE)
if url.scheme != "http" or url.hostname != "127.0.0.1" or not 18000 <= (url.port or 0) < 19000:
    raise RuntimeError("T33 accepts only the ephemeral loopback 18xxx stack")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def request(method, path, body=None, token=None):
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Relative API path required")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read().decode(errors="replace")
    try:
        content = json.loads(raw)
    except ValueError:
        content = raw
    return response.status, content


def credentials():
    path = Path.home() / ".tesis-scan-2026-10-08/out/creds.env"
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Scan credentials must have mode 600")
    values = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, value = line.removeprefix("export ").split("=", 1)
            values[name] = shlex.split(value)[0] if value else ""
    return values


def login(profile):
    if profile == "black":
        return None
    values = credentials()
    status, data = request("POST", "/api/v1/auth/login", {
        "username": values["STUDENT" if profile == "student" else "ADMIN"], "password": values["PASS"]})
    if status != 200 or not isinstance(data, dict) or "access_token" not in data:
        raise RuntimeError(f"Scan login {profile} failed: HTTP {status}")
    return data["access_token"]


SECRET_FIELDS = {"access_token", "refresh_token", "password", "codes", "authorization", "cookie", "set-cookie"}


def sanitize(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in SECRET_FIELDS else sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value
