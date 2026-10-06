"""Invoke pinned Schemathesis in-process; never expose bearer tokens in argv."""
import json
import os
from pathlib import Path
import sys
from schemathesis.cli import schemathesis
from local_client import BASE, login, request, sanitize

profile, output = sys.argv[1:]
os.umask(0o077)
out = Path(output).resolve()
out.mkdir(parents=True, exist_ok=True)
token = login(profile)
before = request("GET", "/api/v1/auth/me", token=token)
(out / f"{profile}-auth-preflight.json").write_text(json.dumps(sanitize(before), indent=2))
if profile != "black" and before[0] != 200:
    raise SystemExit("Authenticated preflight failed")
args = ["run", BASE + "/openapi.json", "--workers", "1", "--max-examples", "20",
        "--seed", "20261008", "--generation-database", "none",
        "--generation-with-security-parameters", "false", "--max-redirects", "0",
        "--request-timeout", "3", "--max-time", "120", "--continue-on-failure",
        "--phases", "examples,coverage,fuzzing", "--checks", "all",
        # Mutations of live roles/users can revoke the scanner's own permissions.
        # Exercise these via disposable-fixture probes in pentest_http.py instead.
        "--exclude-path-regex", r"/auth/(login|logout|register|refresh|mfa/.*)$|/users/.*|/roles/.*",
        "--report", "junit,ndjson", "--report-junit-path", str(out / f"{profile}.xml"),
        "--report-ndjson-path", str(out / f"{profile}.ndjson"),
        "--output-sanitize", "true"]
if token:
    args += ["--header", "Authorization:Bearer " + token]
try:
    schemathesis.main(args=args, standalone_mode=False)
except SystemExit as exc:
    code = exc.code
else:
    code = 0
finally:
    # Schemathesis 4.29.3 sanitizes request headers but retains the bearer in
    # ScenarioFinished.recorder.cases.*.value.headers in native NDJSON.
    # Redact the exact session token before exposing the artifact.
    if token:
        for report in (out / f"{profile}.ndjson", out / f"{profile}.xml"):
            if report.exists():
                temporary = report.with_suffix(report.suffix + ".redacted")
                with report.open() as source, temporary.open("w") as dest:
                    for line in source:
                        dest.write(line.replace(token, "[REDACTED]"))
                temporary.replace(report)
    after = request("GET", "/api/v1/auth/me", token=token)
    (out / f"{profile}-auth-postflight.json").write_text(json.dumps(sanitize(after), indent=2))
    if profile != "black" and after != before:
        raise RuntimeError("Scanner authentication or permissions changed during the run")
sys.exit(code)
