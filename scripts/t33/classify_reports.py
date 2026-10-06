"""Classify every saved JUnit failure; preserve native evidence and counts."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

root = Path(sys.argv[1])
records = []
summaries = {}


def category(check, status):
    if check == "Server error" or (check == "Undocumented HTTP status code" and status and status >= 500):
        return "5xx: reproducir y clasificar defecto funcional; no descartar como OpenAPI"
    if check in {"Network Error", "ReadTimeout"}:
        return "límite: timeout con dependencias aisladas; no prueba vulnerabilidad"
    if check == "Failed Health Check":
        return "límite del generador: demasiados ejemplos filtrados"
    if check == "API accepted schema-violating request":
        return "contrato: coerción de booleano 0 a false; autorización admin requerida"
    if check == "Invalid Allow header":
        return "contrato HTTP: Allow incompleto en recurso con varios métodos"
    if check == "Response violates schema":
        return "contrato: detail string donde OpenAPI declara array de validación"
    if check == "API rejected schema-compliant request":
        return "contrato: validación de aplicación no expresada en OpenAPI"
    if check == "Undocumented HTTP status code":
        return "contrato: estado HTTP no declarado; revisar respuesta nativa"
    return "revisión manual requerida"


for name in ("black", "student", "admin-exploratory-auth-degraded", "admin"):
    tree = ET.parse(root / f"{name}.xml")
    raw = (root / f"{name}.txt").read_text()
    counts = re.search(r"(\d+) generated, (\d+) found (\d+) unique failures", raw)
    summaries[name] = {"generated_cases": int(counts[1]), "cases_with_failures": int(counts[2]),
                       "unique_failure_checks_cli": int(counts[3]),
                       "junit": tree.getroot().attrib}
    for case in tree.findall(".//testcase"):
        for item in case:
            if item.tag not in {"failure", "error"}:
                continue
            text = item.text or ""
            chunks = re.split(r"(?m)(?=^\d+\. Test Case ID:)", text)
            for chunk in chunks:
                if not chunk.strip():
                    continue
                match = re.search(r"\[(\d{3})\]", chunk)
                status = int(match[1]) if match else None
                checks = re.findall(r"(?m)^- (.+)$", chunk) or [chunk.splitlines()[0]]
                ident = re.search(r"Test Case ID: (\S+)", chunk)
                for check in checks:
                    records.append({"run": name, "operation": case.attrib["name"],
                        "case_id": ident[1] if ident else None, "status": status, "check": check,
                        "classification": category(check, status), "source": f"{name}.xml"})

legacy_dir = Path.home() / ".tesis-scan-2026-10-08/out"
legacy = []
for file in sorted(legacy_dir.glob("schemathesis-*.txt")):
    original = file.read_text()
    sanitized = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", original)
    dest = root / ("legacy-" + file.name)
    dest.write_text(sanitized)
    operation = ""
    for line in sanitized.splitlines():
        match = re.match(r"_+\s+((?:GET|POST|PATCH|DELETE) /\S+)\s+_+", line)
        if match:
            operation = match[1]
        match = re.match(r"\s+Received: (\d{3})", line)
        if match:
            legacy.append({"file": dest.name, "operation": operation, "status": int(match[1]),
                           "classification": category("Undocumented HTTP status code", int(match[1]))})
    summaries[file.name] = {"original_sha256": hashlib.sha256(original.encode()).hexdigest(),
                           "received_statuses": dict(Counter(x["status"] for x in legacy if x["file"] == dest.name))}

(root / "classification.json").write_text(json.dumps({"runs": summaries, "failures": records, "legacy": legacy}, indent=2))
lines = ["# Clasificación Schemathesis — T33", "", "Ejecutado 2026-10-06 contra el tag pre-scan-2026-10-08.", "",
         "Cada fila corresponde a un check/caso de JUnit, no a una vulnerabilidad independiente. Los errores repetidos del generador se conservan en JSON/XML.", "",
         "| Corrida | Casos generados | Casos con fallos | Checks únicos CLI |", "|---|---:|---:|---:|"]
for name, summary in summaries.items():
    if "generated_cases" in summary:
        lines.append(f"| {name} | {summary['generated_cases']} | {summary['cases_with_failures']} | {summary['unique_failure_checks_cli']} |")
lines += ["", "## Fallos clasificados", "", "| Corrida | Operación | Caso | HTTP | Check | Clasificación |", "|---|---|---|---|---|---|"]
seen = set()
for row in records:
    key = tuple(row.values())
    if key in seen:
        continue
    seen.add(key)
    lines.append(f"| {row['run']} | `{row['operation']}` | {row['case_id'] or '—'} | {row['status'] or '—'} | {row['check']} | {row['classification']} |")
lines += ["", "## Logs heredados", "", "| Archivo | Operación | HTTP | Clasificación |", "|---|---|---|---|"]
for row in legacy:
    lines.append(f"| {row['file']} | `{row['operation']}` | {row['status']} | {row['classification']} |")
lines += ["", "Los dos logs heredados admin muestran mayormente 401 y no demuestran cobertura autenticada. No se encontró el log independiente de 351 casos citado en el relevo. No se inventa ni se reconstruye su contenido.",
          "", "La corrida admin exploratoria cambió sus propios permisos: se excluye de cualquier afirmación de cobertura admin estable. La repetición admin conserva todos sus permisos; PATCH/DELETE de roles y PATCH users se verifican con fixtures desechables en el pentest dirigido.",
          "", "Las cuentas/roles sintéticos y los contadores cambian durante el fuzzing; los totales entre perfiles no son una comparación de rendimiento. Stateful desactivado. Los límites y las peticiones de reproducción están en XML/NDJSON."]
(root / "CLASSIFICATION.md").write_text("\n".join(lines) + "\n")
print(json.dumps(summaries, indent=2))
