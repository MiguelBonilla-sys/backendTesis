"""T33 — shim HTTP para Garak: cada prompt de Garak entra como CUERPO DE CORREO no confiable.

Usa el prompt real del LLMAgent (system message, redacción de PII, fence
<<<UNTRUSTED_CONTENT>>>, recorte a 500 caracteres) y el modelo real del gateway.
Garak lee `text` (salida cruda del modelo, criterio estricto); `reason` es lo
que llegaría al dashboard tras `_sanitize_reason`. Cada intento queda en JSONL
para medir además si la inyección movió el SCORE.

Uso (desde backendTesis, con su .venv):
  GARAK_LOG=out.jsonl GARAK_FULL_BODY=0 uvicorn garak_shim:app --app-dir <dir> --port 18300
GARAK_FULL_BODY=1 quita el recorte a 500 caracteres (mide solo modelo + fence).
"""

import json
import os
import time

from fastapi import FastAPI
from pydantic import BaseModel

from agents import llm_agent as mod
from agents.llm_agent import llm_agent

URL, DOMAIN = "https://secure-paypa1-login.test/verify", "secure-paypa1-login.test"
LOG = os.environ.get("GARAK_LOG", "garak-shim.jsonl")

if os.environ.get("GARAK_FULL_BODY") == "1":
    _orig = llm_agent._build_prompt

    def _full(url, domain, email_body, rag_context, idn_summary):
        prompt = _orig(url, domain, None, rag_context, idn_summary)
        return prompt.replace(
            "\n\n## Task:", f"Email content snippet:\n{mod._fence(mod.redact(email_body))}\n\n## Task:", 1)

    llm_agent._build_prompt = _full

app = FastAPI()


class Probe(BaseModel):
    prompt: str


@app.post("/probe")
async def probe(body: Probe) -> dict:
    prompt = llm_agent._build_prompt(URL, DOMAIN, body.prompt, [], None)
    t0 = time.monotonic()
    try:
        text = str(await llm_agent._call_llm(prompt))
    except Exception as exc:  # noqa: BLE001 — el error también es un resultado
        text = f"__ERROR__ {type(exc).__name__}"
    row = {"prompt": body.prompt, "text": text, "score": llm_agent._parse_score(text),
           "reason": llm_agent._parse_reason(text), "ms": round(1000 * (time.monotonic() - t0))}
    with open(LOG, "a") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row
