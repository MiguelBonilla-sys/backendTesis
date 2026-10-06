"""Error responses the API really returns, declared in OpenAPI (hallazgo F33-04)."""

from __future__ import annotations

from pydantic import BaseModel


class ErrorDetail(BaseModel):
    detail: str


def _r(description: str) -> dict:
    return {"model": ErrorDetail, "description": description}


PROTECTED = {
    401: _r("Sin sesión válida o token vencido"),
    403: _r("La cuenta no tiene el permiso requerido"),
    429: _r("Límite de peticiones alcanzado"),
    503: _r("Servicio de sesión o almacenamiento no disponible"),
}
RESOURCE = {**PROTECTED, 404: _r("Recurso inexistente"), 409: _r("Conflicto con el estado actual")}
AUTH = {
    401: _r("Credenciales o segundo factor rechazados"),
    429: _r("Demasiados intentos o espera de reenvío"),
    503: _r("Servicio de sesión no disponible"),
}
