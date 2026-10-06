"""Cifrado autenticado de campos sensibles (AES-256-GCM).

Formato almacenado: ``v1:<kid>:<base64(nonce || ciphertext || tag)>``.
Los datos asociados (``aad``) atan el texto cifrado a su fila y columna
(p. ej. ``"<incident_id>|origin_ip"``): copiarlo a otra fila hace fallar
el descifrado. Rotación: se descifra con cualquier ``kid`` conocido y se
cifra siempre con ``FIELD_ENC_ACTIVE``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import settings

_PREFIX = "v1"
_NONCE_BYTES = 12


class FieldCryptoError(Exception):
    """Llaves mal configuradas o texto cifrado inválido/alterado."""


def _keys() -> dict[str, bytes]:
    raw = settings.FIELD_ENC_KEYS.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        keys = {str(kid): base64.b64decode(value, validate=True) for kid, value in parsed.items()}
    except (ValueError, TypeError, AttributeError, binascii.Error) as exc:
        raise FieldCryptoError("FIELD_ENC_KEYS must be a JSON object of base64 keys") from exc
    for kid, key in keys.items():
        if len(key) != 32 or ":" in kid or not kid:
            raise FieldCryptoError(f"key {kid!r} must be 32 bytes and kid without ':'")
    return keys


def is_configured() -> bool:
    """True cuando hay una llave activa válida para cifrar."""
    try:
        return settings.FIELD_ENC_ACTIVE in _keys()
    except FieldCryptoError:
        return False


def encrypt_field(value: str | None, aad: str) -> str | None:
    if value is None:
        return None
    keys = _keys()
    kid = settings.FIELD_ENC_ACTIVE
    if kid not in keys:
        raise FieldCryptoError("FIELD_ENC_ACTIVE is not a configured key id")
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(keys[kid]).encrypt(nonce, value.encode("utf-8"), aad.encode("utf-8"))
    return f"{_PREFIX}:{kid}:{base64.b64encode(nonce + sealed).decode('ascii')}"


def decrypt_field(token: str | None, aad: str) -> str | None:
    if token is None:
        return None
    parts = token.split(":", 2)
    if len(parts) != 3 or parts[0] != _PREFIX:
        raise FieldCryptoError("unknown ciphertext format")
    _, kid, payload = parts
    key = _keys().get(kid)
    if key is None:
        raise FieldCryptoError(f"unknown key id {kid!r}")
    try:
        blob = base64.b64decode(payload, validate=True)
        plain = AESGCM(key).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], aad.encode("utf-8"))
    except (binascii.Error, InvalidTag, ValueError) as exc:
        raise FieldCryptoError("ciphertext failed authentication") from exc
    return plain.decode("utf-8")


def needs_rotation(token: str | None) -> bool:
    """True si el valor está cifrado con una llave distinta de la activa."""
    if not token:
        return False
    parts = token.split(":", 2)
    return len(parts) == 3 and parts[1] != settings.FIELD_ENC_ACTIVE


def reencrypt_field(token: str | None, aad: str) -> str | None:
    return encrypt_field(decrypt_field(token, aad), aad)
