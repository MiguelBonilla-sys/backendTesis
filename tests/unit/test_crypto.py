import base64
import json

import pytest

from core import crypto
from core.config import settings


def _key() -> str:
    return base64.b64encode(bytes(range(32))).decode()


def _key2() -> str:
    return base64.b64encode(bytes(range(32, 64))).decode()


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", json.dumps({"k1": _key(), "k2": _key2()}))
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "k1")


def test_roundtrip_and_format(keys):
    token = crypto.encrypt_field("203.0.113.7", "inc-1|origin_ip")
    assert token.startswith("v1:k1:")
    assert "203.0.113.7" not in token
    assert crypto.decrypt_field(token, "inc-1|origin_ip") == "203.0.113.7"


def test_nonce_is_random(keys):
    assert crypto.encrypt_field("x", "a") != crypto.encrypt_field("x", "a")


def test_none_passthrough(keys):
    assert crypto.encrypt_field(None, "a") is None
    assert crypto.decrypt_field(None, "a") is None


def test_tampered_ciphertext_fails(keys):
    token = crypto.encrypt_field("secret", "a")
    prefix, kid, payload = token.split(":", 2)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 0x01
    bad = f"{prefix}:{kid}:{base64.b64encode(bytes(raw)).decode()}"
    with pytest.raises(crypto.FieldCryptoError):
        crypto.decrypt_field(bad, "a")


def test_wrong_aad_fails(keys):
    token = crypto.encrypt_field("secret", "inc-1|origin_ip")
    with pytest.raises(crypto.FieldCryptoError):
        crypto.decrypt_field(token, "inc-2|origin_ip")


def test_rotation(keys, monkeypatch):
    old = crypto.encrypt_field("secret", "a")
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "k2")
    assert crypto.needs_rotation(old)
    new = crypto.reencrypt_field(old, "a")
    assert new.startswith("v1:k2:") and not crypto.needs_rotation(new)
    assert crypto.decrypt_field(new, "a") == "secret"


def test_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", "")
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "")
    assert not crypto.is_configured()
    with pytest.raises(crypto.FieldCryptoError):
        crypto.encrypt_field("x", "a")


@pytest.mark.parametrize(
    "raw", ["not json", json.dumps({"k1": "short"}), json.dumps({"a:b": _key()})]
)
def test_bad_keys(monkeypatch, raw):
    monkeypatch.setattr(settings, "FIELD_ENC_KEYS", raw)
    monkeypatch.setattr(settings, "FIELD_ENC_ACTIVE", "k1")
    assert not crypto.is_configured()
    with pytest.raises(crypto.FieldCryptoError):
        crypto.encrypt_field("x", "a")


def test_unknown_format_and_kid(keys):
    with pytest.raises(crypto.FieldCryptoError):
        crypto.decrypt_field("plain-text", "a")
    with pytest.raises(crypto.FieldCryptoError):
        crypto.decrypt_field("v1:zz:AAAA", "a")
    with pytest.raises(crypto.FieldCryptoError):
        crypto.decrypt_field("v1:k1:@@@", "a")
