# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — AES-256-GCM column encryption primitives (T6.2)."""

from __future__ import annotations

import base64
import os

import pytest

from app.security import encryption


@pytest.fixture(autouse=True)
def _configure_test_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wire a known 32-byte hex key + clear cipher caches per test."""
    key = os.urandom(32).hex()
    monkeypatch.setattr(
        encryption,
        "get_settings",
        lambda: _settings_with(
            pii_encryption_key=key,
            pii_encryption_key_id=1,
            pii_encryption_old_keys="",
        ),
    )
    encryption.get_cipher.cache_clear()
    encryption._old_ciphers.cache_clear()


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    from app.config import Settings

    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


def test_round_trip_simple() -> None:
    plaintext = "주민등록번호 010101-1234567"   # synthetic
    ct = encryption.encrypt_str(plaintext)
    assert ct  # non-empty
    assert ct != plaintext
    assert encryption.decrypt_str(ct) == plaintext


def test_empty_input_round_trips_to_empty() -> None:
    assert encryption.encrypt_str("") == ""
    assert encryption.decrypt_str("") == ""


def test_unicode_round_trip() -> None:
    plaintext = "이름: 홍길동 — email: alice@example.com"
    assert encryption.decrypt_str(encryption.encrypt_str(plaintext)) == plaintext


def test_envelope_format_has_version_byte_and_kid() -> None:
    ct = encryption.encrypt_str("hello")
    raw = base64.b64decode(ct)
    assert raw[0:1] == b"v"
    # default key id is 1
    assert raw[1] == 1


def test_tampered_ciphertext_rejected() -> None:
    ct = encryption.encrypt_str("hello")
    raw = bytearray(base64.b64decode(ct))
    # Flip a bit in the ciphertext region (after version + kid + nonce).
    raw[20] ^= 0x01
    bad = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str(bad)


def test_truncated_envelope_rejected() -> None:
    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str(base64.b64encode(b"short").decode("ascii"))


def test_bad_base64_rejected() -> None:
    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str("!!! not base64 !!!")


def test_key_mismatch_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-encrypting with one key, then swapping the master key, must fail."""
    ct = encryption.encrypt_str("secret")

    new_key = os.urandom(32).hex()
    monkeypatch.setattr(
        encryption,
        "get_settings",
        lambda: _settings_with(
            pii_encryption_key=new_key,
            pii_encryption_key_id=1,
            pii_encryption_old_keys="",
        ),
    )
    encryption.get_cipher.cache_clear()
    encryption._old_ciphers.cache_clear()

    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str(ct)


def test_old_keys_decrypt_after_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypt under key v1, rotate to v2 with v1 in pii_encryption_old_keys."""
    # Capture the current key BEFORE rotation.
    v1_key = encryption.get_settings().pii_encryption_key
    # Encrypt under current key (kid=1).
    ct = encryption.encrypt_str("secret-v1")

    # Rotate: new master key, kid=2; v1 retained as retired key.
    v2_key = os.urandom(32).hex()
    import json
    monkeypatch.setattr(
        encryption,
        "get_settings",
        lambda: _settings_with(
            pii_encryption_key=v2_key,
            pii_encryption_key_id=2,
            pii_encryption_old_keys=json.dumps({"1": v1_key}),
        ),
    )
    encryption.get_cipher.cache_clear()
    encryption._old_ciphers.cache_clear()

    # Old envelope still decrypts via the retired-key map.
    assert encryption.decrypt_str(ct) == "secret-v1"
    # New envelope uses the v2 key + kid=2.
    new_ct = encryption.encrypt_str("secret-v2")
    raw = base64.b64decode(new_ct)
    assert raw[1] == 2
    assert encryption.decrypt_str(new_ct) == "secret-v2"


def test_unconfigured_key_raises() -> None:
    from app.config import Settings

    encryption.get_cipher.cache_clear()
    encryption._old_ciphers.cache_clear()
    base = Settings().model_dump()
    base["pii_encryption_key"] = ""
    bad = Settings(**base)

    import pytest as _pytest
    with _pytest.MonkeyPatch.context() as m:
        m.setattr(encryption, "get_settings", lambda: bad)
        with _pytest.raises(encryption.EncryptionError):
            encryption.encrypt_str("anything")
