"""AES-256-GCM application-level encryption for at-rest PII (Phase 6, Q1).

Used for any column that may contain PII plaintext. We deliberately avoid
``pgcrypto`` so the key never lives in the database where a DBA could read
both the key and the ciphertext.

Envelope format
---------------
The on-disk / on-DB representation is the base64 of the binary envelope::

    b"v" || key_id (1B) || nonce (12B) || ciphertext || tag (16B)

* ``"v"`` literal is a sanity sentinel for the envelope version.
* ``key_id`` allows future master-key rotation without re-encrypting old
  rows in lockstep.
* ``nonce`` is a 96-bit random value, the AES-GCM standard.
* ``tag`` is appended by ``AESGCM.encrypt`` (last 16 bytes of output).

Empty / None plaintext maps to an empty string round-trip — callers can
store optional values without a sentinel value.
"""

from __future__ import annotations

import base64
import json
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

_VERSION_BYTE = b"v"
_NONCE_BYTES = 12
_TAG_BYTES = 16


class EncryptionError(Exception):
    """Raised on tampered ciphertext, key mismatch, or malformed envelope."""


def _decode_master_key(hex_str: str) -> bytes:
    """Convert the hex-encoded master key to 32 raw bytes.

    Empty input is rejected — encryption must be configured before use.
    """
    if not hex_str:
        raise EncryptionError(
            "pii_encryption_key is not configured (set 32-byte hex env var)"
        )
    try:
        key = bytes.fromhex(hex_str)
    except ValueError as e:
        raise EncryptionError(f"pii_encryption_key is not valid hex: {e}") from e
    if len(key) != 32:
        raise EncryptionError(
            f"pii_encryption_key must decode to 32 bytes (AES-256); got {len(key)}"
        )
    return key


@lru_cache(maxsize=1)
def get_cipher() -> AESGCM:
    """Process-wide AES-GCM primitive bound to the configured master key."""
    settings = get_settings()
    return AESGCM(_decode_master_key(settings.pii_encryption_key))


@lru_cache(maxsize=1)
def _old_ciphers() -> dict[int, AESGCM]:
    """Map of retired key_id → AESGCM, used for decryption only.

    Lets operators rotate the active key while still being able to read
    rows encrypted under previous keys. Population comes from
    ``Settings.pii_encryption_old_keys`` (JSON-encoded ``{kid: hex_key}``).
    """
    raw = (get_settings().pii_encryption_old_keys or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise EncryptionError(
            f"pii_encryption_old_keys is not valid JSON: {e}"
        ) from e
    out: dict[int, AESGCM] = {}
    for k, v in parsed.items():
        try:
            kid = int(k) & 0xFF
        except (ValueError, TypeError) as e:
            raise EncryptionError(
                f"pii_encryption_old_keys: bad key_id {k!r}"
            ) from e
        out[kid] = AESGCM(_decode_master_key(str(v)))
    return out


def _cipher_for(kid: int) -> AESGCM:
    """Pick the cipher matching the envelope's key_id byte.

    Falls back to the current cipher if the retired-key table is empty
    so envelopes encrypted before key rotation was introduced still
    decrypt cleanly.
    """
    current_kid = int(get_settings().pii_encryption_key_id) & 0xFF
    if kid == current_kid:
        return get_cipher()
    olds = _old_ciphers()
    if kid in olds:
        return olds[kid]
    # No matching key: fall through to the current one — caller will get
    # an InvalidTag on mismatch, surfaced as EncryptionError.
    return get_cipher()


def _key_id_byte() -> bytes:
    kid = int(get_settings().pii_encryption_key_id) & 0xFF
    return bytes([kid])


def encrypt_str(plaintext: str) -> str:
    """Encrypt ``plaintext`` to a base64 envelope string.

    Empty / falsy input round-trips as an empty string so optional columns
    don't need a sentinel.
    """
    if not plaintext:
        return ""
    cipher = get_cipher()
    nonce = os.urandom(_NONCE_BYTES)
    ct_with_tag = cipher.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    envelope = _VERSION_BYTE + _key_id_byte() + nonce + ct_with_tag
    return base64.b64encode(envelope).decode("ascii")


def decrypt_str(envelope: str) -> str:
    """Decrypt a base64 envelope back to plaintext.

    Raises :class:`EncryptionError` on tampered ciphertext, malformed
    envelope, or master-key mismatch.
    """
    if not envelope:
        return ""
    try:
        raw = base64.b64decode(envelope.encode("ascii"), validate=True)
    except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
        raise EncryptionError(f"malformed envelope (bad base64): {e}") from e

    if len(raw) < 1 + 1 + _NONCE_BYTES + _TAG_BYTES:
        raise EncryptionError("malformed envelope (too short)")
    if raw[0:1] != _VERSION_BYTE:
        raise EncryptionError("malformed envelope (bad version sentinel)")

    kid = raw[1]
    nonce = raw[2 : 2 + _NONCE_BYTES]
    ct_with_tag = raw[2 + _NONCE_BYTES :]

    cipher = _cipher_for(kid)
    try:
        plaintext = cipher.decrypt(nonce, ct_with_tag, associated_data=None)
    except Exception as e:  # cryptography raises InvalidTag etc.
        raise EncryptionError(f"decryption failed: {e}") from e
    return plaintext.decode("utf-8")
