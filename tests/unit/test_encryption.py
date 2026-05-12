# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — AES-256-GCM envelope 암호화 헬퍼 회귀 방지 (T6.2).

`app.security.encryption` 의 column-level 암호화 primitive 가 키 로테이션·
변조 감지·구버전 envelope 호환을 정확히 수행하는지 검증한다. 각 테스트는
fixture 가 깨끗한 32-byte 키 + 빈 retired-key 맵을 주입하고 cipher 캐시를
비우므로 테스트 간 상태 누출이 없다.

검증 영역:
- 평문/유니코드/빈 문자열 라운드트립
- envelope 의 version byte + key-id 헤더 형식
- 변조된 ciphertext / 잘린 envelope / 잘못된 base64 거절
- 키 교체 후 옛 envelope 가 retired-key 맵으로 복호화 가능
- 키 미설정 시 명시적 에러
"""

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
    """평문 → ciphertext → 평문 라운드트립이 성공해야 한다 (happy path).

    가장 기본적인 가드 — 암/복호화 둘 다 작동하지 않으면 운영 가능성 0.
    """
    plaintext = "주민등록번호 010101-1234567"  # 합성 데이터
    ct = encryption.encrypt_str(plaintext)
    assert ct  # 빈 문자열 아님
    assert ct != plaintext
    assert encryption.decrypt_str(ct) == plaintext


def test_empty_input_round_trips_to_empty() -> None:
    """빈 문자열 입력은 빈 문자열로 그대로 통과 (no-op).

    DB 컬럼이 NOT NULL 인데 값이 비어있는 행을 다룰 때 envelope 헤더만 들어
    가지 않도록 함. 빈 문자열을 굳이 암호화/복호화 사이클 태우는 비용 회피.
    """
    assert encryption.encrypt_str("") == ""
    assert encryption.decrypt_str("") == ""


def test_unicode_round_trip() -> None:
    """UTF-8 다국어 문자열도 정확히 라운드트립 — bytes 인코딩 회귀 방지."""
    plaintext = "이름: 홍길동 — email: alice@example.com"
    assert encryption.decrypt_str(encryption.encrypt_str(plaintext)) == plaintext


def test_envelope_format_has_version_byte_and_kid() -> None:
    """envelope 의 첫 두 바이트가 version (`v`) + key-id (1) 임을 핀(pin).

    이 헤더 형식이 바뀌면 기존 DB row 가 전부 복호화 불가가 된다. 호환성을
    유지하려면 헤더 변경 시 새 version byte 추가 + 마이그레이션 필요.
    """
    ct = encryption.encrypt_str("hello")
    raw = base64.b64decode(ct)
    assert raw[0:1] == b"v"
    # 기본 key id 는 1
    assert raw[1] == 1


def test_tampered_ciphertext_rejected() -> None:
    """ciphertext 의 한 비트를 뒤집으면 GCM tag 검증이 실패해 거절되어야 한다.

    AES-GCM 의 인증 기능을 확실히 사용하는지 확인. 변조된 envelope 가 silent
    하게 잘못된 평문을 돌려주는 사고를 차단.
    """
    ct = encryption.encrypt_str("hello")
    raw = bytearray(base64.b64decode(ct))
    # version + kid + nonce 뒤의 ciphertext 영역에서 한 비트 뒤집기
    raw[20] ^= 0x01
    bad = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str(bad)


def test_truncated_envelope_rejected() -> None:
    """envelope 길이가 헤더만 있고 ciphertext 가 없는 경우 명시적 거절."""
    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str(base64.b64encode(b"short").decode("ascii"))


def test_bad_base64_rejected() -> None:
    """잘못된 base64 입력 시 silent 빈 결과가 아니라 명시적 EncryptionError."""
    with pytest.raises(encryption.EncryptionError):
        encryption.decrypt_str("!!! not base64 !!!")


def test_key_mismatch_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """키 A 로 암호화한 envelope 를 키 B 로 복호화 시도 → EncryptionError.

    동일 key-id 라도 마스터 키 자체가 다르면 GCM tag 검증이 실패한다.
    이는 retired-key 맵 없이 단순 키 교체 후 옛 envelope 가 무용지물이
    됨을 명시적으로 노출하는 가드.
    """
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
    """v1 키로 암호화한 envelope 가 v2 로 회전 후에도 retired-key 맵으로 복호화.

    실제 운영 시나리오 — 보안 사고 등으로 마스터 키를 새 버전으로 교체할 때
    DB 안의 기존 envelope 를 일괄 재암호화하기 전이라도 retired-key 맵
    (`pii_encryption_old_keys`) 에 v1 키를 남겨두면 점진적 마이그레이션이
    가능해야 한다. 새 envelope 는 새 key-id (2) 로 발급되는 것도 함께 확인.
    """
    # 회전 전의 현재 키를 캡처.
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
    """`pii_encryption_key` 가 빈 문자열이면 encrypt_str 호출 시 즉시 에러.

    silent fallback (예: 평문 그대로 저장) 이 발생하면 DB 에 평문 PII 가
    들어가는 사고로 직결되므로 명시적 EncryptionError 가 떨어져야 한다.
    """
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
