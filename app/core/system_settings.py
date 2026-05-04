"""런타임 토글 설정 — JSON 파일 기반.

DB 스키마 변경 없이 대시보드에서 설정을 토글할 수 있다.
파일: data/system_settings.json (gitignored)
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

_FILE = Path("data/system_settings.json")
_lock = threading.Lock()
_DEFAULTS: dict[str, object] = {
    "audit_detail_enabled": True,  # 테스트 기본 ON
}


def get_settings_dict() -> dict[str, object]:
    """현재 설정을 dict로 반환. 파일 없거나 파싱 실패 시 기본값 반환."""
    if not _FILE.exists():
        return dict(_DEFAULTS)
    try:
        data: object = json.loads(_FILE.read_text(encoding="utf-8"))
    except Exception:
        return dict(_DEFAULTS)
    if not isinstance(data, dict):
        return dict(_DEFAULTS)
    merged = dict(_DEFAULTS)
    merged.update(data)
    return merged


def get(key: str) -> object:
    """단일 키 조회."""
    return get_settings_dict().get(key)


def set_value(key: str, value: object) -> None:
    """단일 키 저장 (스레드 안전)."""
    with _lock:
        cur = get_settings_dict()
        cur[key] = value
        _FILE.parent.mkdir(parents=True, exist_ok=True)
        _FILE.write_text(
            json.dumps(cur, indent=2, ensure_ascii=False), encoding="utf-8"
        )
