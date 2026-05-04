"""런타임 인식기 오버라이드 — patterns / context 사용자 편집.

Phase 9I — 대시보드 "패턴" 화면에서 인식기의 정규식 패턴과 context words 를
편집할 수 있도록 한다. 코드 변경 없이 system_settings.json 만으로 운영자가
오탐/미탐을 즉시 보정할 수 있다.

저장 형식 (system_settings.json 의 ``recognizer_overrides`` 키)::

    {
      "<RecognizerClassName>": {
        "patterns": [
          {"name": "...", "regex": "...", "score": 0.6},
          ...
        ],
        "context": ["주민", "주민등록", ...]
      }
    }

규칙:
  - ``patterns`` / ``context`` 는 각각 코드 기본값을 **전체 대체**한다 (delta 아님).
  - 키가 없으면 코드 기본값 그대로 사용된다.
  - 인식기 항목 자체를 삭제 (``reset_recognizer``) 하면 모든 코드 기본값으로
    복원된다.
  - regex 는 저장 시 ``re.compile`` 로 검증되며, 잘못된 정규식은 ``ValueError``.
  - score 는 0.0 ~ 1.0 범위로 클램프.
"""

from __future__ import annotations

import re
from typing import Any

from presidio_analyzer import Pattern

from app.core import system_settings as _ss

_OVERRIDES_KEY = "recognizer_overrides"


def get_all_overrides() -> dict[str, dict[str, Any]]:
    """저장된 오버라이드 전체 반환 (없으면 빈 dict)."""
    raw = _ss.get(_OVERRIDES_KEY)
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, dict):
            out[k] = v
    return out


def get_override(class_name: str) -> dict[str, Any]:
    """특정 인식기 오버라이드 — 없으면 빈 dict."""
    return get_all_overrides().get(class_name, {})


def has_override(class_name: str) -> bool:
    """오버라이드가 하나라도 적용된 인식기인지."""
    ov = get_override(class_name)
    return bool(ov.get("patterns")) or "context" in ov


def set_override(
    class_name: str,
    *,
    patterns: list[dict[str, Any]] | None = None,
    context: list[str] | None = None,
) -> None:
    """오버라이드 저장. ``None`` 으로 전달된 필드는 변경하지 않는다.

    ``patterns`` 의 각 dict 는 ``name`` (str), ``regex`` (str, 컴파일 가능),
    ``score`` (float, 0.0 ~ 1.0) 를 가져야 한다. 잘못된 정규식은 ``ValueError``.
    """
    cur = get_all_overrides()
    entry = dict(cur.get(class_name, {}))

    if patterns is not None:
        validated: list[dict[str, Any]] = []
        for p in patterns:
            name = str(p.get("name", "")).strip()
            regex = str(p.get("regex", ""))
            if not name or not regex:
                continue
            try:
                re.compile(regex)
            except re.error as e:
                msg = f"invalid regex for pattern '{name}': {e}"
                raise ValueError(msg) from e
            try:
                score = float(p.get("score", 0.5))
            except (TypeError, ValueError):
                score = 0.5
            score = max(0.0, min(1.0, score))
            validated.append({"name": name, "regex": regex, "score": score})
        entry["patterns"] = validated

    if context is not None:
        # 공백 제거 + 빈 문자열 제거 + 중복 제거 (입력 순서 보존).
        seen: set[str] = set()
        cleaned: list[str] = []
        for w in context:
            w = str(w).strip()
            if w and w not in seen:
                seen.add(w)
                cleaned.append(w)
        entry["context"] = cleaned

    cur[class_name] = entry
    _ss.set_value(_OVERRIDES_KEY, cur)


def reset_recognizer(class_name: str) -> None:
    """해당 인식기의 모든 오버라이드 제거 → 코드 기본값으로 복원."""
    cur = get_all_overrides()
    if class_name in cur:
        del cur[class_name]
        _ss.set_value(_OVERRIDES_KEY, cur)


def apply_to(recognizer: object) -> None:
    """오버라이드를 인식기 인스턴스에 in-place 적용.

    Presidio ``PatternRecognizer`` 는 ``self.patterns`` / ``self.context`` 를
    분석 시 그대로 읽으므로 속성 재할당으로 충분하다.
    """
    cls = type(recognizer).__name__
    ov = get_override(cls)
    if not ov:
        return

    if "patterns" in ov and isinstance(ov["patterns"], list):
        recognizer.patterns = [  # type: ignore[attr-defined]
            Pattern(
                name=str(p["name"]),
                regex=str(p["regex"]),
                score=float(p["score"]),
            )
            for p in ov["patterns"]
            if isinstance(p, dict) and p.get("name") and p.get("regex")
        ]

    if "context" in ov and isinstance(ov["context"], list):
        recognizer.context = [str(w) for w in ov["context"] if str(w).strip()]  # type: ignore[attr-defined]
