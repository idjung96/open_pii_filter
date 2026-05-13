"""PoC(shadow) 모드 전용 파일 로거.

실제 운영 환경에서 기존 상용 PII filter 와 본 ``open_pii_filter`` 의 판정을
비교(PoC) 하기 위한 로깅 채널.

설계 원칙:
  - 활성화 시 사용자 응답은 항상 PASS(OK-0000) 로 고정되지만, 본 모듈은
    **분석기가 실제로 내린 판정**(would-be verdict / code / 검출 종류) 만
    파일에 기록한다.
  - §2.5 보안 가드 — 평문 PII 는 절대 기록하지 않는다. ``entity_type`` /
    ``code`` / ``score`` / ``start`` / ``end`` 메타데이터만 남기고 원문 문자열
    이나 마스킹 미리보기는 일절 포함하지 않는다.
  - 출력 포맷은 JSON Lines (한 줄 = 한 요청). 후처리/분석을 위해 일반 텍스트
    로그가 아닌 구조화 형식을 사용.
  - I/O 실패는 swallow — PoC 로깅이 깨져도 본 요청 흐름은 계속 진행되어야
    한다 (best-effort).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.api.schemas import Detection

_logger = logging.getLogger(__name__)
_file_lock = threading.Lock()


def _resolve_path(raw: str) -> Path:
    """``poc_log_file`` 설정값을 ``Path`` 로 정규화하고 디렉터리를 보장."""
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _safe_detections(detections: Iterable[Detection]) -> list[dict[str, Any]]:
    """검출 목록을 PII 평문이 빠진 메타데이터 dict 로 직렬화."""
    out: list[dict[str, Any]] = []
    for d in detections:
        out.append(
            {
                "field": d.field,
                "entity_type": d.entity_type,
                "code": d.code,
                "score": round(float(d.score), 4),
                "start": d.start,
                "end": d.end,
            }
        )
    return out


def log_body_decision(
    *,
    request_id: UUID,
    actual_code: str,
    actual_verdict: str,
    detections: Iterable[Detection],
    log_only_types: Iterable[str] | None = None,
    shadow_hit_types: Iterable[str] | None = None,
    strictness: str,
    audit_only: bool,
    author_ip: str | None,
    board_id: str | None,
    processing_ms: int,
) -> None:
    """본문(title + body) 검사 결과 1건을 PoC 로그에 기록.

    응답이 PASS 로 강제되기 *전* 의 실제 판정을 남긴다.
    """
    from app.config import get_settings  # local import — avoid cycles

    settings = get_settings()
    if not settings.poc_mode:
        return

    record = {
        "ts": datetime.now(tz=UTC).isoformat(),
        "kind": "body",
        "request_id": str(request_id),
        "actual_code": actual_code,
        "actual_verdict": actual_verdict,
        "forced_response_code": "OK-0000",
        "forced_response_verdict": "PASS",
        "strictness": strictness,
        "audit_only": bool(audit_only),
        "author_ip": author_ip or "",
        "board_id": board_id or "",
        "processing_ms": int(processing_ms),
        "detections": _safe_detections(detections),
        "log_only_types": sorted(set(log_only_types or [])),
        "shadow_hit_types": sorted(set(shadow_hit_types or [])),
    }
    _emit(record)


def log_attachment_decision(
    *,
    request_id: UUID,
    job_id: str,
    actual_code: str,
    actual_verdict: str,
    attachment_summaries: list[dict[str, Any]],
) -> None:
    """첨부(Case C) 비동기 결과 1건을 PoC 로그에 기록.

    ``attachment_summaries`` 는 각 첨부의 ``{attachment_id, filename, verdict,
    code, detections}`` 메타만 담은 dict 리스트 (평문 미포함).
    """
    from app.config import get_settings

    settings = get_settings()
    if not settings.poc_mode:
        return

    record = {
        "ts": datetime.now(tz=UTC).isoformat(),
        "kind": "attachment",
        "request_id": str(request_id),
        "job_id": job_id,
        "actual_code": actual_code,
        "actual_verdict": actual_verdict,
        "forced_response_code": "OK-0000",
        "forced_response_verdict": "PASS",
        "attachment_results": attachment_summaries,
    }
    _emit(record)


def _emit(record: dict[str, Any]) -> None:
    """JSON Lines 한 줄을 ``poc_log_file`` 에 append.

    파일 쓰기 실패는 swallow + 표준 로거에 warning 만 남긴다 (운영 영향 0).
    """
    from app.config import get_settings

    settings = get_settings()
    try:
        path = _resolve_path(settings.poc_log_file)
        line = json.dumps(record, ensure_ascii=False)
        with _file_lock, path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        _logger.warning("poc_logger write failed: %s", exc)


def reset_path_cache() -> None:
    """테스트 헬퍼 — 현재 구현은 캐싱이 없지만 향후 확장 대비 placeholder."""
    return


def _clear_log_for_tests(path_override: str | os.PathLike[str] | None = None) -> Path:
    """테스트 헬퍼 — 로그 파일을 truncate 하고 경로를 돌려준다.

    프로덕션 코드에서 호출하지 않는다.
    """
    from app.config import get_settings

    raw = str(path_override) if path_override is not None else get_settings().poc_log_file
    p = _resolve_path(raw)
    p.write_text("", encoding="utf-8")
    return p
