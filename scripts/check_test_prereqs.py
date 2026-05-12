#!/usr/bin/env python3
"""테스트 사전 조건 점검 스크립트.

`docs/test_catalog.md` 의 *공통 사전 조건* 절에 명시된 항목을 한 번에 점검
하여 ``pytest tests/unit tests/integration`` 가 부드럽게 통과할 수 있는
환경인지 확인합니다.

점검 항목
---------
1. Python 버전 (>= 3.12)
2. 핵심 런타임 패키지 import 가능 여부 — fastapi / pydantic / sqlalchemy /
   asyncpg / redis / presidio_analyzer / spacy / pypdfium2 / pdfplumber /
   python-docx / openpyxl / python-pptx / lxml / httpx / pillow /
   paddleocr / cryptography / prometheus_client / clamd
3. spaCy 한국어 모델 (``ko_core_news_lg``) 설치 여부
4. PostgreSQL TCP 접근 (``DATABASE_URL`` 호스트:포트 도달성)
5. Redis TCP 접근 (``REDIS_URL`` 호스트:포트 도달성)
6. ClamAV TCP 접근 (``CLAMAV_HOST:CLAMAV_PORT``) — 선택, 없으면 ⚠ 경고
7. VLM 엔드포인트 — 선택. `OCR_ENGINE=paddle` (기본) 이면 SKIP

종료 코드
---------
- 0: 필수 항목 모두 통과 (선택 항목 경고 무관)
- 1: 필수 항목 한 개 이상 실패

사용 예
-------
::

   .venv/bin/python scripts/check_test_prereqs.py
   .venv/bin/python scripts/check_test_prereqs.py --verbose
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent

Status = Literal["ok", "warn", "fail", "skip"]

ICONS: dict[Status, str] = {
    "ok": "✓",
    "warn": "⚠",
    "fail": "✗",
    "skip": "·",
}


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str = ""

    @property
    def required(self) -> bool:
        return self.status == "fail"


def _load_env() -> dict[str, str]:
    """``.env`` 파일을 그대로 파싱 (pydantic-settings 없이 sys-stdlib 만 사용)."""
    env: dict[str, str] = dict(os.environ)
    candidates = [ROOT / ".env", ROOT / ".env.example"]
    for path in candidates:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            env.setdefault(key, value)
        break
    return env


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    """``host:port`` 가 TCP connect 가능한지 확인 (auth 검증은 안 함)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "reachable"
    except OSError as e:
        return False, str(e)


# ── 1. Python 버전 ─────────────────────────────────────────────────────────
def check_python_version() -> CheckResult:
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 12):
        return CheckResult(
            "Python ≥ 3.12",
            "ok",
            f"{sys.version.split()[0]} @ {sys.executable}",
        )
    return CheckResult(
        "Python ≥ 3.12",
        "fail",
        (
            f"{sys.version.split()[0]} (require 3.12+) — "
            "`uv python install 3.12` 또는 conda 환경 재구성"
        ),
    )


# ── 2. 패키지 import ───────────────────────────────────────────────────────
_REQUIRED_PACKAGES = (
    # FastAPI 스택
    ("fastapi", None),
    ("uvicorn", None),
    ("pydantic", None),
    ("pydantic_settings", None),
    ("multipart", None),  # python-multipart
    # DB
    ("sqlalchemy", None),
    ("asyncpg", None),
    ("alembic", None),
    ("redis", None),
    # PII 엔진
    ("presidio_analyzer", None),
    ("spacy", None),
    # 추출
    ("pypdfium2", None),
    ("pdfplumber", None),
    ("docx", "python-docx"),
    ("openpyxl", None),
    ("pptx", "python-pptx"),
    ("lxml", None),
    # OCR / 이미지
    ("paddleocr", None),
    ("paddle", "paddlepaddle"),
    ("PIL", "pillow"),
    # 보안 / 통신
    ("httpx", None),
    ("clamd", None),
    ("cryptography", None),
    ("prometheus_client", None),
)


def check_packages() -> list[CheckResult]:
    out: list[CheckResult] = []
    for module_name, pip_name in _REQUIRED_PACKAGES:
        label = pip_name or module_name
        try:
            mod = import_module(module_name)
        except ImportError as e:
            out.append(
                CheckResult(
                    f"import {label}",
                    "fail",
                    f"{e}. `uv sync` 실행으로 의존성 설치",
                )
            )
            continue
        version = getattr(mod, "__version__", "?")
        out.append(CheckResult(f"import {label}", "ok", version))
    return out


# ── 3. spaCy ko_core_news_lg ──────────────────────────────────────────────
def check_spacy_model() -> CheckResult:
    try:
        import spacy
    except ImportError:
        return CheckResult(
            "spaCy ko_core_news_lg",
            "fail",
            "spacy 미설치 — `uv sync` 후 재시도",
        )
    try:
        nlp = spacy.load("ko_core_news_lg")
    except OSError as e:
        return CheckResult(
            "spaCy ko_core_news_lg",
            "fail",
            f"모델 미설치 — `python -m spacy download ko_core_news_lg` 실행 ({e})",
        )
    return CheckResult(
        "spaCy ko_core_news_lg",
        "ok",
        f"loaded ({nlp.meta.get('name')} v{nlp.meta.get('version')})",
    )


# ── 4. PostgreSQL ─────────────────────────────────────────────────────────
def _parse_dburl(url: str) -> tuple[str, int] | None:
    if not url:
        return None
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 5432
    if host in {"<host>", ""} or "<" in host:
        return None
    return host, port


def check_postgres(env: dict[str, str]) -> CheckResult:
    target = _parse_dburl(env.get("DATABASE_URL", ""))
    if target is None:
        return CheckResult(
            "PostgreSQL 16 (TCP)",
            "fail",
            "DATABASE_URL 이 .env 에 설정되지 않음 (placeholder `<host>` 인 경우 포함)",
        )
    host, port = target
    ok, msg = _tcp_probe(host, port)
    if ok:
        return CheckResult("PostgreSQL 16 (TCP)", "ok", f"{host}:{port} {msg}")
    return CheckResult(
        "PostgreSQL 16 (TCP)",
        "fail",
        f"{host}:{port} 연결 불가 ({msg}) — `docker compose up postgres` 또는 로컬 데몬 확인",
    )


# ── 5. Redis ───────────────────────────────────────────────────────────────
def _parse_redisurl(url: str) -> tuple[str, int] | None:
    if not url:
        return None
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 6379
    if host in {"<host>", ""} or "<" in host:
        return None
    return host, port


def check_redis(env: dict[str, str]) -> CheckResult:
    target = _parse_redisurl(env.get("REDIS_URL", ""))
    if target is None:
        return CheckResult(
            "Redis 7 (TCP)",
            "fail",
            "REDIS_URL 이 .env 에 설정되지 않음 (placeholder `<host>` 인 경우 포함)",
        )
    host, port = target
    ok, msg = _tcp_probe(host, port)
    if ok:
        return CheckResult("Redis 7 (TCP)", "ok", f"{host}:{port} {msg}")
    return CheckResult(
        "Redis 7 (TCP)",
        "fail",
        f"{host}:{port} 연결 불가 ({msg}) — `docker compose up redis` 또는 로컬 데몬 확인",
    )


# ── 6. ClamAV (선택) ───────────────────────────────────────────────────────
def check_clamav(env: dict[str, str]) -> CheckResult:
    host = env.get("CLAMAV_HOST", "").strip()
    port_s = env.get("CLAMAV_PORT", "").strip()
    if not host or host.startswith("<") or not port_s.isdigit():
        return CheckResult(
            "ClamAV (선택)",
            "skip",
            "CLAMAV_HOST 미설정 — 관련 테스트는 자동 skip 됨",
        )
    ok, msg = _tcp_probe(host, int(port_s))
    if ok:
        return CheckResult("ClamAV (선택)", "ok", f"{host}:{port_s} {msg}")
    return CheckResult(
        "ClamAV (선택)",
        "warn",
        f"{host}:{port_s} 연결 불가 ({msg}) — 관련 테스트는 soft-skip",
    )


# ── 7. VLM 엔드포인트 (선택) ───────────────────────────────────────────────
def check_vlm(env: dict[str, str]) -> CheckResult:
    engine = env.get("OCR_ENGINE", "paddle").strip().lower()
    endpoint = env.get("VLM_ENDPOINT", "").strip()
    if engine != "vlm":
        return CheckResult(
            "VLM 엔드포인트 (선택)",
            "skip",
            f"OCR_ENGINE={engine!r} — PaddleOCR 가 기본 엔진이므로 점검 생략",
        )
    if not endpoint or endpoint.startswith("<") or "<" in endpoint:
        return CheckResult(
            "VLM 엔드포인트 (선택)",
            "warn",
            "VLM_ENDPOINT 미설정 — OCR_ENGINE=vlm 이지만 폴백 경로만 동작",
        )
    parsed = urlparse(endpoint)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return CheckResult(
            "VLM 엔드포인트 (선택)",
            "warn",
            f"VLM_ENDPOINT 형식이 잘못됨: {endpoint!r}",
        )
    ok, msg = _tcp_probe(host, port)
    if ok:
        return CheckResult("VLM 엔드포인트 (선택)", "ok", f"{host}:{port} {msg}")
    return CheckResult(
        "VLM 엔드포인트 (선택)",
        "warn",
        f"{host}:{port} 연결 불가 ({msg}) — paddle 폴백 사용 가능",
    )


# ── main ───────────────────────────────────────────────────────────────────
def render(results: list[CheckResult], verbose: bool) -> None:
    pad = max(len(r.name) for r in results) + 2
    for r in results:
        if r.status == "skip" and not verbose:
            continue
        line = f"  {ICONS[r.status]}  {r.name:<{pad}} {r.detail}"
        print(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="skip 항목까지 모두 출력")
    args = parser.parse_args(argv)

    env = _load_env()
    results: list[CheckResult] = []

    print("== Python ==")
    py = check_python_version()
    results.append(py)
    render([py], verbose=True)

    print("\n== 핵심 패키지 ==")
    pkgs = check_packages()
    results.extend(pkgs)
    render(pkgs, verbose=args.verbose or True)

    print("\n== spaCy 모델 ==")
    sp = check_spacy_model()
    results.append(sp)
    render([sp], verbose=True)

    print("\n== 외부 시스템 ==")
    ext = [
        check_postgres(env),
        check_redis(env),
        check_clamav(env),
        check_vlm(env),
    ]
    results.extend(ext)
    render(ext, verbose=True)

    fail = sum(1 for r in results if r.status == "fail")
    warn = sum(1 for r in results if r.status == "warn")
    ok = sum(1 for r in results if r.status == "ok")
    skip = sum(1 for r in results if r.status == "skip")

    print("\n== 요약 ==")
    print(f"  ok={ok}  warn={warn}  fail={fail}  skip={skip}")
    if fail:
        print("\n  ✗ 필수 항목이 통과하지 못했습니다. 위 detail 의 안내대로 환경을 보강하세요.")
        return 1
    print("\n  ✓ 모든 필수 사전 조건 통과 — pytest tests/ 실행 준비 완료.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
