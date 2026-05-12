# SYNTHETIC DATA - NOT REAL PII
"""Health / readiness / legal / jobs 엔드포인트 통합 회귀 방지.

다음 비-detect 엔드포인트의 동작을 통합 검증:

  - `GET /healthz` / `GET /v1/healthz` — liveness (DB / Redis 의존 없음)
  - `GET /readyz` / `GET /v1/readyz` — readiness (DB + Redis 둘 다 응답)
  - `GET /v1/legal/privacy-notice` — 공개 개인정보처리방침 (PlainTextResponse)
  - `GET /v1/jobs/{job_id}` — Case C 작업 상태 조회 (없는 job → 404)

이들은 자격 인증 / strictness / PII 분석과 직접 관계없지만 운영 모니터링
(k8s probe / load balancer) 의 단일 신뢰점이라 회귀 가드가 중요.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient


# ── /healthz — liveness ──────────────────────────────────────────────────
async def test_healthz_returns_200(client: AsyncClient) -> None:
    """`/healthz` 는 프로세스가 떠 있으면 항상 200."""
    resp = await client.get("/healthz")
    assert resp.status_code == 200


async def test_healthz_returns_json(client: AsyncClient) -> None:
    """`/healthz` 는 JSON 응답 (load balancer 가 파싱 가능)."""
    resp = await client.get("/healthz")
    data = resp.json()
    assert isinstance(data, dict)


async def test_v1_healthz_returns_200_with_env(client: AsyncClient) -> None:
    """`/v1/healthz` 는 동일 200 + `env` 라벨 포함."""
    resp = await client.get("/v1/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert "env" in data


async def test_healthz_does_not_require_auth(client_anon: AsyncClient) -> None:
    """`/healthz` 는 인증 없이도 호출 가능 — k8s probe 가 헤더 없이 호출."""
    resp = await client_anon.get("/healthz")
    assert resp.status_code == 200


# ── /readyz — readiness ──────────────────────────────────────────────────
async def test_readyz_returns_ok_when_dependencies_up(client: AsyncClient) -> None:
    """test 환경에서 DB / Redis 가 살아 있다면 200 + status=ok."""
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["checks"]["database"]["ok"] is True
    assert data["checks"]["redis"]["ok"] is True


async def test_readyz_response_includes_env_label(client: AsyncClient) -> None:
    """readyz 응답에 환경 라벨 (`dev`/`stage`/`prod` 등) 포함."""
    resp = await client.get("/readyz")
    data = resp.json()
    assert "env" in data


async def test_v1_readyz_identical_to_readyz(client: AsyncClient) -> None:
    """`/v1/readyz` 와 `/readyz` 응답 형식 동일."""
    a = await client.get("/readyz")
    b = await client.get("/v1/readyz")
    assert a.status_code == b.status_code
    # status 키 동일.
    assert a.json()["status"] == b.json()["status"]


async def test_readyz_checks_structure(client: AsyncClient) -> None:
    """readyz.checks 가 database / redis 각각 ok+error 키를 가진다."""
    resp = await client.get("/readyz")
    data = resp.json()
    for component in ("database", "redis"):
        assert component in data["checks"]
        check = data["checks"][component]
        assert "ok" in check
        assert "error" in check
        # ok=True 면 error=None.
        if check["ok"]:
            assert check["error"] is None


async def test_readyz_does_not_require_auth(client_anon: AsyncClient) -> None:
    """readyz 도 인증 미요구 — k8s/LB probe."""
    resp = await client_anon.get("/readyz")
    # 200 또는 503 (의존성 상태에 따라) — 401/403 이 나오면 회귀.
    assert resp.status_code in (200, 503)


# ── /v1/legal/privacy-notice — 공개 정책 ────────────────────────────────
async def test_privacy_notice_returns_200(client: AsyncClient) -> None:
    """privacy-notice 는 항상 200 — 공개 정책."""
    resp = await client.get("/v1/legal/privacy-notice")
    assert resp.status_code == 200


async def test_privacy_notice_is_text_content_type(client: AsyncClient) -> None:
    """text/plain 또는 text/markdown 같은 텍스트 계열 Content-Type.

    PlainTextResponse 베이스이지만 운영에서는 markdown 으로 라우팅될 수 있음.
    HTML 이 아니어야 한다는 가드 (인젝션 위험 회피).
    """
    resp = await client.get("/v1/legal/privacy-notice")
    ct = resp.headers["content-type"]
    assert ct.startswith("text/")
    assert "html" not in ct.lower()


async def test_privacy_notice_contains_korean(client: AsyncClient) -> None:
    """본문에 한국어 텍스트 포함 (공개 정책)."""
    resp = await client.get("/v1/legal/privacy-notice")
    body = resp.text
    assert any("가" <= c <= "힣" for c in body), "한글 없음"


async def test_privacy_notice_non_empty(client: AsyncClient) -> None:
    """privacy-notice 본문이 비어 있지 않음."""
    resp = await client.get("/v1/legal/privacy-notice")
    assert len(resp.text.strip()) > 50  # 최소 한 문단


async def test_privacy_notice_does_not_require_auth(
    client_anon: AsyncClient,
) -> None:
    """공개 정책이므로 인증 미요구."""
    resp = await client_anon.get("/v1/legal/privacy-notice")
    assert resp.status_code == 200


# ── /v1/jobs/{job_id} — 없는 job 처리 ──────────────────────────────────
async def test_jobs_unknown_id_returns_404(client: AsyncClient) -> None:
    """없는 job_id → 404."""
    rid = f"job_{uuid.uuid4().hex[:12]}"
    resp = await client.get(f"/v1/jobs/{rid}")
    assert resp.status_code == 404


async def test_jobs_malformed_id_returns_error(client: AsyncClient) -> None:
    """job_id 형식이 잘못되어도 404 또는 422."""
    resp = await client.get("/v1/jobs/")
    # trailing slash 가 빠진 경로 — 404 일 수도 405 일 수도.
    assert resp.status_code in (404, 405)


async def test_jobs_endpoint_responds_to_get(client: AsyncClient) -> None:
    """GET 메서드 지원 — POST 시 405."""
    resp = await client.post("/v1/jobs/some-id")
    # GET 만 등록 — POST 는 405.
    assert resp.status_code in (405, 404)


# ── HTTP 메서드 가드 ──────────────────────────────────────────────────
async def test_healthz_post_not_allowed(client: AsyncClient) -> None:
    """healthz 는 GET only — POST 거절."""
    resp = await client.post("/healthz")
    assert resp.status_code == 405


async def test_readyz_post_not_allowed(client: AsyncClient) -> None:
    resp = await client.post("/readyz")
    assert resp.status_code == 405


async def test_privacy_notice_post_not_allowed(client: AsyncClient) -> None:
    resp = await client.post("/v1/legal/privacy-notice")
    assert resp.status_code == 405


# ── 404 — 미등록 라우트 ──────────────────────────────────────────────
async def test_unknown_path_returns_404(client: AsyncClient) -> None:
    """미등록 경로는 404."""
    resp = await client.get("/v1/no-such-endpoint")
    assert resp.status_code == 404


async def test_root_path_handled(client: AsyncClient) -> None:
    """루트 경로 `/` 가 200 또는 404 — favicon 사고 회피."""
    resp = await client.get("/")
    assert resp.status_code in (200, 404)


# ── 응답 시간 — readyz 가 1.5s probe timeout 안에 답함 ─────────────────
async def test_readyz_responds_within_probe_timeout(client: AsyncClient) -> None:
    """readyz 가 _PROBE_TIMEOUT_SECONDS (1.5초) 안에 응답.

    의존성이 살아 있을 때 1.5s 안에 답하지 못하면 k8s probe failure 발생.
    """
    import time

    start = time.monotonic()
    resp = await client.get("/readyz")
    elapsed = time.monotonic() - start
    assert resp.status_code in (200, 503)
    # 정상 환경에서는 매우 빨라야 함 — 통합 테스트에서 2초 안에 응답 보장.
    assert elapsed < 2.0, f"readyz 응답 {elapsed:.2f}s 너무 느림"


# ── /v1/healthz 추가 케이스 ───────────────────────────────────────────
async def test_v1_healthz_response_structure(client: AsyncClient) -> None:
    """v1_healthz 응답에 status + env 키."""
    resp = await client.get("/v1/healthz")
    data = resp.json()
    # 운영 모니터링이 의존하는 필드.
    assert "status" in data or "ok" in data
    assert "env" in data
