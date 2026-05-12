"""Phase 0 T0.2 — `/healthz` liveness 응답 회귀 방지.

ASGI 인-프로세스 클라이언트로 healthz 두 변종 (`/healthz`, `/v1/healthz`)
이 200 OK + 최소 페이로드를 응답하는지 검증한다. 외부 LB/쿠버네티스
liveness probe 가 이 엔드포인트를 사용하므로 형식 변경은 곧 배포 사고로
이어진다.
"""

from httpx import AsyncClient


async def test_healthz_returns_ok(client: AsyncClient) -> None:
    """루트 `/healthz` — 단일 `{"status": "ok"}` 응답 형식 핀(pin).

    인증 없이 호출되며 LB/오케스트레이터가 빈번하게 polling 하기에
    페이로드를 최소로 유지해야 한다. 키 추가/제거는 회귀.
    """
    res = await client.get("/healthz")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


async def test_v1_healthz_returns_env(client: AsyncClient) -> None:
    """`/v1/healthz` — 운영자가 환경(`env` 라벨)을 식별할 수 있어야 한다.

    `status` 외에 `env` 키가 추가로 포함되어 dev/stage/prod 어디로 가는
    트래픽인지 즉시 구별 가능. 자세한 의존성 체크는 `/readyz` 가 담당.
    """
    res = await client.get("/v1/healthz")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "env" in body
