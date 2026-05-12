"""Phase 8 — `metrics_collector` Prometheus 지표 회귀 방지.

세 종류의 시리즈가 운영 대시보드/알림의 근거가 되므로 helper 가 카운터·
히스토그램에 정확히 기록하는지 확인한다:

* ``pii_detect_requests_total{verdict}`` — 전체 / BLOCK 콜 수
* ``ocr_duration_seconds{engine}`` — OCR 엔진별 지연 시간 분포
* ``attachment_size_bytes`` — 첨부 파일 크기 분포

각 테스트는 라이브 Prometheus 레지스트리를 직접 읽고 시작 시점의 스냅샷
대비 변화량을 검증하기 때문에 다른 테스트의 누적값에 영향을 받지 않는다.
"""

from __future__ import annotations

from prometheus_client import REGISTRY

from app.security.metrics_collector import (
    observe_attachment_size,
    observe_detect_request,
    observe_ocr_duration,
)


def _counter(name: str, labels: dict[str, str]) -> float:
    """라벨이 붙은 카운터의 현재 값을 읽는다 (없으면 0.0)."""
    value = REGISTRY.get_sample_value(name, labels)
    return value or 0.0


def _histogram_count(name: str, labels: dict[str, str] | None = None) -> float:
    """히스토그램의 `_count` 시리즈 (총 관측 횟수) 를 읽는다."""
    value = REGISTRY.get_sample_value(f"{name}_count", labels or {})
    return value or 0.0


def _histogram_bucket(name: str, le: str, labels: dict[str, str] | None = None) -> float:
    """히스토그램의 `_bucket{le=...}` 누적 카운트를 읽는다."""
    full_labels = {"le": le, **(labels or {})}
    value = REGISTRY.get_sample_value(f"{name}_bucket", full_labels)
    return value or 0.0


def test_observe_detect_request_increments_pass_and_block_independently() -> None:
    """`verdict=PASS|BLOCK` 라벨이 서로 독립적으로 증가해야 한다.

    같은 카운터에 두 라벨이 묶여 있어 한쪽 호출이 다른 쪽 라벨까지 함께
    올리면 운영 통계가 왜곡된다. PASS 2회 + BLOCK 1회 호출이 각각 +2 / +1
    로 떨어지는지 델타로 측정.
    """
    pass_before = _counter("pii_detect_requests_total", {"verdict": "PASS"})
    block_before = _counter("pii_detect_requests_total", {"verdict": "BLOCK"})

    observe_detect_request(verdict="PASS")
    observe_detect_request(verdict="PASS")
    observe_detect_request(verdict="BLOCK")

    pass_after = _counter("pii_detect_requests_total", {"verdict": "PASS"})
    block_after = _counter("pii_detect_requests_total", {"verdict": "BLOCK"})

    assert pass_after - pass_before == 2.0
    assert block_after - block_before == 1.0


def test_observe_detect_request_records_processing_and_error() -> None:
    """ACK(PROCESSING) / ERROR verdict 도 각자의 시리즈로 기록되어야 한다.

    PASS / BLOCK 외에도 첨부 비동기 진행 (ACK-3001) 과 에러 경로의 호출
    빈도가 별도 라벨로 노출되어야 SRE 가 "BLOCK 률" 과 "에러률" 을 분리해
    모니터링 할 수 있다.
    """
    proc_before = _counter("pii_detect_requests_total", {"verdict": "PROCESSING"})
    err_before = _counter("pii_detect_requests_total", {"verdict": "ERROR"})

    observe_detect_request(verdict="PROCESSING")
    observe_detect_request(verdict="ERROR")

    assert _counter("pii_detect_requests_total", {"verdict": "PROCESSING"}) - proc_before == 1.0
    assert _counter("pii_detect_requests_total", {"verdict": "ERROR"}) - err_before == 1.0


def test_observe_ocr_duration_records_per_engine() -> None:
    """엔진별 OCR 지연 시간 분포가 따로 누적되어야 한다.

    Paddle 과 vLLM 의 SLA 가 크게 다르므로 한 통에 섞이면 알림 임계값이
    무의미해진다. `engine=vlm` 2회 + `engine=paddle` 1회 호출 후 각 시리즈
    의 관측 횟수 델타가 올바른지 확인.
    """
    vlm_before = _histogram_count("ocr_duration_seconds", {"engine": "vlm"})
    paddle_before = _histogram_count("ocr_duration_seconds", {"engine": "paddle"})

    observe_ocr_duration(engine="vlm", seconds=0.42)
    observe_ocr_duration(engine="vlm", seconds=2.5)
    observe_ocr_duration(engine="paddle", seconds=0.7)

    assert _histogram_count("ocr_duration_seconds", {"engine": "vlm"}) - vlm_before == 2.0
    assert _histogram_count("ocr_duration_seconds", {"engine": "paddle"}) - paddle_before == 1.0


def test_observe_ocr_duration_buckets_observation_correctly() -> None:
    """0.42초 관측은 `le=0.5` 버킷에는 들어가고 `le=0.25` 에는 들어가지 않는다.

    히스토그램 버킷이 누적 카운트 (`le` = 이하 누적) 라는 점을 핀(pin).
    버킷 경계 회귀가 발생하면 P95/P99 알림이 잘못 트리거된다.
    """
    le_025_before = _histogram_bucket("ocr_duration_seconds", "0.25", {"engine": "vlm"})
    le_05_before = _histogram_bucket("ocr_duration_seconds", "0.5", {"engine": "vlm"})

    observe_ocr_duration(engine="vlm", seconds=0.42)

    assert _histogram_bucket("ocr_duration_seconds", "0.25", {"engine": "vlm"}) == le_025_before
    assert _histogram_bucket("ocr_duration_seconds", "0.5", {"engine": "vlm"}) == le_05_before + 1


def test_observe_attachment_size_records_each_call() -> None:
    """첨부 크기 히스토그램이 호출마다 +1 씩 누적되는지.

    2 KiB / 5 MiB / 49 MiB 세 가지 크기를 보내고 관측 횟수 델타가 3 이어야
    한다. 분포 자체 (어떤 버킷에 들어가는지) 는 다음 테스트가 책임.
    """
    count_before = _histogram_count("attachment_size_bytes")

    observe_attachment_size(size_bytes=2048)  # 2 KiB → 첫 번째 버킷
    observe_attachment_size(size_bytes=5 * 1024 * 1024)  # 5 MiB
    observe_attachment_size(size_bytes=49 * 1024 * 1024)  # 50 MiB 상한 부근

    assert _histogram_count("attachment_size_bytes") - count_before == 3.0


def test_observe_attachment_size_buckets_to_correct_le() -> None:
    """5 MiB 관측은 4 MiB 버킷을 통과하지 못하고 더 큰 버킷에 들어간다.

    `le` 누적 정의를 검증: 5 MiB 가 들어왔을 때
      - `le=1 MiB` 카운트는 변하지 않음 (이미 초과)
      - `le=4 MiB` 카운트도 변하지 않음 (5 > 4)
    이 두 조건이 깨지면 첨부 크기 분포 그래프가 비대해 보이는 회귀.
    """
    le_1mb = str(1 * 1024 * 1024)
    le_4mb = str(4 * 1024 * 1024)

    le_1mb_before = _histogram_bucket("attachment_size_bytes", le_1mb)
    le_4mb_before = _histogram_bucket("attachment_size_bytes", le_4mb)

    observe_attachment_size(size_bytes=5 * 1024 * 1024)

    assert _histogram_bucket("attachment_size_bytes", le_1mb) == le_1mb_before
    # 5 MiB > 4 MiB 이므로 누적 `le=4 MiB` 카운트는 올라가면 안 된다.
    assert _histogram_bucket("attachment_size_bytes", le_4mb) == le_4mb_before


def test_observe_helpers_swallow_exceptions(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """메트릭 헬퍼가 내부 예외를 흡수해 요청 흐름을 막지 않아야 한다.

    Prometheus 클라이언트의 `labels()` 가 어떤 이유로 예외를 던져도 요청
    처리 핫패스가 멈추면 안 된다 — 관측 실패는 운영 데이터 손실이지
    서비스 장애가 되어선 안 된다. 강제 예외 주입 후 `observe_detect_request`
    호출이 silent 통과하는지 확인.
    """
    from app.security import metrics_collector as mc

    def _boom(*_a: object, **_kw: object) -> None:
        raise RuntimeError("simulated metric failure")

    monkeypatch.setattr(mc.PII_DETECT_REQUESTS_TOTAL, "labels", _boom)
    # 예외가 호출자에게 새어나가면 안 된다.
    observe_detect_request(verdict="PASS")
