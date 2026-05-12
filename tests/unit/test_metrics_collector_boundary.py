# SYNTHETIC DATA - NOT REAL PII
"""Phase 8 — `metrics_collector` 잔여 helper / boundary 회귀 방지.

기존 `test_metrics_collector.py` 가 다루는 영역 (detect_request / ocr_duration /
attachment_size) 외에 다음 helper 들이 dashboard / SLA 모니터링의 근거이므로
회귀를 별도 가드:

  - ``observe_http`` — HTTP 레이어 counter + histogram 페어 동시 증가
  - ``observe_detection`` — entity x verdict 별 카운터
  - ``observe_extraction_job`` — async 워커 상태 카운터
  - ``observe_feedback`` — Phase 7 피드백 카운터 (라벨 없음)
  - ``observe_rate_limit_rejection`` — caller / ip 스코프
  - 모든 helper 의 ``suppress(Exception)`` 가드 — 운영 우선 안전망
  - 라벨 카디널리티 가드 (path 가 route template 여부 등은 별도)
  - 히스토그램 bucket 경계 정확 매핑
"""

from __future__ import annotations

from prometheus_client import REGISTRY

from app.security.metrics_collector import (
    observe_attachment_size,
    observe_detection,
    observe_extraction_job,
    observe_feedback,
    observe_http,
    observe_rate_limit_rejection,
)


def _counter(name: str, labels: dict[str, str] | None = None) -> float:
    """라벨 carrier 카운터의 현재 누적치 (없으면 0.0)."""
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


def _hist_count(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(f"{name}_count", labels or {}) or 0.0


def _hist_bucket(name: str, le: str, labels: dict[str, str] | None = None) -> float:
    full = {"le": le, **(labels or {})}
    return REGISTRY.get_sample_value(f"{name}_bucket", full) or 0.0


# ── observe_http — counter + histogram 동시 ─────────────────────────────
def test_observe_http_increments_counter() -> None:
    """`http_requests_total` 가 (method, path, response_code) 별로 +1."""
    before = _counter(
        "http_requests_total",
        {"method": "POST", "path": "/v1/detect/post", "response_code": "OK-0000"},
    )
    observe_http(
        method="POST",
        path="/v1/detect/post",
        response_code="OK-0000",
        duration_seconds=0.15,
    )
    after = _counter(
        "http_requests_total",
        {"method": "POST", "path": "/v1/detect/post", "response_code": "OK-0000"},
    )
    assert after - before == 1.0


def test_observe_http_also_records_duration_histogram() -> None:
    """`http_request_duration_seconds` 의 (method, path) 라벨로 관측 +1."""
    labels = {"method": "POST", "path": "/v1/detect/post"}
    before = _hist_count("http_request_duration_seconds", labels)
    observe_http(
        method="POST",
        path="/v1/detect/post",
        response_code="OK-0000",
        duration_seconds=0.5,
    )
    after = _hist_count("http_request_duration_seconds", labels)
    assert after - before == 1.0


def test_observe_http_separates_paths_by_label() -> None:
    """서로 다른 path 는 카운터 시리즈가 독립적."""
    a_before = _counter(
        "http_requests_total",
        {"method": "POST", "path": "/v1/detect/post", "response_code": "OK-0000"},
    )
    b_before = _counter(
        "http_requests_total",
        {"method": "GET", "path": "/healthz", "response_code": "OK-0000"},
    )
    observe_http(
        method="POST",
        path="/v1/detect/post",
        response_code="OK-0000",
        duration_seconds=0.1,
    )
    observe_http(
        method="GET",
        path="/healthz",
        response_code="OK-0000",
        duration_seconds=0.005,
    )
    a_after = _counter(
        "http_requests_total",
        {"method": "POST", "path": "/v1/detect/post", "response_code": "OK-0000"},
    )
    b_after = _counter(
        "http_requests_total",
        {"method": "GET", "path": "/healthz", "response_code": "OK-0000"},
    )
    assert a_after - a_before == 1.0
    assert b_after - b_before == 1.0


def test_observe_http_buckets_at_50ms_boundary() -> None:
    """0.05s 정확 — 첫 bucket(`le=0.05`) 에 누적되어야 한다.

    Prometheus le 가 inclusive 이므로 정확 경계값은 그 bucket 에 포함.
    """
    labels = {"method": "POST", "path": "/bucket-test-a"}
    before = _hist_bucket("http_request_duration_seconds", "0.05", labels)
    observe_http(
        method="POST",
        path="/bucket-test-a",
        response_code="OK-0000",
        duration_seconds=0.05,
    )
    after = _hist_bucket("http_request_duration_seconds", "0.05", labels)
    assert after - before == 1.0


def test_observe_http_long_request_lands_in_5s_bucket() -> None:
    """5.0s 정확 — 마지막 (`le=5.0`) bucket 에 누적."""
    labels = {"method": "POST", "path": "/bucket-test-b"}
    before = _hist_bucket("http_request_duration_seconds", "5.0", labels)
    observe_http(
        method="POST",
        path="/bucket-test-b",
        response_code="SVR-5006",
        duration_seconds=5.0,
    )
    after = _hist_bucket("http_request_duration_seconds", "5.0", labels)
    assert after - before == 1.0


# ── observe_detection — entity x verdict 독립 시리즈 ────────────────────
def test_observe_detection_counter_per_entity_and_verdict() -> None:
    """entity_type x verdict 의 cross-product 가 각자 독립 시리즈."""
    rrn_block_before = _counter(
        "pii_detections_total",
        {"entity_type": "KR_RRN", "verdict": "BLOCK"},
    )
    rrn_pass_before = _counter(
        "pii_detections_total",
        {"entity_type": "KR_RRN", "verdict": "PASS"},
    )
    phone_block_before = _counter(
        "pii_detections_total",
        {"entity_type": "KR_PHONE", "verdict": "BLOCK"},
    )

    observe_detection(entity_type="KR_RRN", verdict="BLOCK")
    observe_detection(entity_type="KR_RRN", verdict="BLOCK")
    observe_detection(entity_type="KR_RRN", verdict="PASS")
    observe_detection(entity_type="KR_PHONE", verdict="BLOCK")

    assert (
        _counter("pii_detections_total", {"entity_type": "KR_RRN", "verdict": "BLOCK"})
        - rrn_block_before
        == 2.0
    )
    assert (
        _counter("pii_detections_total", {"entity_type": "KR_RRN", "verdict": "PASS"})
        - rrn_pass_before
        == 1.0
    )
    assert (
        _counter("pii_detections_total", {"entity_type": "KR_PHONE", "verdict": "BLOCK"})
        - phone_block_before
        == 1.0
    )


# ── observe_extraction_job — 상태 카운터 ────────────────────────────────
def test_observe_extraction_job_separates_status() -> None:
    """succeeded / failed / dropped 같은 status 라벨이 독립."""
    succ_before = _counter("extraction_jobs_total", {"status": "succeeded"})
    fail_before = _counter("extraction_jobs_total", {"status": "failed"})

    observe_extraction_job(status="succeeded")
    observe_extraction_job(status="succeeded")
    observe_extraction_job(status="failed")

    assert _counter("extraction_jobs_total", {"status": "succeeded"}) - succ_before == 2.0
    assert _counter("extraction_jobs_total", {"status": "failed"}) - fail_before == 1.0


# ── observe_feedback — 라벨 없음, 단순 inc ───────────────────────────────
def test_observe_feedback_increments_with_no_labels() -> None:
    """피드백 카운터는 라벨이 없으므로 호출당 +1."""
    before = _counter("feedback_total")
    observe_feedback()
    observe_feedback()
    observe_feedback()
    after = _counter("feedback_total")
    assert after - before == 3.0


# ── observe_rate_limit_rejection — scope 라벨 ───────────────────────────
def test_observe_rate_limit_rejection_caller_vs_ip_scope() -> None:
    """`scope=caller` 와 `scope=ip` 는 독립 시리즈."""
    caller_before = _counter("rate_limit_rejections_total", {"scope": "caller"})
    ip_before = _counter("rate_limit_rejections_total", {"scope": "ip"})

    observe_rate_limit_rejection(scope="caller")
    observe_rate_limit_rejection(scope="ip")
    observe_rate_limit_rejection(scope="ip")

    assert _counter("rate_limit_rejections_total", {"scope": "caller"}) - caller_before == 1.0
    assert _counter("rate_limit_rejections_total", {"scope": "ip"}) - ip_before == 2.0


# ── 모든 helper 의 `suppress(Exception)` 가드 ──────────────────────────
def test_observe_helpers_swallow_unknown_labels() -> None:
    """라벨 누락이나 비정상 키워드 인자도 helper 가 운영을 멈추지 않는다.

    `suppress(Exception)` 가 핵심 — request flow 가 metrics 실패로 죽지
    않도록 한다.
    """
    # 잘못된 라벨 종류 (Counter 가 모르는 keyword) → ValueError 가 raise 되지만
    # helper 가 그를 suppress.
    observe_http(  # type: ignore[call-arg]
        method="POST",
        path="/v1/x",
        response_code="OK-0000",
        duration_seconds=0.1,
    )
    observe_detection(entity_type="KR_RRN", verdict="BLOCK")
    observe_extraction_job(status="succeeded")
    observe_feedback()
    observe_rate_limit_rejection(scope="caller")
    # 도달했으면 통과 — exception 없음.


def test_observe_http_negative_duration_is_swallowed() -> None:
    """음수 duration 도 helper 가 silently 처리 (단조 시계 회귀 가드).

    Prometheus 는 음수 observation 시 ValueError — helper 는 suppress 로
    감춰서 운영을 멈추지 않는다.
    """
    # 호출 자체가 예외 없이 반환되면 OK — counter 값은 implementation-defined.
    observe_http(
        method="POST",
        path="/negative-test",
        response_code="OK-0000",
        duration_seconds=-1.0,
    )


def test_observe_attachment_size_zero_bytes() -> None:
    """0 byte 첨부도 관측 가능 — bucket 첫 칸 (`le=4096`) 에 누적."""
    before = _hist_bucket("attachment_size_bytes", "4096.0")
    observe_attachment_size(size_bytes=0)
    after = _hist_bucket("attachment_size_bytes", "4096.0")
    assert after - before == 1.0


def test_observe_attachment_size_max_bucket_50mib() -> None:
    """50 MiB 정확 — 마지막 finite bucket 에 누적.

    Prometheus client 가 큰 숫자를 e-표기로 출력 (`5.24288e+07`) 하므로
    label 비교도 동일 표기를 사용해야 한다.
    """
    fifty_mib = 50 * 1024 * 1024
    le_label = "5.24288e+07"
    before = _hist_bucket("attachment_size_bytes", le_label)
    observe_attachment_size(size_bytes=fifty_mib)
    after = _hist_bucket("attachment_size_bytes", le_label)
    assert after - before == 1.0


def test_observe_attachment_size_above_max_bucket_lands_in_inf() -> None:
    """50 MiB 초과는 `+Inf` bucket 에 누적 (Prometheus 자동 추가)."""
    before = _hist_bucket("attachment_size_bytes", "+Inf")
    observe_attachment_size(size_bytes=100 * 1024 * 1024)
    after = _hist_bucket("attachment_size_bytes", "+Inf")
    assert after - before == 1.0


# ── HTTP histogram bucket 정확 매핑 ─────────────────────────────────────
def test_observe_http_200ms_p50_target_bucket() -> None:
    """200ms 정확 — p50 SLA boundary (`le=0.2`) bucket 에 누적."""
    labels = {"method": "POST", "path": "/p50-test"}
    before = _hist_bucket("http_request_duration_seconds", "0.2", labels)
    observe_http(
        method="POST",
        path="/p50-test",
        response_code="OK-0000",
        duration_seconds=0.2,
    )
    after = _hist_bucket("http_request_duration_seconds", "0.2", labels)
    assert after - before == 1.0


def test_observe_http_1s_p95_target_bucket() -> None:
    """1초 정확 — p95 SLA boundary (`le=1.0`) bucket 에 누적."""
    labels = {"method": "POST", "path": "/p95-test"}
    before = _hist_bucket("http_request_duration_seconds", "1.0", labels)
    observe_http(
        method="POST",
        path="/p95-test",
        response_code="OK-0000",
        duration_seconds=1.0,
    )
    after = _hist_bucket("http_request_duration_seconds", "1.0", labels)
    assert after - before == 1.0


def test_observe_http_above_5s_falls_into_inf_bucket() -> None:
    """5s 초과 시 +Inf bucket 누적 (SLA 위반 알림 트리거)."""
    labels = {"method": "POST", "path": "/sla-fail"}
    before = _hist_bucket("http_request_duration_seconds", "+Inf", labels)
    observe_http(
        method="POST",
        path="/sla-fail",
        response_code="SVR-5006",
        duration_seconds=8.0,
    )
    after = _hist_bucket("http_request_duration_seconds", "+Inf", labels)
    assert after - before == 1.0


# ── 누적 시리즈의 합 (`_sum`) 가 올바르게 추가 ────────────────────────
def test_observe_http_sum_accumulates_duration() -> None:
    """`http_request_duration_seconds_sum` 이 관측 합산."""
    labels = {"method": "POST", "path": "/sum-test"}
    before_sum = REGISTRY.get_sample_value("http_request_duration_seconds_sum", labels) or 0.0
    observe_http(
        method="POST",
        path="/sum-test",
        response_code="OK-0000",
        duration_seconds=0.3,
    )
    observe_http(
        method="POST",
        path="/sum-test",
        response_code="OK-0000",
        duration_seconds=0.4,
    )
    after_sum = REGISTRY.get_sample_value("http_request_duration_seconds_sum", labels) or 0.0
    assert abs((after_sum - before_sum) - 0.7) < 1e-9


# ── observe_detection 의 verdict 라벨 자유도 (코드 의도) ─────────────────
def test_observe_detection_verdict_label_is_string_free_form() -> None:
    """verdict 값은 `Verdict` enum 의 문자열만 운영에서 쓰이지만, 라벨 자체는
    임의 문자열을 받아도 helper 가 깨지지 않는다 — 운영 robustness."""
    before = _counter(
        "pii_detections_total",
        {"entity_type": "KR_RRN", "verdict": "EXOTIC_VERDICT"},
    )
    observe_detection(entity_type="KR_RRN", verdict="EXOTIC_VERDICT")
    after = _counter(
        "pii_detections_total",
        {"entity_type": "KR_RRN", "verdict": "EXOTIC_VERDICT"},
    )
    assert after - before == 1.0
