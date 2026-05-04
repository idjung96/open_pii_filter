"""Unit tests for the new Prometheus metrics added in `metrics_collector`.

Three series are exercised:

* ``pii_detect_requests_total{verdict}`` — total + blocked detect calls
* ``ocr_duration_seconds{engine}`` — OCR latency by backend
* ``attachment_size_bytes`` — per-attachment size distribution

Each test reads the live Prometheus registry to confirm the helper
actually moved the right counter / bucket. We measure deltas against
a snapshot so tests do not depend on what other tests left behind.
"""

from __future__ import annotations

from prometheus_client import REGISTRY

from app.security.metrics_collector import (
    observe_attachment_size,
    observe_detect_request,
    observe_ocr_duration,
)


def _counter(name: str, labels: dict[str, str]) -> float:
    """Read a labelled counter's current value (or 0.0 if absent)."""
    value = REGISTRY.get_sample_value(name, labels)
    return value or 0.0


def _histogram_count(name: str, labels: dict[str, str] | None = None) -> float:
    """Read a histogram's `_count` series (number of observations)."""
    value = REGISTRY.get_sample_value(f"{name}_count", labels or {})
    return value or 0.0


def _histogram_bucket(name: str, le: str, labels: dict[str, str] | None = None) -> float:
    """Read a histogram's `_bucket{le=...}` cumulative count."""
    full_labels = {"le": le, **(labels or {})}
    value = REGISTRY.get_sample_value(f"{name}_bucket", full_labels)
    return value or 0.0


def test_observe_detect_request_increments_pass_and_block_independently() -> None:
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
    """ACK (PROCESSING) and ERROR verdicts must each register as their own series."""
    proc_before = _counter("pii_detect_requests_total", {"verdict": "PROCESSING"})
    err_before = _counter("pii_detect_requests_total", {"verdict": "ERROR"})

    observe_detect_request(verdict="PROCESSING")
    observe_detect_request(verdict="ERROR")

    assert _counter("pii_detect_requests_total", {"verdict": "PROCESSING"}) - proc_before == 1.0
    assert _counter("pii_detect_requests_total", {"verdict": "ERROR"}) - err_before == 1.0


def test_observe_ocr_duration_records_per_engine() -> None:
    vlm_before = _histogram_count("ocr_duration_seconds", {"engine": "vlm"})
    paddle_before = _histogram_count("ocr_duration_seconds", {"engine": "paddle"})

    observe_ocr_duration(engine="vlm", seconds=0.42)
    observe_ocr_duration(engine="vlm", seconds=2.5)
    observe_ocr_duration(engine="paddle", seconds=0.7)

    assert _histogram_count("ocr_duration_seconds", {"engine": "vlm"}) - vlm_before == 2.0
    assert _histogram_count("ocr_duration_seconds", {"engine": "paddle"}) - paddle_before == 1.0


def test_observe_ocr_duration_buckets_observation_correctly() -> None:
    """A 0.42s observation must land in the `le=0.5` bucket but not `le=0.25`."""
    le_025_before = _histogram_bucket("ocr_duration_seconds", "0.25", {"engine": "vlm"})
    le_05_before = _histogram_bucket("ocr_duration_seconds", "0.5", {"engine": "vlm"})

    observe_ocr_duration(engine="vlm", seconds=0.42)

    assert _histogram_bucket("ocr_duration_seconds", "0.25", {"engine": "vlm"}) == le_025_before
    assert _histogram_bucket("ocr_duration_seconds", "0.5", {"engine": "vlm"}) == le_05_before + 1


def test_observe_attachment_size_records_each_call() -> None:
    count_before = _histogram_count("attachment_size_bytes")

    observe_attachment_size(size_bytes=2048)  # 2 KiB → first bucket
    observe_attachment_size(size_bytes=5 * 1024 * 1024)  # 5 MiB
    observe_attachment_size(size_bytes=49 * 1024 * 1024)  # near the 50 MiB ceiling

    assert _histogram_count("attachment_size_bytes") - count_before == 3.0


def test_observe_attachment_size_buckets_to_correct_le() -> None:
    """A 5 MiB observation must clear the 4 MiB bucket but not the 1 MiB one."""
    le_1mb = str(1 * 1024 * 1024)
    le_4mb = str(4 * 1024 * 1024)

    le_1mb_before = _histogram_bucket("attachment_size_bytes", le_1mb)
    le_4mb_before = _histogram_bucket("attachment_size_bytes", le_4mb)

    observe_attachment_size(size_bytes=5 * 1024 * 1024)

    assert _histogram_bucket("attachment_size_bytes", le_1mb) == le_1mb_before
    # 5 MiB > 4 MiB so the cumulative `le=4 MiB` count must NOT advance.
    assert _histogram_bucket("attachment_size_bytes", le_4mb) == le_4mb_before


def test_observe_helpers_swallow_exceptions(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A failing labels() must never propagate; the request flow stays alive.

    We patch the underlying counter so .labels() raises, then call the
    helper. If the suppress wrapper is missing the exception bubbles
    out; we treat any exception as a regression.
    """
    from app.security import metrics_collector as mc

    def _boom(*_a: object, **_kw: object) -> None:
        raise RuntimeError("simulated metric failure")

    monkeypatch.setattr(mc.PII_DETECT_REQUESTS_TOTAL, "labels", _boom)
    # Should not raise.
    observe_detect_request(verdict="PASS")
