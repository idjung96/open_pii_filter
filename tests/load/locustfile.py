# SYNTHETIC DATA - NOT REAL PII
"""Locust scenarios for the PII Detection API (Phase 8, T8.2).

Why Locust
----------
* Pure-Python — re-uses ``app.security.hmac_auth.compute_signature`` so
  the load test exercises the *exact* same canonicalisation the real
  client must implement.
* Distributed-by-default — a single ``locust -f`` command can fan out
  to multiple workers when the box can't sustain the target RPS by itself.

Scenarios
---------
* ``BodyOnlyUser`` (weight=80) — Case A/B traffic; one POST per task.
* ``WithAttachmentUser`` (weight=15) — Case C; the load profile points
  ``fetch_url`` at a public synthetic-PDF mirror so the call exercises
  the full request validation path. The async worker still tries to
  fetch; failures are surfaced per-attachment but don't block the body
  result.
* ``JobPollUser`` (weight=5) — GET /v1/jobs/{id} for previously-created
  jobs. The user remembers job_ids in its session state.

Authentication setup
--------------------
The load runner needs a valid API key. Provide it via environment
variables before running locust:

    export PII_LOAD_API_KEY=<key_id>
    export PII_LOAD_API_SECRET=<secret>
    uv run locust -f tests/load/locustfile.py --host http://127.0.0.1:8000

If the variables are missing the script falls back to *unauthenticated*
calls — useful when the target deployment runs with the conftest stub
auth (e.g. an ASGI smoke run inside the same Python process).

Synthetic data only
-------------------
Every payload is generated via ``tests.fixtures.synthetic_pii_generator``.
Per the Phase 0 directive, real PII is never sent — even in load.
"""

from __future__ import annotations

import contextlib
import json
import os
import random
import time
import uuid
from typing import Any

from locust import HttpUser, between, events, task

# Import from app/ — locust runs in the same venv as the API.
from app.security.hmac_auth import compute_signature
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

_DEFAULT_BOARD = "general"
_PII_TYPES = ["KR_PHONE", "EMAIL_ADDRESS", "KR_BANK_ACCOUNT", "PERSON"]
_BLOCK_PII_TYPES = ["KR_RRN", "CREDIT_CARD"]


def _signed_headers(
    *,
    key_id: str | None,
    secret: str | None,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    """Build the four HMAC headers; return empty dict when key not set."""
    if not key_id or not secret:
        return {"content-type": "application/json"}
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret,
        timestamp=ts,
        nonce=n,
        method=method,
        path=path,
        body=body,
    )
    return {
        "content-type": "application/json",
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
    }


def _gen_body(
    *,
    rng: SyntheticPIIGenerator,
    block_chance: float = 0.05,
) -> dict[str, Any]:
    """Build a synthetic detect-post body. ``block_chance`` controls the
    fraction of generated requests that will trip a BLOCK verdict."""
    if random.random() < block_chance:
        types = [random.choice(_BLOCK_PII_TYPES)]
    elif random.random() < 0.4:
        types = [random.choice(_PII_TYPES)]
    else:
        types = []

    if types:
        sample = rng.gen_post_sample(entity_types=types)
        title, body = sample["title"], sample["body"]
    else:
        title, body = "공지사항", "오늘 회의는 14시에 진행됩니다. 모두 참석 부탁드립니다."

    return {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": _DEFAULT_BOARD, "title": title, "body": body},
        "author": {"name": "테스터", "ip": "127.0.0.1"},
    }


# ── Body-only traffic — Case A/B ──────────────────────────────────────────
class BodyOnlyUser(HttpUser):
    """Most common case — one POST per task, no attachments."""

    wait_time = between(0.05, 0.2)
    weight = 80

    def on_start(self) -> None:
        self._key_id = os.environ.get("PII_LOAD_API_KEY")
        self._secret = os.environ.get("PII_LOAD_API_SECRET")
        self._rng = SyntheticPIIGenerator(seed=random.randint(1, 1_000_000))

    @task
    def post_detect(self) -> None:
        body = _gen_body(rng=self._rng)
        raw = json.dumps(body).encode("utf-8")
        headers = _signed_headers(
            key_id=self._key_id,
            secret=self._secret,
            method="POST",
            path="/v1/detect/post",
            body=raw,
        )
        with self.client.post(
            "/v1/detect/post",
            data=raw,
            headers=headers,
            name="POST /v1/detect/post (body-only)",
            catch_response=True,
        ) as resp:
            if resp.status_code in {200, 202}:
                resp.success()
            else:
                resp.failure(f"unexpected status {resp.status_code}: {resp.text[:120]}")


# ── Attachment traffic — Case C ──────────────────────────────────────────
class WithAttachmentUser(HttpUser):
    """Smaller-volume Case C path. Uses a public test PDF URL — the
    actual fetch may fail in offline test environments; the body result
    still matters."""

    wait_time = between(0.5, 2.0)
    weight = 15

    def on_start(self) -> None:
        self._key_id = os.environ.get("PII_LOAD_API_KEY")
        self._secret = os.environ.get("PII_LOAD_API_SECRET")
        self._rng = SyntheticPIIGenerator(seed=random.randint(1, 1_000_000))

    @task
    def post_with_attachment(self) -> None:
        body = _gen_body(rng=self._rng, block_chance=0.0)
        body["attachments"] = [
            {
                "attachment_id": f"att_{uuid.uuid4().hex[:8]}",
                "filename": "report.pdf",
                "size_bytes": 4096,
                "mime_type": "application/pdf",
                "sha256": "0" * 64,
                "fetch_url": "https://files.example.invalid/report.pdf",
            }
        ]
        body["callback_url"] = "https://callback.example.invalid/hook"
        raw = json.dumps(body).encode("utf-8")
        headers = _signed_headers(
            key_id=self._key_id,
            secret=self._secret,
            method="POST",
            path="/v1/detect/post",
            body=raw,
        )
        with self.client.post(
            "/v1/detect/post",
            data=raw,
            headers=headers,
            name="POST /v1/detect/post (attachment)",
            catch_response=True,
        ) as resp:
            # 202 ACK-3001 is the expected success path; 200 BLOCK is also
            # acceptable when synthetic body data hits a BLOCK code.
            if resp.status_code in {200, 202}:
                resp.success()
                # Stash the job_id for JobPollUser to consume.
                with contextlib.suppress(Exception):
                    payload = resp.json()
                    job = payload.get("job") or {}
                    if job.get("job_id"):
                        _SHARED_JOB_IDS.append(job["job_id"])
                        # Bound the queue.
                        if len(_SHARED_JOB_IDS) > 200:
                            del _SHARED_JOB_IDS[:100]
            else:
                resp.failure(f"unexpected status {resp.status_code}: {resp.text[:120]}")


# ── Job-poll traffic ─────────────────────────────────────────────────────
_SHARED_JOB_IDS: list[str] = []


class JobPollUser(HttpUser):
    """GET /v1/jobs/{id} — only fires when the attachment users have
    populated _SHARED_JOB_IDS."""

    wait_time = between(1.0, 3.0)
    weight = 5

    def on_start(self) -> None:
        self._key_id = os.environ.get("PII_LOAD_API_KEY")
        self._secret = os.environ.get("PII_LOAD_API_SECRET")

    @task
    def poll_job(self) -> None:
        if not _SHARED_JOB_IDS:
            return
        job_id = random.choice(_SHARED_JOB_IDS)
        path = f"/v1/jobs/{job_id}"
        headers = _signed_headers(
            key_id=self._key_id,
            secret=self._secret,
            method="GET",
            path=path,
            body=b"",
        )
        with self.client.get(
            path,
            headers=headers,
            name="GET /v1/jobs/{id}",
            catch_response=True,
        ) as resp:
            # 404 is acceptable — the job may have been pruned by the
            # 24-hour retention vacuum.
            if resp.status_code in {200, 404}:
                resp.success()
            else:
                resp.failure(f"unexpected status {resp.status_code}: {resp.text[:120]}")


# ── Stats hooks ──────────────────────────────────────────────────────────
@events.test_start.add_listener
def _on_start(environment, **_kwargs):  # type: ignore[no-untyped-def]
    print(
        f"\n=== load test starting ===\nhost={environment.host}\n"
        "Set PII_LOAD_API_KEY + PII_LOAD_API_SECRET to enable HMAC signing.\n"
    )


@events.test_stop.add_listener
def _on_stop(environment, **_kwargs):  # type: ignore[no-untyped-def]
    print("\n=== load test finished ===")
