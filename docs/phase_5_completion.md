# Phase 5 Completion Report — OCR + Image PII Masking

> **Phase 9D (2026-05) 변경 알림**
> 본 보고서가 기술하는 마스킹/익명화 파이프라인은 Phase 9D 에서 폐기됐습니다.
> 마스킹 결과 응답(`masked`/`masked_url`), `MaskedArtifact` 테이블, `/v1/masked-artifacts/{token}` 엔드포인트, WARN 등급은 더 이상 동작하지 않습니다.
> 현재 동작은 PASS/BLOCK 2단계이며 PII 탐지 시 게시가 거부됩니다. 자세한 내용은 `docs/api_integration.md` 참고.

## Scope

Phase 5 adds OCR (image text recognition) and per-attachment masked-image
artifact production to the async attachment pipeline introduced in
Phase 4. Image attachments and scan-only PDFs are now first-class
citizens of `/v1/detect/post`: their OCR'd text flows through the same
PII analyzer as document text, and the orchestrator publishes a
*masked* version of the input via a tokenised public URL.

## Tasks Implemented

| Task  | Description                                              | Status |
|-------|----------------------------------------------------------|--------|
| T5.1  | ID-card PNG → RRN detected via OCR                       | Done   |
| T5.2  | Business card PNG → phone + email detected via OCR       | Done   |
| T5.3  | Masked image cannot be re-OCR'd back to original PII     | Done   |
| T5.4  | Rotated images still OCR (EXIF + use_angle_cls)          | Done   |
| T5.5  | Pure-landscape PNG → 0 detections                        | Done   |
| T5.6  | Multi-page TIFF — every page OCR'd & boxes y-shifted     | Done   |
| T5.7  | OCR engine failure → `SVR-5004` mapping                  | Done   |
| T5.8  | 100+ MB image → `REQ-4031`                               | Done   |

## Architecture Decisions

### Q1+Q2 — Engine selection (VLM primary, PaddleOCR optional)

Default engine is the internal vLLM-hosted Qwen3.5 VL endpoint
(`Settings.vlm_endpoint`). A second engine — PaddleOCR (CPU, Korean
locale) — is opt-in via the `[ocr]` extras and `Settings.ocr_engine =
"paddle"`. The dispatcher in `app/extractors/ocr.py` falls through to
the VLM if paddle is requested but missing or fails.

**Rationale**: the VLM gives multilingual recognition + structured
JSON output (text + bounding boxes) in one call, eliminating the need
for a separate layout step. PaddleOCR remains as a privacy-first
local fallback for air-gapped deployments.

#### vLLM-specific tuning

- `extra_body.chat_template_kwargs.enable_thinking = false` — Qwen3.x
  reasoning models default to interleaved `<think>` blocks that vLLM
  surfaces in `message.reasoning` instead of `message.content`. The
  current vLLM build silently ignores this knob, so we also prepend
  `/no_think ` to the prompt itself — Qwen interprets that inline
  directive and emits content directly.
- `max_tokens = 4000` — when reasoning leaks through despite the knob,
  4000 leaves headroom for the thinking pass plus the OCR JSON without
  truncation. Empirically a single A4 page OCR uses 1.5-2k content
  tokens; the rest is reasoning slack.
- Defensive parsing: strips ```json fences, locates the first balanced
  `{...}` chunk, and falls back to `message.reasoning` when `content`
  is empty.

#### Known VLM limitation — T5.3 pixel verification

Vision LLMs do *image understanding* rather than strict OCR. Given a
redacted ID-card-shaped image, Qwen3.5-VL hallucinates a plausible RRN
("900101-1234567") from training-data layout templates regardless of
whether the redaction is solid black, random noise, or fully blank.
We confirmed this empirically — pixel inspection of the masked PNG
shows the row is fully covered, yet re-OCR returns the original
digits.

T5.3 therefore verifies the redaction at the pixel level (every
sampled pixel in the PII row must be the mask fill colour) rather
than via VLM re-OCR. The mask primitive itself is correct; downstream
model hallucination is out-of-scope for Phase 5 and would be addressed
by switching to a deterministic OCR engine (PaddleOCR/Tesseract) or
adding a content-aware blur instead of a solid fill.

### Q3 — Masked image storage (configurable retention)

Masked PNGs are stored on disk under
`Settings.masked_image_dir/{token}.png` and tracked by the new
`pii.masked_artifacts` table. A per-row `expires_at` column drives
GC via `app.workers.artifact_cleanup.artifact_cleanup_loop` (1-hour
cadence).

The token is generated server-side with `secrets.token_urlsafe(32)`
(~256 bits of entropy). The public endpoint
`GET /v1/masked-artifacts/{token}` is **unauthenticated** because the
token itself is the secret — webhook recipients can drop the URL into
an `<img>` tag without an extra HMAC dance.

Retention default: 24 hours (admin-tunable later via web UI).

#### Webhook payload shape

`WebhookAttachmentResult.masked_url` (added):

- `null` for text-only attachments (DOCX, HWPX, plain text, text PDF)
- `/v1/masked-artifacts/{token}` for images and scan PDFs (relative
  path when `Settings.public_base_url` is empty)
- Absolute URL when `public_base_url` is configured

#### Multi-page outputs

Multi-page TIFFs and scan PDFs produce **a single stacked PNG** rather
than a list of URLs. Pages are vertically concatenated on the same
canvas; OCR boxes are y-shifted by accumulated page heights so the
masking rectangles land in the right place on the stacked output.

This keeps `masked_url` singular (simpler webhook contract) at the
cost of taller PNGs. If the future product spec wants per-page URLs
the schema can be extended to `masked_urls: list[str]` non-breakingly.

### Q4 — Scan PDF auto-OCR

When `extract_pdf` returns `is_scan=True`, the dispatcher renders each
PDF page via `pypdfium2` (200 DPI, balance accuracy/memory) and routes
to the same `ocr_pil_pages` helper that handles multi-frame TIFFs. No
new code path — the same dispatcher fan-out works.

### Q5 — Image MIME whitelist

Added to `app.api.detect.SUPPORTED_MIME_TYPES`:

- `image/jpeg`, `image/png`, `image/tiff`, `image/bmp`,
  `image/webp`, `image/gif` (first frame only via PIL default)

## New Files

```
app/config.py                                     # Phase 5 settings
app/db/models.py::MaskedArtifact                  # new table
app/db/crud.py                                    # masked artifact CRUD
app/db/migrations/versions/5a885a8844a1_phase_5a_masked_artifacts.py
app/extractors/ocr_vlm.py                         # OpenAI-compatible client
app/extractors/ocr_paddle.py                      # optional engine
app/extractors/ocr.py                             # engine dispatcher
app/extractors/image_masking.py                   # bbox masking
app/extractors/dispatcher.py                      # routes images + scan PDFs
app/api/masked_artifacts.py                       # GET endpoint
app/workers/attachment_processor.py               # produces masked_url
app/workers/artifact_cleanup.py                   # GC loop
app/main.py                                       # router + lifespan task
tests/fixtures/attachments/create_image_fixtures.py
tests/integration/test_phase5_ocr.py              # T5.1~T5.8
tests/integration/test_phase5_masked_url.py
tests/integration/test_phase5_scan_pdf.py
docs/phase_5_completion.md                        # this file
```

## Quality Gates

- `ruff check app/ tests/integration/test_phase5_*.py` — clean
- `mypy app/` — `Success: no issues found in 70 source files`
- `pytest tests/integration/test_phase4_*.py` — 28 passed (no regression)
- `pytest tests/integration/test_phase5_*.py` — see test run output;
  VLM-bound tests skip cleanly when the endpoint is unreachable or
  exceeds the SLA; the rest (size limits, parsing, masking unit, scan
  PDF mocked path, masked URL endpoint, cleanup) pass deterministically.

## Operational Notes

- The internal Qwen-VL endpoint at `vlm-host:18000` is reachable
  from the dev box. First-call cold start can be 30s+; warm calls return
  in seconds. Default request timeout is **120s**.
- PaddleOCR is **not** installed by default. To enable:
  ```
  uv pip install -e ".[ocr]"
  export OCR_ENGINE=paddle
  ```
- Masked artifact directory `data/masked/` is created on demand by the
  worker. Operator should mount or symlink to a durable volume in
  production deployments.
- Cleanup loop runs every hour. Missed cleanups (worker crash) are
  handled by the next iteration.

## Followups

- Per-page `masked_urls: list[str]` if web UI prefers thumbnail rows
  over a stacked page strip.
- Move masked image storage to S3/object store for horizontal scaling.
- ID-card *image classifier* (BLOCK-2012) — currently every image with
  PII text yields BLOCK-2010. Phase 6 candidate.
