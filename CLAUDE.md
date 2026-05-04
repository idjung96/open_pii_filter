# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PII Detection & Masking REST API for the 기관 public website bulletin board. Detects and masks personally identifiable information (PII) in post text and attachments (PDF/DOCX/HWP/HWPX/images) before publication. Korean-language focused with Korean-specific PII types (주민등록번호, 운전면허번호, etc.).

Requirements document: `PII_API_Development_Requirements.md` — the single source of truth for all specs. **Internal-only**, not committed to the public repository (see `.gitignore`).

## Tech Stack

- **Framework**: FastAPI (REST API)
- **Async Queue**: Celery + Redis
- **Database**: PostgreSQL 16 + asyncpg, Alembic migrations
- **PII Engine**: Microsoft Presidio (analyzer) + spaCy (ko_core_news_lg, 토크나이저)
- **File Extraction**: pypdfium2 + pdfplumber (PDF), python-docx (DOCX), pyhwpx (HWP/HWPX)
- **OCR**: PaddleOCR (Korean), Pillow (bbox masking)
- **Security**: HMAC-SHA256 + API Key + IP whitelist, pgcrypto (DB encryption), ClamAV (malware scan)
- **Config**: pydantic-settings, environment variables
- **Linting/Types**: ruff, mypy (strict), bandit
- **Package Manager**: uv or poetry (pyproject.toml)

### Banned Libraries (AGPL/license issues)

- PyMuPDF (AGPL-3.0)
- pyhwp / hwp5txt (AGPL-3.0)
- alphagyuu Korean-PII-BERT (license unclear)

New dependencies must be license-checked; AGPL/GPL/SSPL is prohibited for this externally-exposed API.

## Build & Run Commands

```bash
# Environment setup
make setup              # Full local setup (target: <15 min)
docker compose up       # Start PostgreSQL, Redis, ClamAV

# Development
uvicorn app.main:app --reload   # FastAPI dev server
celery -A app.workers worker    # Celery workers

# Quality checks
ruff check .            # Linting
mypy app/               # Type checking (strict)
bandit -r app/          # Security scan

# Testing
pytest tests/                        # All tests
pytest tests/unit/                   # Unit tests only
pytest tests/integration/            # Integration tests
pytest tests/unit/test_something.py  # Single test file
pytest -k "test_name"                # Single test by name

# Pattern management CLI
python -m app.cli pattern add/list/disable

# Synthetic test data generation
python -m tests.fixtures.gen --category rrn --count 1000 --output samples/rrn.txt
```

## Architecture

### Directory Structure

```
pii-api/
├── app/
│   ├── api/           # FastAPI routers (auth, detect, jobs, schemas, responses)
│   ├── core/          # PII engine (analyzer, recognizers, codes, policies)
│   ├── extractors/    # File text extraction (pdf, docx, hwp, ocr, fetcher)
│   ├── workers/       # Celery tasks (text, extract, ocr, callback)
│   ├── db/            # SQLAlchemy models, CRUD, Alembic migrations
│   ├── security/      # HMAC, rate limiting, encryption, idempotency, audit
│   └── config.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/      # Synthetic PII data generator + test samples
│   └── conftest.py
├── deploy/            # Docker, nginx config
└── docs/              # API docs, operations, data flow, privacy notice
```

### Request Flow

Single endpoint `POST /v1/detect/post` handles all cases:

1. **Case A** (HTTP 200): Body contains BLOCK-level PII → immediate rejection, attachments skipped
2. **Case B** (HTTP 200): Body PASS, no attachments → immediate response
3. **Case C** (HTTP 202): Body PASS, has attachments → body result returned immediately, attachments queued for async processing via Celery → results delivered via webhook callback

Routing is determined **solely by attachment presence** (not by size/type/count). Any attachment triggers async mode.

### Response Code System

Codes follow `[CATEGORY]-[4digits]` pattern. Categories: `OK-`, `WARN-` (deprecated since Phase 9D — no longer generated), `BLOCK-`, `ACK-`, `REQ-`, `SVR-`. Codes are permanent identifiers — never reuse or redefine. All codes defined in `app/core/codes.py` as `ResponseCode` dataclass entries in a `CODES` dict.

### Three-tier Strictness

`options.strictness` (low/medium/high) controls score thresholds that determine the BLOCK cutoff for PII detections (PASS/BLOCK 2-tier). Policy mapping: `(entity_type, score_band) → response_code` in `app/core/policies.py`.

### Celery Queue Layout

- `pii.text` — CPU, high concurrency (text analysis)
- `pii.extract` — CPU, memory-heavy (document parsing)
- `pii.ocr` — GPU, concurrency=1 (PaddleOCR)

### Webhook Callbacks

Async results POST to `callback_url` with HMAC signature. Exponential backoff retry (5 attempts: 1s/4s/16s/64s/256s). Results also queryable via `GET /v1/jobs/{job_id}` for 24 hours.

## Development Rules

### Phase Gate Process

Development follows 9 sequential phases (0-8). Each phase has explicit test cases and pass criteria. **Do not start next phase until all current phase tests pass.** Tag completions with `git tag phase-N-complete`.

### Synthetic Test Data (Critical)

- **Never use real PII** — not even developer's own info
- Build the synthetic data generator (`tests/fixtures/synthetic_pii_generator.py`) **before** Phase 1 tests
- Checksum algorithms (RRN, business number, Luhn) must be implemented in Python directly
- Use safe ranges: phone `010-0000-XXXX`, email `@example.com`/`@test.local`, addresses with non-existent numbers
- All fixture files must have `# SYNTHETIC DATA - NOT REAL PII` header
- CI includes `real_pii_scan.py` to block accidental real PII in fixtures

### Privacy Requirements

- PII plaintext must **never** appear in logs, metrics, traces, or unencrypted DB columns
- `user_message` must not expose: exact position, confidence score, algorithm name, entity type codes, or masked PII values
- `developer_message` only populated for ERROR category responses
- Detection results encrypted with pgcrypto AES; retention default 30 days
- Audit logs are append-only, 1-year retention

### Code Quality

- All code requires type hints (mypy strict mode)
- Public functions require docstrings
- Unit test coverage > 80%
- Conventional Commits format for commit messages
- Phase completion reports in `docs/phase_N_completion.md`

### Idempotency

`request_id` (UUID v4) cached for 24 hours. Duplicate requests return the original response. In-progress duplicates return `REQ-4005`.
