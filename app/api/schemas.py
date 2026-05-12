"""요청/응답 envelope Pydantic 모델 (§2.2 / §2.3).

이 모듈은 OpenAPI / Swagger 가 자동 생성하는 스키마의 단일 진실 원천이다.
모든 외부 호출은 여기에 정의된 envelope 를 따르고, Field description /
example 이 Swagger UI 의 inline 도움말로 그대로 노출된다.

주요 모델:
  - 요청 — `DetectPostRequest` (author / post / attachments / callback_url /
    options): 모든 외부 호출의 표준 envelope
  - 응답 — `DetectPostResponse` (verdict / code / detections / body_result /
    job / processing_ms): 모든 응답을 같은 shape 으로 통일
  - webhook — `WebhookPayload` + `WebhookAttachmentResult`: Case C 워커가
    `callback_url` 로 발송하는 페이로드 (detect 응답과 schema 공통화)

스키마 변경 시:
  1. 외부 노출 필드면 docs/api_integration.md 도 함께 갱신
  2. `model_config = ConfigDict(extra="forbid")` 가 켜진 모델은 새 필드를
     자동 거절하므로 호환성 영향 평가 필수
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.codes import Verdict

# 호출자가 보내는 엄격도 선택지 — `low` (0.65 임계) / `medium` (0.78, 기본) /
# `high` (0.88). 게시판 성격에 맞춰 클라이언트가 선택.
Strictness = Literal["low", "medium", "high"]


# ── Request ─────────────────────────────────────────────────────────────────
class Author(BaseModel):
    """게시 작성자 정보 — IP 는 예외 IP / 발신지 통계에 사용.

    이름과 IP 만 필수, 나머지는 선택. 익명 게시판은 `is_anonymous=True`
    + 임의의 닉네임을 보내면 된다.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="작성자 표시명 — 익명 게시판이라도 임의 식별 라벨 (예: '익명123') 을 채워 보낸다.",
        examples=["홍길동"],
    )
    user_id: str | None = Field(
        default=None,
        max_length=100,
        description="작성자 계정 ID (해시 등 — 선택). 통계 집계 단위로 사용.",
        examples=["u_001"],
    )
    ip: str = Field(
        ...,
        min_length=1,
        max_length=45,
        description="작성자 발신 IP — IPv4 또는 IPv6. 예외 IP 매칭과 audit 통계에 사용.",
        examples=["203.0.113.5"],
    )
    is_anonymous: bool = Field(
        default=False,
        description="익명 게시판 호출 여부. `name` / `user_id` 의 의미를 호출자가 라벨링 할 수 있게 보조.",
    )


# 본문 / 제목 길이 한도 — 엔드포인트에서 직접 체크해 pydantic 의 422 대신
# 의도된 REQ-4030 (HTTP 413) 으로 매핑한다.
MAX_TITLE_LEN = 500
MAX_BODY_LEN = 50_000


class Post(BaseModel):
    """검사 대상 게시글 본체 — board_id / title / body 3종."""

    board_id: str = Field(
        ...,
        max_length=64,
        description="게시판 식별자 — strictness override 등 정책 매핑의 기준 키.",
        examples=["free", "qna", "complaint"],
    )
    title: str = Field(
        ...,
        description=f"게시글 제목. {MAX_TITLE_LEN}자 초과 시 REQ-4030 (HTTP 413).",
        examples=["문의 드립니다"],
    )
    body: str = Field(
        ...,
        description=f"게시글 본문. {MAX_BODY_LEN:,}자 초과 시 REQ-4030 (HTTP 413).",
        examples=["문의사항은 010-0000-1234 로 연락 부탁드립니다."],
    )


class Attachment(BaseModel):
    """첨부파일 메타데이터 — 워커가 `fetch_url` 로 직접 다운로드.

    실제 파일은 호출자의 스토리지에 있고, API 서버는 인덱스만 받아 비동기
    워커에서 fetch → sha256 검증 → 분석을 수행. `attachment_id` 는 호출자가
    임의 발급하며 응답 / webhook 에서 그대로 echo 된다.
    """

    attachment_id: str = Field(
        ...,
        max_length=64,
        description="호출자가 발급한 첨부 식별자 (UUID 또는 슬러그). 응답/webhook 에서 echo 된다.",
        examples=["att_a1b2c3d4"],
    )
    filename: str = Field(
        ...,
        max_length=255,
        description="원본 파일명 (한글 가능). deny-list 확장자 매칭 대상.",
        examples=["resume.pdf"],
    )
    size_bytes: int = Field(
        ...,
        ge=0,
        description="파일 바이트 크기. 20 MiB 초과 시 REQ-4031 (HTTP 413).",
        examples=[204800],
    )
    mime_type: str = Field(
        ...,
        max_length=100,
        description=(
            "MIME 타입. 지원: PDF / DOCX / XLSX / PPTX / 이미지 (PNG/JPEG/TIFF/BMP/WEBP/GIF) / TXT. "
            "HWP/HWPX/ZIP 등은 deny-list 가 일괄 거절 (REQ-4035)."
        ),
        examples=["application/pdf"],
    )
    sha256: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="페이로드의 SHA-256 hex digest. 워커가 다운로드 후 재계산 검증; 불일치 시 REQ-4041.",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )
    fetch_url: str = Field(
        ...,
        max_length=2048,
        description="워커가 파일을 다운로드할 URL. TLS 권장. 호출자가 접근 권한을 관리.",
        examples=["https://storage.example.com/uploads/resume.pdf"],
    )


class Options(BaseModel):
    """검사 옵션 — 현재는 strictness 한 가지."""

    strictness: Strictness = Field(
        default="medium",
        description=(
            "엄격도. **low** = score ≥ 0.65 BLOCK / **medium** = 0.78 (기본) / **high** = 0.88. "
            "게시판 성격 (자유게시판 vs 민원/법무) 에 맞춰 선택."
        ),
    )


class DetectPostRequest(BaseModel):
    """`POST /v1/detect/post` 요청 envelope (§2.2).

    `extra="forbid"` 가 켜져 있어 정의되지 않은 필드는 검증 단계에서 거절된다 —
    호출자 측 오타나 미지원 옵션이 silent 통과하지 않도록 하기 위함.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: UUID = Field(
        ...,
        description=(
            "멱등성 키 (UUID v4). 24h 캐시에 보관되어 동일 ID 재전송 시 원본 응답이 그대로 반환된다. "
            "in-progress 동시 호출은 `REQ-4005` 로 거절."
        ),
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    author: Author = Field(..., description="작성자 메타 — name / IP 필수")
    post: Post = Field(..., description="게시글 본문 — 검사 대상")
    attachments: list[Attachment] | None = Field(
        default=None,
        description=(
            "첨부 목록 (최대 5개). 있으면 Case C 분기 (`callback_url` 필수). "
            '`null` / `[]` / 키 누락은 모두 동일하게 "첨부 없음" 으로 처리.'
        ),
    )
    callback_url: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Case C 의 결과 webhook 수신 URL. 첨부가 있으면 필수. 워커가 HMAC 서명을 붙여 POST 한다 "
            "(canonical = `{ts}\\n{nonce}\\n{POST}\\n{path}\\n{sha256(body)}`)."
        ),
        examples=["https://www.example.com/webhooks/pii"],
    )
    options: Options = Field(default_factory=Options, description="검사 옵션 (strictness 등)")

    @field_validator("attachments", mode="before")
    @classmethod
    def _normalize_attachments(cls, v: object) -> object:
        """§2.8 edge case — `null` 과 `[]` 를 동등하게 취급.

        클라이언트가 어느 표기를 쓰든 결과가 같도록 정규화. 빈 리스트는
        그대로 보존돼 `has_attachments` 가 False 가 된다.
        """
        if v is None:
            return None
        return v

    @property
    def has_attachments(self) -> bool:
        """검사 분기 (Case B vs C) 결정용 헬퍼 — 첨부 1건 이상이면 True."""
        return bool(self.attachments)


# ── Response ────────────────────────────────────────────────────────────────
class Detection(BaseModel):
    """단일 PII 검출 결과 (§2.3).

    응답에 노출되는 정보는 위치(start/end) + 메타데이터뿐이고, **원본 문자열은 절대
    포함되지 않는다** (§2.5 — 평문 PII 비노출 보안 가드).
    """

    field: str = Field(
        description="검출 위치 — `post.body` / `post.title` / `attachment.{id}` 중 하나",
        examples=["post.body"],
    )
    entity_type: str = Field(
        description="검출된 엔티티 종류 (예: KR_RRN / KR_PHONE / EMAIL_ADDRESS / CREDIT_CARD).",
        examples=["KR_RRN"],
    )
    code: str = Field(
        description="이 검출이 매핑된 응답 코드 (예: BLOCK-2001).",
        examples=["BLOCK-2001"],
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="분석기 신뢰도 (0.0~1.0). strictness 임계와 비교해 PASS/BLOCK 분류.",
        examples=[0.95],
    )
    start: int | None = Field(
        default=None,
        description="검출 시작 오프셋 (코드포인트). 첨부에서는 추출 텍스트 기준.",
        examples=[5],
    )
    end: int | None = Field(
        default=None,
        description="검출 끝 오프셋 (exclusive).",
        examples=[18],
    )
    masked_preview: str | None = Field(
        default=None,
        description="**마스킹된** 짧은 미리보기 (예: `900101-*******`). 원본은 절대 포함하지 않음.",
        examples=["900101-*******"],
    )


class JobInfo(BaseModel):
    """Case C 응답의 비동기 작업 포인터 (§2.3, HTTP 202)."""

    job_id: str = Field(
        description="워커가 발급한 작업 ID — `GET /v1/jobs/{job_id}` 로 조회.",
        examples=["job_a1b2c3d4e5f6"],
    )
    status_url: str = Field(
        description="status 조회 URL (상대 경로) — 호출자가 직접 join 가능.",
        examples=["/v1/jobs/job_a1b2c3d4e5f6"],
    )
    estimated_completion_seconds: int = Field(
        description="예상 처리 완료 시간 (초). 폴링 시작 주기 산정에 사용.",
        examples=[30],
    )
    attachment_count: int = Field(description="이 작업이 처리할 첨부 개수.", examples=[1])


class BodyResult(BaseModel):
    """Case C 응답에 임베드되는 본문 검사 요약.

    Case C 에서는 본문이 PASS 라도 첨부 결과로 최종 verdict 가 BLOCK 으로 바뀔
    수 있다. `body_result.verdict` 는 본문 단독 결과를 보존해 호출자가 본문/
    첨부 사고를 구분할 수 있게 한다.
    """

    verdict: Verdict = Field(description="본문 단독 verdict (PASS/BLOCK).")
    code: str = Field(description="본문 응답 코드 (예: OK-0000).")
    detections: list[Detection] = Field(
        default_factory=list, description="본문에서 검출된 PII 목록."
    )


class DetectPostResponse(BaseModel):
    """`POST /v1/detect/post` 통합 응답 envelope (§2.3).

    Case A/B/C 모든 분기에서 같은 shape — 호출자는 `code` 또는 `verdict` 만 보고
    분기 가능. `job` 객체가 채워져 있고 `code == "ACK-3001"` 이면 Case C.
    """

    request_id: UUID = Field(description="요청에 사용된 `request_id` 그대로 echo.")
    verdict: Verdict = Field(
        description="최종 verdict — `PASS` / `BLOCK`. Case C 진행 중 응답은 본문 verdict 를 그대로 노출."
    )
    code: str = Field(
        description="응답 코드 (`OK-0000` / `BLOCK-2xxx` / `ACK-3001` / `REQ-4xxx` / `SVR-5xxx`).",
        examples=["OK-0000"],
    )
    system_message: str = Field(description="운영자/로그용 영문 메시지.")
    user_message: str = Field(
        description="최종 사용자에게 노출할 한국어 안내. **PII 원본·entity 코드·score 등 내부 정보는 절대 포함하지 않는다** (§2.5).",
        examples=["본문에 주민등록번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다."],
    )
    developer_message: str | None = Field(
        default=None,
        description="ERROR (REQ-4xxx / SVR-5xxx) 응답에서만 채워지는 운영자용 진단 메시지.",
    )

    detections: list[Detection] = Field(
        default_factory=list,
        description="본문 + 제목에서 검출된 PII 목록 (첨부 검출은 webhook 또는 jobs API 에서 확인).",
    )

    # Case C 전용 필드
    body_result: BodyResult | None = Field(
        default=None,
        description="Case C 응답에만 채워짐 — 첨부 검사가 진행 중일 때 본문 단독 결과를 별도로 노출.",
    )
    job: JobInfo | None = Field(
        default=None,
        description="Case C 응답에만 채워짐 — 비동기 작업 포인터 (job_id / status_url 등).",
    )

    processed_at: datetime = Field(
        description="서버에서 응답을 생성한 시각 (UTC, ISO 8601).",
    )
    processing_ms: int = Field(
        description="서버 내부 처리 시간 (밀리초). 네트워크 RTT 미포함.",
    )


class WebhookAttachmentResult(BaseModel):
    """첨부 1건의 검사 결과 — webhook payload 와 job status 응답에 공통 사용."""

    attachment_id: str = Field(description="요청 시 호출자가 보낸 attachment_id echo.")
    filename: str = Field(description="요청 시 보낸 파일명 echo.")
    verdict: Verdict = Field(description="이 첨부 단독 verdict — PASS / BLOCK / ERROR.")
    code: str = Field(description="첨부 응답 코드 (예: BLOCK-2010, REQ-4040, OK-0000).")
    detections: list[Detection] = Field(
        default_factory=list,
        description="이 첨부에서 검출된 PII 목록 (`field` 는 `attachment.{id}` 패턴).",
    )


class WebhookPayload(BaseModel):
    """Case C 워커가 `callback_url` 로 발송하는 webhook 본문.

    HMAC 서명 헤더는 `app/workers/webhook_sender.py` 의 canonical 과 함께 붙어
    오고, 본 페이로드는 그 본문이다. 호출자는 본 페이로드의 `verdict` 와
    `attachment_results[].code` 로 사용자에게 안내할 사유를 매핑하면 된다.
    """

    request_id: UUID = Field(description="원본 요청의 request_id (호출자 측 게시물과 연결).")
    job_id: str = Field(description="`/v1/jobs/{job_id}` 와 동일한 ID.")
    verdict: Verdict = Field(description="첨부까지 포함한 최종 verdict — PASS / BLOCK / ERROR.")
    code: str = Field(
        description="최종 응답 코드. 첨부 검사 결과로 BLOCK 인 경우 BLOCK-2008/2010 등이 들어옴."
    )
    user_message: str = Field(description="사용자에게 안내할 한국어 메시지 (PII 평문 미포함).")
    attachment_results: list[WebhookAttachmentResult] = Field(
        default_factory=list,
        description="첨부별 검사 결과 리스트.",
    )
    completed_at: datetime = Field(description="첨부 검사가 끝난 시각 (UTC).")
