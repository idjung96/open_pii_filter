"""Build a Presidio AnalyzerEngine for Korean text.

Wires together:
  - spaCy `ko_core_news_lg` as the NLP tokenizer backbone (NER 미사용)
  - Custom KR recognizers in `app.core.recognizers`
  - Selected Presidio built-ins: Email, CreditCard, IP, URL, IBAN, Crypto

The factory caches a single AnalyzerEngine across the process; constructing
one costs ~1.5 s and we never want that on the request path.

Phase 9E-A — SpacyRecognizer 등록 제거. NER (PERSON/LOCATION/ORGANIZATION)
단독 검출은 일반 게시 컨텐츠에서 오탐 폭증의 원인이 되어 폐기. 정규식 +
체크섬 기반 PII 만으로 법적 위험 커버는 충분. spaCy NLP 엔진 자체는
Presidio AnalyzerEngine 의 토크나이저로 여전히 필요하므로 유지한다.

Phase 9E-B — pii_patterns 테이블 + DB 패턴 통합 헬퍼 제거. deny_list 는
별도 메커니즘으로 보존되며 ``build_analyzer_with_deny_list()`` 가 처리한다.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngine, NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    CryptoRecognizer,
    EmailRecognizer,
    IbanRecognizer,
    IpRecognizer,
    UrlRecognizer,
)

from app.core.recognizers import (
    KrBankAccountStrongRecognizer,
    KrBankAccountWeakRecognizer,
    KrBusinessNumRecognizer,
    KrDriverLicenseRecognizer,
    KrPassportRecognizer,
    KrPhoneRecognizer,
    KrRrnRecognizer,
)
from app.core.recognizers.deny_list import build_deny_list_recognizers

Language = Literal["ko"]


def _make_nlp_engine() -> NlpEngine:
    """Construct the spaCy-backed NLP engine for Presidio.

    Phase 9E-A — NER 결과는 더 이상 사용하지 않지만 Presidio AnalyzerEngine
    이 토크나이저로 NLP 엔진을 요구하므로 spaCy 모델 로드는 유지한다.
    ``model_to_presidio_entity_mapping`` 은 빈 dict 로 두어 NER 라벨이
    Presidio entity 로 변환되지 않게 한다 (혹시라도 누군가 SpacyRecognizer
    를 다시 등록하더라도 라벨 매핑이 없으니 아무 결과도 못 낸다).
    """
    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "ko", "model_name": "ko_core_news_lg"}],
        "ner_model_configuration": {
            "model_to_presidio_entity_mapping": {},
            "labels_to_ignore": ["DT", "TI", "QT", "PS", "LC", "OG"],
        },
    }
    return NlpEngineProvider(nlp_configuration=config).create_engine()


def _disabled_recognizer_names() -> set[str]:
    """system_settings.json 에 등록된 비활성 인식기 클래스명 집합.

    Phase 9F — 대시보드 "패턴" 페이지에서 인식기를 개별 on/off 가능.
    """
    from app.core import system_settings as _ss

    raw = _ss.get("disabled_recognizers")
    if not isinstance(raw, list):
        return set()
    return {str(x) for x in raw}


def _all_recognizer_candidates() -> list[object]:
    """등록 후보 인식기 전체 (커스텀 KR 7개 + Presidio 내장 6개).

    Phase 9F — disabled_recognizers 토글이 어떤 클래스를 끄고 있는지
    대시보드에서 보여주려면 비활성 인식기도 메타정보를 추출할 수 있어야
    하므로 후보 목록을 별도 함수로 분리.

    Phase 9I — 대시보드에서 patterns / context 를 편집한 결과 (system_settings
    의 ``recognizer_overrides``) 를 인스턴스 생성 직후 in-place 로 적용한다.
    """
    from app.core.recognizer_overrides import apply_to

    candidates: list[object] = [
        # Custom Korean recognizers (체크섬 검증 포함, 7개)
        KrRrnRecognizer(),
        KrPhoneRecognizer(),
        KrBusinessNumRecognizer(),
        KrBankAccountStrongRecognizer(),
        KrBankAccountWeakRecognizer(),
        KrDriverLicenseRecognizer(),
        KrPassportRecognizer(),
        # Presidio 내장 정규식 인식기 (언어 무관, 6개)
        EmailRecognizer(supported_language="ko"),
        CreditCardRecognizer(supported_language="ko"),
        IpRecognizer(supported_language="ko"),
        UrlRecognizer(supported_language="ko"),
        IbanRecognizer(supported_language="ko"),
        CryptoRecognizer(supported_language="ko"),
    ]
    for r in candidates:
        apply_to(r)
    return candidates


def _make_registry() -> RecognizerRegistry:
    """Registry containing custom KR recognizers + selected Presidio built-ins.

    Phase 9E-A — SpacyRecognizer (NER) 등록 제거.
    Phase 9F — system_settings 의 disabled_recognizers 에 포함된 인식기는 skip.
    """
    registry = RecognizerRegistry(supported_languages=["ko"])
    disabled = _disabled_recognizer_names()

    for r in _all_recognizer_candidates():
        if type(r).__name__ in disabled:
            continue
        registry.add_recognizer(r)  # type: ignore[arg-type]

    return registry


def inspect_all_candidates() -> list[dict[str, object]]:
    """모든 후보 인식기의 메타데이터 + 현재 활성/비활성 상태 반환.

    Phase 9F — 대시보드 패턴 페이지에서 비활성 인식기도 보여주기 위함.
    Phase 9I — ``has_override`` 필드 추가 (런타임 편집 적용 여부).
    """
    from app.core.recognizer_overrides import has_override

    disabled = _disabled_recognizer_names()
    out: list[dict[str, object]] = []
    for r in _all_recognizer_candidates():
        cls = type(r).__name__
        patterns: list[dict[str, object]] = []
        for p in getattr(r, "patterns", []) or []:
            patterns.append({"name": p.name, "regex": p.regex, "score": p.score})
        out.append(
            {
                "name": getattr(r, "name", cls),
                "class": cls,
                "module": type(r).__module__,
                "source": _classify_source(r),
                "supported_entities": list(getattr(r, "supported_entities", [])),
                "supported_language": getattr(r, "supported_language", None),
                "context_words": list(getattr(r, "context", []) or []),
                "patterns": patterns,
                "enabled": cls not in disabled,
                "has_override": has_override(cls),
            }
        )
    return out


@lru_cache(maxsize=1)
def build_analyzer() -> AnalyzerEngine:
    """Return the singleton Korean Presidio AnalyzerEngine."""
    return AnalyzerEngine(
        nlp_engine=_make_nlp_engine(),
        registry=_make_registry(),
        supported_languages=["ko"],
    )


def reset_analyzer_cache() -> None:
    """Clear the cached AnalyzerEngine (used by tests for clean state)."""
    build_analyzer.cache_clear()


async def build_analyzer_with_deny_list(session: object) -> AnalyzerEngine:
    """Build an AnalyzerEngine combining the static recognizer set + deny list.

    Phase 9E-B — pii_patterns 인프라가 폐기되어 DB 에서 가져오는 행은
    ``pii_deny_list`` 만이다. deny_list 는 사용자 요청 범위 밖 별도
    메커니즘으로 보존된다 (T2.6 — 직원 명단 등 정확 일치 매칭).
    """
    # Lazy import to avoid pulling SQLAlchemy into hot test paths.
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.crud import list_deny_entries

    if not isinstance(session, AsyncSession):
        msg = "build_analyzer_with_deny_list requires an AsyncSession"
        raise TypeError(msg)

    registry = _make_registry()
    deny_rows = await list_deny_entries(session)
    for r in build_deny_list_recognizers(deny_rows):
        registry.add_recognizer(r)

    return AnalyzerEngine(
        nlp_engine=_make_nlp_engine(),
        registry=registry,
        supported_languages=["ko"],
    )


# ── 대시보드용 인식기 introspection ────────────────────────────────────────
def _classify_source(recognizer: object) -> str:
    """인식기의 출처 분류."""
    mod = type(recognizer).__module__
    name = getattr(recognizer, "name", "") or ""
    if mod.startswith("presidio_analyzer.predefined_recognizers"):
        return "presidio_builtin"
    if mod.startswith("app.core.recognizers"):
        return "custom_kr"
    if name.startswith("denylist::") or name.startswith("deny::"):
        return "db_deny_list"
    # PatternRecognizer 인스턴스인데 이름 prefix 가 없는 경우 — deny-list 가
    # default 명을 쓰는 경우 등. 안전을 위해 db_deny_list 로 분류.
    return "db_deny_list"


def inspect_recognizers(engine: AnalyzerEngine) -> list[dict[str, object]]:
    """엔진에 등록된 모든 인식기 메타데이터를 직렬화."""
    out: list[dict[str, object]] = []
    for r in engine.registry.recognizers:
        patterns: list[dict[str, object]] = []
        for p in getattr(r, "patterns", []) or []:
            patterns.append(
                {
                    "name": p.name,
                    "regex": p.regex,
                    "score": p.score,
                }
            )
        out.append(
            {
                "name": getattr(r, "name", type(r).__name__),
                "source": _classify_source(r),
                "supported_entities": list(getattr(r, "supported_entities", [])),
                "supported_language": getattr(r, "supported_language", None),
                "context_words": list(getattr(r, "context", []) or []),
                "patterns": patterns,
                "class": type(r).__name__,
                "module": type(r).__module__,
            }
        )
    return out
