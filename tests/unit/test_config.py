"""Phase 0 — `.env` 로드 + Settings lru_cache 회귀 방지.

`app.config.get_settings()` 가 환경 변수를 읽어 `Settings` 를 구성하고
프로세스 수명 내내 동일 인스턴스를 재사용하는지 검증한다. 모든 통합
테스트가 이 싱글턴에 의존하므로 여기서 회귀를 1차 방어한다.
"""

from app.config import Settings, get_settings


def test_settings_loads() -> None:
    """필수 환경 변수가 `Settings` 로 빠짐없이 흡수되는지 점검한다.

    검증 포인트:
    - `database_url` (asyncpg) / `database_url_sync` (psycopg2 — Alembic 용) 둘 다 채워짐
    - DB 스키마 기본값 `pii`
    - ClamAV 포트가 0보다 큰 정수로 캐스팅됨 (str → int 변환 회귀 방지)
    """
    s = get_settings()
    assert isinstance(s, Settings)
    assert s.database_url
    assert s.database_url_sync
    assert s.db_schema == "pii"
    assert s.clamav_port > 0


def test_settings_cached() -> None:
    """`get_settings()` 는 lru_cache 로 동일 인스턴스를 돌려줘야 한다.

    매 요청마다 `.env` 를 다시 파싱하면 부하가 커지므로 identity (`is`)
    비교로 캐시 무효화 회귀를 잡는다.
    """
    assert get_settings() is get_settings()
