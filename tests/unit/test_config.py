"""Phase 0: Settings loads from .env without crashing."""

from app.config import Settings, get_settings


def test_settings_loads() -> None:
    s = get_settings()
    assert isinstance(s, Settings)
    assert s.database_url
    assert s.database_url_sync
    assert s.db_schema == "pii"
    assert s.clamav_port > 0


def test_settings_cached() -> None:
    assert get_settings() is get_settings()
