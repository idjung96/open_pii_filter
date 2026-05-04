"""`python -m app.cli` — top-level CLI dispatch.

Settings (DATABASE_URL etc.) are loaded eagerly at import time by
``app.db.models``. Wrap the import so a missing ``.env`` produces a
single-line operator-friendly message instead of a pydantic stack trace.
"""

from __future__ import annotations

import sys

if __name__ == "__main__":  # pragma: no cover — invoked via `python -m`
    try:
        from app.cli.main import cli
    except Exception as e:
        msg = str(e)
        if "database_url" in msg.lower():
            sys.stderr.write(
                "환경변수 설정 필요: DATABASE_URL / DATABASE_URL_SYNC\n"
                "프로젝트 루트의 .env 가 로딩되지 않았거나 변수가 없습니다.\n"
            )
            raise SystemExit(2) from None
        sys.stderr.write(f"CLI 초기화 실패: {e}\n")
        raise SystemExit(2) from None
    cli()
