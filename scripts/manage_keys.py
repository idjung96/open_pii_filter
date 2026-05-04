"""API 키 JSON 관리 스크립트.

사용법:
  python scripts/manage_keys.py issue --name <이름> [--ip <CIDR,...>]
  python scripts/manage_keys.py list
  python scripts/manage_keys.py disable <key_id>
  python scripts/manage_keys.py enable  <key_id>
  python scripts/manage_keys.py revoke  <key_id>
  python scripts/manage_keys.py load-db          # JSON → PostgreSQL 로드

키 파일: keys/api_keys.json  (git 제외)
"""

from __future__ import annotations

import json
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

KEYS_FILE = Path(__file__).parent.parent / "keys" / "api_keys.json"
KEY_ID_BYTES = 16   # 32 hex chars  (app/security/api_key.py 와 동일)
SECRET_BYTES = 32   # 64 hex chars


# ── JSON 헬퍼 ──────────────────────────────────────────────────────────────

def _load() -> dict[str, Any]:
    if not KEYS_FILE.exists():
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        return {
            "version": 1,
            "description": "PII Detection API - HMAC-SHA256 키 레지스트리",
            "warning": "이 파일에는 비밀 키가 포함됩니다. git에 커밋하지 마십시오.",
            "keys": [],
        }
    return json.loads(KEYS_FILE.read_text(encoding="utf-8"))


def _save(data: dict[str, Any]) -> None:
    KEYS_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _find(data: dict[str, Any], key_id: str) -> dict[str, Any] | None:
    for k in data["keys"]:
        if k["key_id"] == key_id:
            return k
    return None


# ── 서브커맨드 ──────────────────────────────────────────────────────────────

def cmd_issue(name: str, ip_allowlist: list[str] | None = None) -> None:
    """새 키를 발급하고 JSON에 저장합니다. secret은 이 시점에만 출력됩니다."""
    key_id = "k_" + secrets.token_hex(KEY_ID_BYTES)
    secret = secrets.token_hex(SECRET_BYTES)
    now = datetime.now(UTC).isoformat()

    entry: dict[str, Any] = {
        "key_id": key_id,
        "secret": secret,
        "name": name,
        "description": "",
        "rate_per_minute": 60,
        "rate_per_hour": 1000,
        "ip_allowlist": ip_allowlist,
        "is_admin": False,
        "created_by": "admin",
        "created_at": now,
        "enabled": True,
        "revoked_at": None,
    }

    data = _load()
    data["keys"].append(entry)
    _save(data)

    print("키 발급 완료 — secret은 지금 복사하십시오. 이후 복구 불가.")
    print(f"  key_id : {key_id}")
    print(f"  secret : {secret}")
    if ip_allowlist:
        print(f"  ip     : {', '.join(ip_allowlist)}")


def cmd_list() -> None:
    data = _load()
    fmt = "{:<42} {:<24} {:<6} {}"
    print(fmt.format("key_id", "name", "enabled", "created_at"))
    print("-" * 90)
    for k in data["keys"]:
        print(fmt.format(
            k["key_id"],
            k["name"][:23],
            "Y" if k["enabled"] else "n",
            k["created_at"],
        ))


def cmd_disable(key_id: str) -> None:
    data = _load()
    entry = _find(data, key_id)
    if entry is None:
        sys.exit(f"오류: key_id={key_id} 를 찾을 수 없습니다.")
    entry["enabled"] = False
    _save(data)
    print(f"비활성화: {key_id}")


def cmd_enable(key_id: str) -> None:
    data = _load()
    entry = _find(data, key_id)
    if entry is None:
        sys.exit(f"오류: key_id={key_id} 를 찾을 수 없습니다.")
    entry["enabled"] = True
    _save(data)
    print(f"활성화: {key_id}")


def cmd_revoke(key_id: str) -> None:
    data = _load()
    entry = _find(data, key_id)
    if entry is None:
        sys.exit(f"오류: key_id={key_id} 를 찾을 수 없습니다.")
    entry["enabled"] = False
    entry["revoked_at"] = datetime.now(UTC).isoformat()
    _save(data)
    print(f"폐기(revoke): {key_id}")


def cmd_load_db() -> None:
    """JSON의 키를 PostgreSQL (pii.api_keys) 에 upsert합니다."""
    import asyncio

    async def _run() -> None:
        from app.db.session import get_sessionmaker
        from app.db.models import ApiKey
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        data = _load()
        sm = get_sessionmaker()
        async with sm() as session:
            for entry in data["keys"]:
                stmt = (
                    pg_insert(ApiKey)
                    .values(
                        key_id=entry["key_id"],
                        secret=entry["secret"],
                        name=entry["name"],
                        ip_allowlist=entry.get("ip_allowlist"),
                        rate_per_minute=entry["rate_per_minute"],
                        rate_per_hour=entry["rate_per_hour"],
                        enabled=entry["enabled"],
                        is_admin=entry.get("is_admin", False),
                        created_by=entry.get("created_by", "import"),
                    )
                    .on_conflict_do_update(
                        index_elements=["key_id"],
                        set_={
                            "secret": entry["secret"],
                            "enabled": entry["enabled"],
                            "name": entry["name"],
                        },
                    )
                )
                await session.execute(stmt)
            await session.commit()
        print(f"완료: {len(data['keys'])}개 키를 DB에 upsert 했습니다.")

    asyncio.run(_run())


# ── 진입점 ─────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0]

    if cmd == "issue":
        name = None
        ip_list = None
        i = 1
        while i < len(args):
            if args[i] == "--name" and i + 1 < len(args):
                name = args[i + 1]; i += 2
            elif args[i] == "--ip" and i + 1 < len(args):
                ip_list = [c.strip() for c in args[i + 1].split(",") if c.strip()]
                i += 2
            else:
                i += 1
        if not name:
            sys.exit("오류: --name 옵션이 필요합니다.")
        cmd_issue(name, ip_list)

    elif cmd == "list":
        cmd_list()

    elif cmd == "disable" and len(args) >= 2:
        cmd_disable(args[1])

    elif cmd == "enable" and len(args) >= 2:
        cmd_enable(args[1])

    elif cmd == "revoke" and len(args) >= 2:
        cmd_revoke(args[1])

    elif cmd == "load-db":
        cmd_load_db()

    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
