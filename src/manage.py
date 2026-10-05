"""Operator commands. Run on the server (Render: Shell tab) or locally.

    python src/manage.py make-admin you@example.com    # grant platform-operator access
    python src/manage.py revoke-admin you@example.com
    python src/manage.py stats
    python src/manage.py disable-user someone@example.com  # sign out + lock indefinitely

Platform admin is deliberately not grantable through the API: an account
takeover of any customer must never be able to escalate to operator.
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import delete, func, select  # noqa: E402

from db import session_scope  # noqa: E402
from models_db import ApiKey, AuditLog, AuthSession, Organization, User  # noqa: E402


def _user(s, email: str) -> User:
    user = s.scalar(select(User).where(User.email == email.strip().lower()))
    if user is None:
        sys.exit(f"No user with email {email}")
    return user


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("make-admin", "revoke-admin", "disable-user"):
        sub.add_parser(name).add_argument("email")
    sub.add_parser("stats")
    args = p.parse_args()

    with session_scope() as s:
        if args.cmd == "make-admin":
            _user(s, args.email).is_platform_admin = True
            print(f"{args.email} is now a platform admin (sign out and back in).")
        elif args.cmd == "revoke-admin":
            _user(s, args.email).is_platform_admin = False
            print(f"{args.email} is no longer a platform admin.")
        elif args.cmd == "disable-user":
            user = _user(s, args.email)
            user.locked_until = datetime.now(timezone.utc) + timedelta(days=36500)
            s.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
            print(f"{args.email} signed out everywhere and locked. "
                  "Their organisation's API keys still work; revoke them separately if needed.")
        elif args.cmd == "stats":
            day = datetime.now(timezone.utc) - timedelta(days=1)
            print(f"organisations     {s.scalar(select(func.count(Organization.id)))}")
            print(f"users             {s.scalar(select(func.count(User.id)))}")
            print(f"active API keys   {s.scalar(select(func.count(ApiKey.id)).where(ApiKey.revoked_at.is_(None)))}")
            print(f"scans, last 24h   {s.scalar(select(func.count(AuditLog.id)).where(AuditLog.timestamp >= day))}")


if __name__ == "__main__":
    main()
