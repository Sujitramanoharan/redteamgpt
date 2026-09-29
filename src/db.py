"""Database engine and sessions.

Postgres in production, SQLite for development and tests, same code for both.
Schema changes go through Alembic (alembic/versions); never create tables by
hand, or production and development drift apart.
"""
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import settings

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent


class Base(DeclarativeBase):
    pass


def _make_engine():
    url = settings.effective_database_url
    if url.startswith("sqlite"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(conn, _record):
            cur = conn.cursor()
            # WAL lets readers and the writer work at the same time; the busy
            # timeout makes a second writer wait instead of failing instantly.
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            # SQLite ignores foreign keys unless asked, which would leave
            # orphaned rows when an organisation is deleted.
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine
    # pre_ping drops connections the database closed while idle, which managed
    # Postgres does routinely.
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    """One unit of work: commit on success, roll back on any error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: a session per request."""
    with session_scope() as session:
        yield session


def migrate() -> None:
    """Bring the schema up to date (alembic upgrade head)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.effective_database_url)
    command.upgrade(cfg, "head")


def healthy() -> bool:
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        logger.exception("Database health check failed")
        return False
