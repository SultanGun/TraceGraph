"""Database engine, connection pooling, and SQLite foreign key configuration."""

import logging
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from tracegraph.core.exceptions import DatabaseError, DatabaseIntegrityError
from tracegraph.storage.schema import Base

logger = logging.getLogger(__name__)


def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:
    """Enforce SQLite foreign key constraints on every new connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_sqlite_url(db_path: Path | str) -> str:
    """Format safe SQLite URL from file path."""
    resolved = Path(db_path).resolve()
    # Normalize Windows backslashes for sqlite URL
    as_posix = resolved.as_posix()
    return f"sqlite:///{as_posix}"


def create_storage_engine(db_path: Path | str, echo: bool = False) -> Engine:
    """Create SQLAlchemy engine with enforced SQLite foreign keys."""
    url = get_sqlite_url(db_path)
    engine = create_engine(url, echo=echo, future=True)
    event.listen(engine, "connect", _set_sqlite_pragma)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create configured session factory."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_database(engine: Engine) -> None:
    """Create all tables in schema."""
    try:
        Base.metadata.create_all(engine)
    except SQLAlchemyError as e:
        logger.error("Failed to initialize database tables: %s", e)
        raise DatabaseError(f"Database table creation failed: {e}") from e


def check_connection(engine: Engine) -> bool:
    """Verify database connectivity and foreign key pragma."""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA foreign_keys;"))
            fk_enabled = result.scalar()
            return bool(fk_enabled == 1)
    except Exception as e:
        logger.debug("Database connection check failed: %s", e)
        return False


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Transactional session context manager with automatic rollback on error."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        # Differentiate integrity errors from general database errors
        err_str = str(e)
        if "UNIQUE constraint failed" in err_str or "FOREIGN KEY constraint failed" in err_str:
            raise DatabaseIntegrityError(f"Database constraint violation: {e}") from e
        raise DatabaseError(f"Database transaction failed: {e}") from e
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
