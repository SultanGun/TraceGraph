"""Pytest shared fixtures and isolation configuration."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from tracegraph.collectors.mock import MockDNSCollector
from tracegraph.storage.database import (
    create_session_factory,
    create_storage_engine,
    init_database,
)
from tracegraph.storage.repository import EvidenceRepository
from tracegraph.storage.workspace import init_workspace


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Provide isolated temporary workspace directory."""
    ws = tmp_path / "test_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


@pytest.fixture
def initialized_workspace(tmp_workspace: Path) -> Path:
    """Provide an initialized temporary workspace."""
    init_workspace(tmp_workspace)
    return tmp_workspace


@pytest.fixture
def test_db_engine(tmp_path: Path):
    """Provide an isolated SQLite database engine with foreign keys enforced."""
    db_file = tmp_path / "test.db"
    engine = create_storage_engine(db_file)
    init_database(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def test_session_factory(test_db_engine) -> sessionmaker[Session]:
    """Provide configured session factory for isolated test database."""
    return create_session_factory(test_db_engine)


@pytest.fixture
def evidence_repo(test_session_factory) -> EvidenceRepository:
    """Provide EvidenceRepository instance connected to isolated test database."""
    return EvidenceRepository(test_session_factory)


@pytest.fixture
def mock_dns() -> MockDNSCollector:
    """Provide fresh MockDNSCollector with standard synthetic fixtures."""
    return MockDNSCollector()
