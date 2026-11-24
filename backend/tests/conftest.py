"""
Pytest configuration and shared fixtures.
Uses an in-memory SQLite database with StaticPool to ensure fast, isolated tests across threads.
Provides FastAPI TestClient with dependency overrides.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.api.dependencies import get_detector


@pytest.fixture(scope="function")
def in_memory_engine():
    """
    Creates a fresh in-memory SQLite database engine for each test.
    StaticPool ensures all sessions and FastAPI worker threads share the exact same in-memory DB.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(in_memory_engine):
    """Provides an isolated database session per test."""
    Session = sessionmaker(autocommit=False, autoflush=False, bind=in_memory_engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(in_memory_engine):
    """
    Provides a FastAPI TestClient configured with an in-memory database override.
    Ensures tests never modify the development SQLite database file.
    """
    Session = sessionmaker(autocommit=False, autoflush=False, bind=in_memory_engine)

    def override_get_db():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    # Ensure detector model is loaded/ready
    get_detector()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
