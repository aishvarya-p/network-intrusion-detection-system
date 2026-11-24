"""
Database initialization and session management using SQLAlchemy and SQLite.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.config import DATABASE_URL

# Create SQLAlchemy engine for SQLite.
# 'check_same_thread=False' allows multiple threads to interact with the connection,
# which is needed for FastAPI request handling.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base for models
Base = declarative_base()


def get_db():
    """
    Yields a database session and ensures it is safely closed after use.
    Can be used as a FastAPI dependency or context manager.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Creates all registered database tables in the SQLite database.
    Safe to run repeatedly; existing tables will not be dropped or modified.
    """
    # Import models here so Base registers them before creating tables
    import backend.app.models.flow_models  # noqa: F401
    Base.metadata.create_all(bind=engine)
