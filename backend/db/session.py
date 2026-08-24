"""
backend/db/session.py
---------------------
SQLAlchemy engine, session factory, and FastAPI `get_db` dependency.

Credentials are loaded from the project-root `.env` file via python-dotenv.
The DATABASE_URL environment variable takes precedence over the built-in default.
Default: postgresql://admin:rootpassword@localhost:5432/chimera_soc
"""

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Load variables from .env (project root) into the process environment.
# This is a no-op if .env does not exist (e.g. in CI where vars are injected).
load_dotenv()

# ---------------------------------------------------------------------------
# Connection URL
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql://admin:rootpassword@localhost:5432/chimera_soc",
)

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
_sqlite = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    # SQLite-specific options (used in tests with in-memory DB)
    **(
        {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        }
        if _sqlite
        else {}
    ),
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
def get_db():
    """
    Yield a SQLAlchemy Session for each request and guarantee it is
    closed in the finally block, regardless of success or exception.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def check_db_connection() -> bool:
    """Return True if the database is reachable, False otherwise."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
