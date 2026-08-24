"""
backend/db/database.py
-----------------------
Compatibility shim — re-exports everything from session.py so that
any existing imports (`from backend.db.database import ...`) continue
to work without modification.
"""

from db.session import DATABASE_URL, engine, SessionLocal, get_db, check_db_connection  # noqa: F401
from sqlalchemy.orm import declarative_base

# Shared declarative base (models import this)
Base = declarative_base()

__all__ = [
    "DATABASE_URL",
    "engine",
    "SessionLocal",
    "get_db",
    "check_db_connection",
    "Base",
]
