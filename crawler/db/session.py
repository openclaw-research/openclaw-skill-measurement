"""Database engine and session factory.

Reads DATABASE_URL from the environment (via .env or shell export).
Provides SessionLocal for direct session construction and get_session()
as a generator-based context manager suitable for dependency injection.
"""

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

_DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_engine(_DATABASE_URL, echo=False)

# autoflush=False: flushes are triggered explicitly (e.g. after flush() calls in repositories)
# autocommit=False: caller controls transaction boundaries via session.commit()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_session():
    """Yield a database session, committing on success and rolling back on error.

    Intended for use as a generator-based dependency (e.g. with FastAPI's Depends,
    or called directly in a with-statement via contextlib.contextmanager).
    The pipeline.py currently constructs sessions directly via SessionLocal for
    explicit transaction control.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
