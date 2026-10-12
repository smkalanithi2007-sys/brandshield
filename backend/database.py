import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from models import Base

BASE_DIR = Path(__file__).resolve().parent


def database_url() -> str | URL:
    configured = os.getenv("DATABASE_URL", "sqlite:///./brandshield.db")
    if configured.startswith("postgres://"):
        configured = configured.replace("postgres://", "postgresql+psycopg://", 1)
    elif configured.startswith("postgresql://"):
        configured = configured.replace(
            "postgresql://", "postgresql+psycopg://", 1
        )

    if configured == "sqlite:///./brandshield.db":
        return URL.create("sqlite", database=str(BASE_DIR / "brandshield.db"))
    return configured


engine = create_engine(
    database_url(),
    connect_args={"check_same_thread": False}
    if os.getenv("DATABASE_URL", "").startswith("sqlite:")
    or not os.getenv("DATABASE_URL")
    else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
