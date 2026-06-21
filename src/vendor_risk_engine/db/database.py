"""
Database connection and session management using SQLAlchemy.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from vendor_risk_engine.config import get_settings

settings = get_settings()

# For local development we use SQLite. In production, this can be overridden via database URL env variable.
DATABASE_URL = getattr(settings, "database_url", "sqlite:///./output/sentinel.db")

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI dependency for database session injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialise database tables."""
    Base.metadata.create_all(bind=engine)
