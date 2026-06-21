"""
Shared pytest configuration and fixtures for SENTINEL tests.
Initialises a clean test database and overrides FastAPI database dependencies.
"""
import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from vendor_risk_engine.api.app import app
from vendor_risk_engine.db.database import Base, get_db

TEST_DB_FILE = "./test_sentinel.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{TEST_DB_FILE}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Apply the FastAPI dependency override globally for all tests in the session
app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Initialise database tables once for the entire test session."""
    # Ensure any stale test database is cleared
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except Exception:
            pass

    # Create tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Tear down tables and clean up file
    Base.metadata.drop_all(bind=engine)
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except Exception:
            pass
