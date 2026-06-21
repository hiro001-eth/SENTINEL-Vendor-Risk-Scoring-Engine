"""
SQLAlchemy models for GRC workflows.
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from vendor_risk_engine.db.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="Analyst", nullable=False)  # Admin, Analyst, Executive
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    domain = Column(String, unique=True, index=True, nullable=False)
    contact_email = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AssessmentInvitation(Base):
    __tablename__ = "assessment_invitations"

    token = Column(String, primary_key=True, index=True)
    vendor_id = Column(String, ForeignKey("vendors.id"), nullable=False)
    email = Column(String, nullable=False)
    status = Column(String, default="Pending", nullable=False)  # Pending, Completed, Expired
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)

    vendor = relationship("Vendor")

class RemediationTicket(Base):
    __tablename__ = "remediation_tickets"

    id = Column(Integer, primary_key=True, index=True)
    vendor_id = Column(String, ForeignKey("vendors.id"), nullable=False)
    category_id = Column(String, nullable=False)
    question_id = Column(String, nullable=False)
    priority = Column(String, default="Medium", nullable=False)  # High, Medium, Low
    status = Column(String, default="Open", nullable=False)  # Open, In-Progress, Resolved
    external_key = Column(String, nullable=True)  # e.g. JIRA-1234
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)

    vendor = relationship("Vendor")

class DBRunMetadata(Base):
    __tablename__ = "run_metadata"

    run_id = Column(String, primary_key=True, index=True)
    status = Column(String, default="Running", nullable=False)  # Running, Completed, Failed
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    total_vendors = Column(Integer, default=0)
    total_gaps = Column(Integer, default=0)
    financial_exposure_usd = Column(Float, default=0.0)

class VendorResponse(Base):
    __tablename__ = "vendor_responses"

    id = Column(Integer, primary_key=True, index=True)
    vendor_id = Column(String, ForeignKey("vendors.id"), nullable=False)
    question_id = Column(String, nullable=False)
    response_value = Column(String, nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    vendor = relationship("Vendor")

