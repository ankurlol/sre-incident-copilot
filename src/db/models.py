import time
from sqlalchemy import Column, String, Float, Boolean, Text, Integer, JSON
from src.db.database import Base

class IncidentModel(Base):
    __tablename__ = "incidents"

    incident_id = Column(String(50), primary_key=True, index=True)
    timestamp = Column(String(50), default=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    service_name = Column(String(100), index=True)
    severity = Column(String(10), default="P1")
    status = Column(String(30), default="NEEDS_REVIEW") # RESOLVED, NEEDS_REVIEW, IN_PROGRESS
    
    # Git context
    breaking_commit_sha = Column(String(50))
    previous_commit_sha = Column(String(50))
    commit_author = Column(String(100))
    commit_message = Column(Text)
    
    # RCA Details
    root_cause_summary = Column(Text)
    confidence_score = Column(Float)
    breaking_file = Column(String(200))
    matched_runbooks = Column(JSON, default=list)
    mitigation_steps = Column(JSON, default=list)
    
    # Guardrails & Rollback
    guardrail_passed = Column(Boolean, default=False)
    guardrail_blocked_reason = Column(Text, nullable=True)
    rollback_status = Column(String(50), nullable=True)
    health_status = Column(String(100), nullable=True)
    
    raw_error_log = Column(Text)
    redaction_count = Column(Integer, default=0)

class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(100), primary_key=True, index=True) # Google sub or unique user id
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), default="SRE Engineer")
    picture = Column(String(500), nullable=True)
    created_at = Column(String(50), default=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    # Per-user GitHub Environment settings
    github_token = Column(String(255), nullable=True)
    github_owner = Column(String(100), nullable=True)
    github_repo = Column(String(100), nullable=True)
    github_workflow_id = Column(String(100), default="deploy.yml")
    target_service_url = Column(String(255), nullable=True)
    auto_rollback_enabled = Column(Boolean, default=True)
    min_confidence_threshold = Column(Float, default=0.75)
    block_on_db_migration = Column(Boolean, default=True)
