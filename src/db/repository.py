from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from src.db.models import IncidentModel, UserModel
from src.db.database import Base, engine, SessionLocal

# Initialize tables (auto-provisions incidents and users tables)
Base.metadata.create_all(bind=engine)

class IncidentRepository:
    @staticmethod
    def save_incident(incident_dict: Dict[str, Any], db: Session = None) -> IncidentModel:
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True

        try:
            rca = incident_dict.get("rca", {})
            guardrail = incident_dict.get("guardrail", {})
            rollback = incident_dict.get("rollback", {}) or {}
            health = incident_dict.get("health", {}) or {}
            commit = incident_dict.get("commit", {})

            incident = IncidentModel(
                incident_id=incident_dict["incident_id"],
                timestamp=incident_dict.get("timestamp"),
                service_name=incident_dict["service_name"],
                severity=incident_dict.get("severity", "P1"),
                status=incident_dict.get("status", "NEEDS_REVIEW"),
                breaking_commit_sha=rca.get("breaking_commit_sha", commit.get("sha")),
                previous_commit_sha=commit.get("previous_sha"),
                commit_author=rca.get("breaking_author", commit.get("author")),
                commit_message=commit.get("message"),
                root_cause_summary=rca.get("root_cause_summary"),
                confidence_score=rca.get("confidence_score", 0.0),
                breaking_file=rca.get("breaking_file", ""),
                matched_runbooks=rca.get("matched_runbooks", []),
                mitigation_steps=rca.get("mitigation_steps", []),
                guardrail_passed=guardrail.get("passed", False),
                guardrail_blocked_reason=guardrail.get("blocked_reason"),
                rollback_status=rollback.get("status"),
                health_status=health.get("message"),
                raw_error_log=incident_dict.get("error_log", ""),
                redaction_count=incident_dict.get("redactions", 0)
            )
            db.merge(incident)
            db.commit()
            return incident
        finally:
            if should_close:
                db.close()

    @staticmethod
    def get_all_incidents(limit: int = 50) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            records = db.query(IncidentModel).order_by(IncidentModel.timestamp.desc()).limit(limit).all()
            result = []
            for r in records:
                result.append({
                    "incident_id": r.incident_id,
                    "timestamp": r.timestamp,
                    "service_name": r.service_name,
                    "severity": r.severity,
                    "status": r.status,
                    "rca": {
                        "root_cause_summary": r.root_cause_summary,
                        "breaking_commit_sha": r.breaking_commit_sha,
                        "breaking_author": r.commit_author,
                        "breaking_file": r.breaking_file,
                        "confidence_score": r.confidence_score,
                        "matched_runbooks": r.matched_runbooks,
                        "mitigation_steps": r.mitigation_steps
                    },
                    "guardrail": {
                        "passed": r.guardrail_passed,
                        "blocked_reason": r.guardrail_blocked_reason
                    },
                    "rollback": {"status": r.rollback_status, "target_sha": r.previous_commit_sha} if r.rollback_status else None,
                    "health": {"message": r.health_status} if r.health_status else None,
                    "commit": {
                        "sha": r.breaking_commit_sha,
                        "previous_sha": r.previous_commit_sha,
                        "author": r.commit_author,
                        "message": r.commit_message
                    },
                    "error_log": r.raw_error_log,
                    "redactions": r.redaction_count
                })
            return result
        finally:
            db.close()

    @staticmethod
    def update_status(incident_id: str, new_status: str, rollback_result: dict, health_result: dict):
        db = SessionLocal()
        try:
            inc = db.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
            if inc:
                inc.status = new_status
                inc.rollback_status = rollback_result.get("status")
                inc.health_status = health_result.get("message")
                db.commit()
        finally:
            db.close()

class UserRepository:
    @staticmethod
    def get_or_create_user(sub_id: str, email: str, name: str = "SRE Engineer", picture: Optional[str] = None) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter((UserModel.id == sub_id) | (UserModel.email == email)).first()
            if not user:
                user = UserModel(
                    id=sub_id,
                    email=email,
                    name=name,
                    picture=picture
                )
                db.add(user)
                db.commit()
                db.refresh(user)
            else:
                # Update profile info if changed
                if name and user.name != name:
                    user.name = name
                if picture and user.picture != picture:
                    user.picture = picture
                db.commit()
                db.refresh(user)

            return UserRepository._to_dict(user)
        finally:
            db.close()

    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()
            return UserRepository._to_dict(user) if user else None
        finally:
            db.close()

    @staticmethod
    def update_user_config(user_id: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()
            if not user:
                return None

            if "github_token" in config and config["github_token"]:
                user.github_token = config["github_token"].strip()
            if "github_owner" in config:
                user.github_owner = config["github_owner"].strip()
            if "github_repo" in config:
                user.github_repo = config["github_repo"].strip()
            if "github_workflow_id" in config:
                user.github_workflow_id = config["github_workflow_id"].strip()
            if "target_service_url" in config:
                user.target_service_url = config["target_service_url"].strip()
            if "auto_rollback_enabled" in config:
                user.auto_rollback_enabled = bool(config["auto_rollback_enabled"])
            if "min_confidence_threshold" in config:
                user.min_confidence_threshold = float(config["min_confidence_threshold"])
            if "block_on_db_migration" in config:
                user.block_on_db_migration = bool(config["block_on_db_migration"])

            db.commit()
            db.refresh(user)
            return UserRepository._to_dict(user)
        finally:
            db.close()

    @staticmethod
    def _to_dict(user: UserModel) -> Dict[str, Any]:
        # Mask github token for security (only expose last 4 chars)
        masked_token = None
        if user.github_token:
            if len(user.github_token) > 8:
                masked_token = "****" + user.github_token[-4:]
            else:
                masked_token = "****"

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
            "created_at": user.created_at,
            "has_github_token": bool(user.github_token),
            "github_token_masked": masked_token,
            "github_owner": user.github_owner or "",
            "github_repo": user.github_repo or "",
            "github_workflow_id": user.github_workflow_id or "deploy.yml",
            "target_service_url": user.target_service_url or "",
            "auto_rollback_enabled": user.auto_rollback_enabled,
            "min_confidence_threshold": user.min_confidence_threshold,
            "block_on_db_migration": user.block_on_db_migration
        }
