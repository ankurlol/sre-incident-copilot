import uuid
import re
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from src.db.models import IncidentModel, UserModel, ProjectModel
from src.db.database import Base, engine, SessionLocal

# Initialize tables (auto-provisions projects, users, incidents)
Base.metadata.create_all(bind=engine)

class ProjectRepository:
    @staticmethod
    def create_project(user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            name = (data.get("name") or "Untitled Service").strip()
            slug = re.sub(r'[^a-zA-Z0-9_-]', '-', name.lower()).strip('-') or "service"
            project_id = f"proj_{uuid.uuid4().hex[:8]}"

            project = ProjectModel(
                id=project_id,
                user_id=user_id,
                name=name,
                service_slug=slug,
                description=(data.get("description") or "").strip(),
                github_owner=(data.get("github_owner") or "").strip(),
                github_repo=(data.get("github_repo") or "").strip(),
                github_token=(data.get("github_token") or "").strip() if data.get("github_token") else None,
                github_workflow_id=(data.get("github_workflow_id") or "deploy.yml").strip(),
                target_service_url=(data.get("target_service_url") or "").strip(),
                auto_rollback_enabled=bool(data.get("auto_rollback_enabled", True)),
                min_confidence_threshold=float(data.get("min_confidence_threshold", 0.75)),
                block_on_db_migration=bool(data.get("block_on_db_migration", True))
            )
            db.add(project)
            db.commit()
            db.refresh(project)
            return ProjectRepository._to_dict(project)
        finally:
            db.close()

    @staticmethod
    def get_user_projects(user_id: str) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            projects = db.query(ProjectModel).filter(ProjectModel.user_id == user_id).order_by(ProjectModel.created_at.desc()).all()
            return [ProjectRepository._to_dict(p) for p in projects]
        finally:
            db.close()

    @staticmethod
    def get_project_by_id(project_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            query = db.query(ProjectModel).filter(ProjectModel.id == project_id)
            if user_id:
                query = query.filter(ProjectModel.user_id == user_id)
            p = query.first()
            return ProjectRepository._to_dict(p) if p else None
        finally:
            db.close()

    @staticmethod
    def get_project_raw_token(project_id: str) -> Optional[str]:
        db = SessionLocal()
        try:
            p = db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
            return p.github_token if p else None
        finally:
            db.close()

    @staticmethod
    def delete_project(project_id: str, user_id: str) -> bool:
        db = SessionLocal()
        try:
            p = db.query(ProjectModel).filter(ProjectModel.id == project_id, ProjectModel.user_id == user_id).first()
            if p:
                db.delete(p)
                db.commit()
                return True
            return False
        finally:
            db.close()

    @staticmethod
    def _to_dict(p: ProjectModel) -> Dict[str, Any]:
        masked_token = None
        if p.github_token:
            masked_token = "****" + (p.github_token[-4:] if len(p.github_token) > 4 else "")

        return {
            "id": p.id,
            "user_id": p.user_id,
            "name": p.name,
            "service_slug": p.service_slug,
            "description": p.description or "",
            "created_at": p.created_at,
            "github_owner": p.github_owner,
            "github_repo": p.github_repo,
            "has_github_token": bool(p.github_token),
            "github_token_masked": masked_token,
            "github_workflow_id": p.github_workflow_id,
            "target_service_url": p.target_service_url or "",
            "auto_rollback_enabled": p.auto_rollback_enabled,
            "min_confidence_threshold": p.min_confidence_threshold,
            "block_on_db_migration": p.block_on_db_migration
        }

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
                project_id=incident_dict.get("project_id"),
                user_id=incident_dict.get("user_id"),
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
    def get_incidents_for_user(user_id: str, project_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            query = db.query(IncidentModel).filter(IncidentModel.user_id == user_id)
            if project_id:
                query = query.filter(IncidentModel.project_id == project_id)
            records = query.order_by(IncidentModel.timestamp.desc()).limit(limit).all()
            return [IncidentRepository._record_to_dict(r) for r in records]
        finally:
            db.close()

    @staticmethod
    def get_all_incidents(limit: int = 50) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            records = db.query(IncidentModel).order_by(IncidentModel.timestamp.desc()).limit(limit).all()
            return [IncidentRepository._record_to_dict(r) for r in records]
        finally:
            db.close()

    @staticmethod
    def _record_to_dict(r: IncidentModel) -> Dict[str, Any]:
        return {
            "incident_id": r.incident_id,
            "project_id": r.project_id,
            "user_id": r.user_id,
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
        }

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
        masked_token = None
        if user.github_token:
            masked_token = "****" + (user.github_token[-4:] if len(user.github_token) > 4 else "")

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
