import os
import time
import uuid
import re
from typing import List, Optional, Dict, Any
from sqlalchemy import text, inspect
from sqlalchemy.orm import Session
from src.db.models import IncidentModel, UserModel, ProjectModel, OTPModel
from src.db.database import Base, engine, SessionLocal

# Initialize tables (auto-provisions projects, users, incidents)
Base.metadata.create_all(bind=engine)

# Safe auto-migration for role, first_name, last_name, and organisation columns if table already existed
try:
    inspector = inspect(engine)
    if "users" in inspector.get_table_names():
        existing_cols = [c["name"] for c in inspector.get_columns("users")]
        with engine.connect() as conn:
            if "role" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';"))
            if "first_name" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN first_name VARCHAR(100);"))
            if "last_name" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_name VARCHAR(100);"))
            if "organisation" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN organisation VARCHAR(255);"))
            conn.commit()
except Exception:
    pass

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
    def get_all_projects_admin() -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            projects = db.query(ProjectModel).order_by(ProjectModel.created_at.desc()).all()
            results = []
            for p in projects:
                d = ProjectRepository._to_dict(p)
                user = db.query(UserModel).filter(UserModel.id == p.user_id).first()
                d["owner_name"] = user.name if user else "Unknown"
                d["owner_email"] = user.email if user else "Unknown"
                d["incident_count"] = db.query(IncidentModel).filter(IncidentModel.project_id == p.id).count()
                results.append(d)
            return results
        finally:
            db.close()

    @staticmethod
    def delete_project_admin(project_id: str) -> bool:
        db = SessionLocal()
        try:
            p = db.query(ProjectModel).filter(ProjectModel.id == project_id).first()
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
    def get_all_incidents(severity: Optional[str] = None, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            query = db.query(IncidentModel)
            if severity and severity != "ALL":
                query = query.filter(IncidentModel.severity == severity)
            if status and status != "ALL":
                query = query.filter(IncidentModel.status == status)
            records = query.order_by(IncidentModel.timestamp.desc()).limit(limit).all()
            return [IncidentRepository._record_to_dict(r) for r in records]
        finally:
            db.close()

    @staticmethod
    def get_system_stats() -> Dict[str, Any]:
        db = SessionLocal()
        try:
            total_users = db.query(UserModel).count()
            total_projects = db.query(ProjectModel).count()
            total_incidents = db.query(IncidentModel).count()
            resolved = db.query(IncidentModel).filter(IncidentModel.status == "RESOLVED").count()
            needs_review = db.query(IncidentModel).filter(IncidentModel.status == "NEEDS_REVIEW").count()
            guardrail_passed = db.query(IncidentModel).filter(IncidentModel.guardrail_passed == True).count()
            guardrail_blocked = db.query(IncidentModel).filter(IncidentModel.guardrail_passed == False).count()
            rollbacks = db.query(IncidentModel).filter(IncidentModel.rollback_status != None).count()

            incidents = db.query(IncidentModel).all()
            avg_confidence = 0.0
            if incidents:
                scores = [inc.confidence_score for inc in incidents if inc.confidence_score is not None]
                avg_confidence = round((sum(scores) / len(scores)) * 100, 1) if scores else 0.0

            return {
                "total_users": total_users,
                "total_projects": total_projects,
                "total_incidents": total_incidents,
                "resolved_incidents": resolved,
                "needs_review_incidents": needs_review,
                "resolution_rate": round((resolved / total_incidents * 100) if total_incidents > 0 else 100.0, 1),
                "guardrail_passed_count": guardrail_passed,
                "guardrail_blocked_count": guardrail_blocked,
                "rollbacks_count": rollbacks,
                "avg_confidence": avg_confidence
            }
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
    def get_or_create_user(
        sub_id: str,
        email: str,
        name: str = "SRE Engineer",
        picture: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        organisation: Optional[str] = None
    ) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter((UserModel.id == sub_id) | (UserModel.email == email)).first()
            if not user:
                total_users = db.query(UserModel).count()
                admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
                is_initial_admin = (total_users == 0) or (bool(admin_email) and email.strip().lower() == admin_email)
                role = "admin" if is_initial_admin else "user"

                if first_name or last_name:
                    name = f"{first_name or ''} {last_name or ''}".strip() or name

                user = UserModel(
                    id=sub_id,
                    email=email,
                    name=name,
                    first_name=first_name,
                    last_name=last_name,
                    organisation=organisation,
                    picture=picture,
                    role=role
                )
                db.add(user)
                db.commit()
                db.refresh(user)
            else:
                admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
                if admin_email and email.strip().lower() == admin_email and user.role != "admin":
                    user.role = "admin"
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name
                if organisation:
                    user.organisation = organisation
                if first_name or last_name:
                    user.name = f"{user.first_name or ''} {user.last_name or ''}".strip() or user.name
                elif name and user.name != name:
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
    def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.email == email.strip().lower()).first()
            return UserRepository._to_dict(user) if user else None
        finally:
            db.close()

    @staticmethod
    def get_all_users() -> List[Dict[str, Any]]:
        db = SessionLocal()
        try:
            users = db.query(UserModel).order_by(UserModel.created_at.desc()).all()
            results = []
            for u in users:
                d = UserRepository._to_dict(u)
                d["project_count"] = db.query(ProjectModel).filter(ProjectModel.user_id == u.id).count()
                d["incident_count"] = db.query(IncidentModel).filter(IncidentModel.user_id == u.id).count()
                results.append(d)
            return results
        finally:
            db.close()

    @staticmethod
    def set_user_role(user_id: str, new_role: str) -> Optional[Dict[str, Any]]:
        if new_role not in ["admin", "user"]:
            return None
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()
            if not user:
                return None
            user.role = new_role
            db.commit()
            db.refresh(user)
            return UserRepository._to_dict(user)
        finally:
            db.close()

    @staticmethod
    def delete_user(user_id: str) -> bool:
        db = SessionLocal()
        try:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()
            if not user:
                return False
            db.query(ProjectModel).filter(ProjectModel.user_id == user_id).delete()
            db.query(IncidentModel).filter(IncidentModel.user_id == user_id).delete()
            db.delete(user)
            db.commit()
            return True
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

        role = getattr(user, "role", "user") or "user"

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "first_name": getattr(user, "first_name", None),
            "last_name": getattr(user, "last_name", None),
            "organisation": getattr(user, "organisation", None),
            "picture": user.picture,
            "role": role,
            "is_admin": (role == "admin"),
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

class OTPRepository:
    @staticmethod
    def save_otp(email: str, code: str, purpose: str, expires_at: float) -> None:
        db = SessionLocal()
        try:
            now = time.time()
            clean_email = email.strip().lower()
            record = db.query(OTPModel).filter(OTPModel.email == clean_email).first()
            if not record:
                record = OTPModel(
                    email=clean_email,
                    code=code,
                    purpose=purpose,
                    created_at=now,
                    expires_at=expires_at,
                    attempts=0
                )
                db.add(record)
            else:
                record.code = code
                record.purpose = purpose
                record.created_at = now
                record.expires_at = expires_at
                record.attempts = 0
            db.commit()
        finally:
            db.close()

    @staticmethod
    def get_otp(email: str) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            clean_email = email.strip().lower()
            record = db.query(OTPModel).filter(OTPModel.email == clean_email).first()
            if not record:
                return None
            return {
                "email": record.email,
                "code": record.code,
                "purpose": record.purpose,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "attempts": record.attempts
            }
        finally:
            db.close()

    @staticmethod
    def increment_attempts(email: str) -> int:
        db = SessionLocal()
        try:
            clean_email = email.strip().lower()
            record = db.query(OTPModel).filter(OTPModel.email == clean_email).first()
            if record:
                record.attempts += 1
                db.commit()
                return record.attempts
            return 0
        finally:
            db.close()

    @staticmethod
    def delete_otp(email: str) -> None:
        db = SessionLocal()
        try:
            clean_email = email.strip().lower()
            record = db.query(OTPModel).filter(OTPModel.email == clean_email).first()
            if record:
                db.delete(record)
                db.commit()
        finally:
            db.close()

