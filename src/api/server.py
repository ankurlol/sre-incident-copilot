import os
import time
import hashlib
import httpx
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, Response, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from config.settings import settings
from src.rag.indexer import KnowledgeIndexer
from src.rag.retriever import HybridRetriever
from src.rag.rca_engine import RCAEngine, RCAReport
from src.automation.git_tracker import GitTracker, GitCommit
from src.automation.guardrails import SafetyGuardrails, GuardrailCheckResult
from src.automation.github_client import GitHubRollbackClient
from src.automation.health_verifier import HealthVerifier
from src.notifications.reporter import IncidentReporter
from src.security.sanitizer import LogSanitizer
from src.security.auth import verify_api_key
from src.security.otp_service import OTPService
from src.db.repository import IncidentRepository, UserRepository, ProjectRepository

app = FastAPI(title=settings.APP_NAME)

indexer = KnowledgeIndexer(settings.RUNBOOKS_DIR, settings.POST_MORTEMS_DIR)
retriever = HybridRetriever(indexer)
rca_engine = RCAEngine()
git_tracker = GitTracker()
guardrails = SafetyGuardrails()
github_client = GitHubRollbackClient()
health_verifier = HealthVerifier()
reporter = IncidentReporter()

templates = Jinja2Templates(directory="src/api/templates")

class AlertPayload(BaseModel):
    service_name: str
    error_log: str
    current_commit_sha: str
    previous_commit_sha: str
    commit_author: str
    commit_message: str
    changed_files: List[str]
    diff_snippet: str

class GoogleAuthPayload(BaseModel):
    credential: str

class OTPSendPayload(BaseModel):
    email: str
    purpose: str = "member_login"  # "member_login", "member_signup", or "admin_login"
    admin_key: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organisation: Optional[str] = None

class OTPVerifyPayload(BaseModel):
    email: str
    code: str
    name: Optional[str] = None
    purpose: str = "member_login"
    admin_key: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organisation: Optional[str] = None

class DemoLoginPayload(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None

class AdminLoginPayload(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    admin_key: Optional[str] = None

class CreateProjectPayload(BaseModel):
    name: str
    description: Optional[str] = ""
    github_owner: str
    github_repo: str
    github_token: Optional[str] = None
    github_workflow_id: Optional[str] = "deploy.yml"
    target_service_url: Optional[str] = None
    auto_rollback_enabled: Optional[bool] = True
    min_confidence_threshold: Optional[float] = 0.75
    block_on_db_migration: Optional[bool] = True

class UserConfigPayload(BaseModel):
    user_id: Optional[str] = None
    github_token: Optional[str] = None
    github_owner: Optional[str] = None
    github_repo: Optional[str] = None
    github_workflow_id: Optional[str] = "deploy.yml"
    target_service_url: Optional[str] = None
    auto_rollback_enabled: Optional[bool] = True
    min_confidence_threshold: Optional[float] = 0.75
    block_on_db_migration: Optional[bool] = True

class TestGitHubPayload(BaseModel):
    token: str
    owner: str
    repo: str

class UserRolePayload(BaseModel):
    role: str

async def process_incident(
    payload: AlertPayload,
    user_config: Optional[Dict[str, Any]] = None,
    project_id: Optional[str] = None,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. PII & Secret Redaction (Pre-RAG Data Privacy Guard)
    sanitized_error, redactions = LogSanitizer.sanitize(payload.error_log)
    sanitized_diff, diff_redactions = LogSanitizer.sanitize(payload.diff_snippet)

    # 2. Parse commit
    commit = git_tracker.parse_commit_payload(
        sha=payload.current_commit_sha,
        previous_sha=payload.previous_commit_sha,
        author=payload.commit_author,
        message=payload.commit_message,
        changed_files=payload.changed_files,
        diff_snippet=sanitized_diff
    )

    # 3. Hybrid RAG Retrieval (Runbooks & Post-Mortems)
    query = f"{sanitized_error} {payload.commit_message} {commit.diff_snippet}"
    matched_chunks = retriever.search(query=query, top_k=3)

    # 4. LLM Diagnostic Root Cause Analysis
    rca = await rca_engine.analyze_incident(
        service_name=payload.service_name,
        error_log=sanitized_error,
        commit=commit,
        matched_chunks=matched_chunks
    )

    # 5. Safety Guardrail Evaluation
    guardrail_result = guardrails.evaluate_rollback_safety(
        commit=commit,
        llm_confidence=rca.confidence_score,
        recommended_action=rca.recommended_action
    )

    rollback_result = None
    health_result = None

    # 6. Autonomous Remediation Execution (if guardrail passed)
    if guardrail_result.passed:
        token = user_config.get("github_token") if user_config else None
        owner = user_config.get("github_owner") if user_config else None
        repo = user_config.get("github_repo") if user_config else None
        workflow_id = user_config.get("github_workflow_id") if user_config else None

        rollback_result = await github_client.trigger_rollback(
            target_sha=commit.previous_sha,
            reason=f"[Autonomous SRE Copilot] Rollback triggered for incident {rca.incident_id}: {rca.root_cause_summary[:80]}",
            token=token,
            owner=owner,
            repo=repo,
            workflow_id=workflow_id
        )
        guardrails.record_rollback(commit.previous_sha)
        health_result = await health_verifier.verify_service_health(mock_should_succeed=True)
    else:
        health_result = {"healthy": False, "message": "Service remains degraded. Auto-rollback held by safety guardrail."}

    # 7. Format Incident Record
    slack_summary = reporter.format_slack_message(rca, guardrail_result, rollback_result)
    markdown_report = reporter.format_markdown_summary(rca, guardrail_result, rollback_result)

    incident_record = {
        "incident_id": rca.incident_id,
        "project_id": project_id,
        "user_id": user_id,
        "timestamp": timestamp,
        "service_name": payload.service_name,
        "severity": rca.severity,
        "status": "RESOLVED" if (guardrail_result.passed and health_result.get("healthy")) else "NEEDS_REVIEW",
        "rca": rca.model_dump(),
        "guardrail": guardrail_result.model_dump(),
        "rollback": rollback_result,
        "health": health_result,
        "slack_summary": slack_summary,
        "markdown_report": markdown_report,
        "commit": commit.model_dump(),
        "error_log": sanitized_error,
        "redactions": redactions + diff_redactions
    }

    # 8. Persistent Storage in PostgreSQL / SQLite
    IncidentRepository.save_incident(incident_record)
    return incident_record

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user_id = request.cookies.get("sre_user_id")
    current_user = UserRepository.get_user_by_id(user_id) if user_id else None

    # If unauthenticated, render the public marketing landing page (all projects/incidents hidden)
    if not current_user:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "app_name": settings.APP_NAME,
                "current_user": None,
                "is_authenticated": False,
                "projects": [],
                "active_project": None,
                "incidents": [],
                "google_client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
                "auto_rollback_enabled": settings.AUTO_ROLLBACK_ENABLED,
                "guardrail_threshold": settings.MIN_CONFIDENCE_THRESHOLD,
                "simulated_mode": settings.SIMULATE_GITHUB_ACTIONS
            }
        )

    # If authenticated, check and update admin role if applicable
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    is_admin = (current_user.get("role") == "admin") or (bool(admin_email) and current_user.get("email", "").lower() == admin_email)
    if is_admin and current_user.get("role") != "admin":
        UserRepository.set_user_role(current_user["id"], "admin")
        current_user["role"] = "admin"
    current_user["is_admin"] = is_admin

    # Load ONLY this user's projects and incidents
    user_projects = ProjectRepository.get_user_projects(current_user["id"])
    active_project_id = request.query_params.get("project_id")
    active_project = None
    if user_projects:
        active_project = next((p for p in user_projects if p["id"] == active_project_id), user_projects[0])

    incidents = []
    if active_project:
        incidents = IncidentRepository.get_incidents_for_user(current_user["id"], project_id=active_project["id"])

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": settings.APP_NAME,
            "current_user": current_user,
            "is_authenticated": True,
            "is_admin": is_admin,
            "projects": user_projects,
            "active_project": active_project,
            "incidents": incidents,
            "google_client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
            "auto_rollback_enabled": settings.AUTO_ROLLBACK_ENABLED,
            "guardrail_threshold": settings.MIN_CONFIDENCE_THRESHOLD,
            "simulated_mode": settings.SIMULATE_GITHUB_ACTIONS
        }
    )

@app.get("/api/v1/incidents", response_class=JSONResponse)
async def get_incidents(request: Request):
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if user_id:
        incidents = IncidentRepository.get_incidents_for_user(user_id)
    else:
        incidents = []
    return {"incidents": incidents}

@app.post("/api/v1/auth/google")
async def auth_google(payload: GoogleAuthPayload, response: Response):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={payload.credential}",
                timeout=10.0
            )
            if resp.status_code != 200:
                return JSONResponse(status_code=400, content={"error": "Invalid Google credential token."})

            token_data = resp.json()
            sub_id = token_data.get("sub")
            email = token_data.get("email")
            name = token_data.get("name") or email.split("@")[0]
            picture = token_data.get("picture")

            user = UserRepository.get_or_create_user(
                sub_id=sub_id,
                email=email,
                name=name,
                picture=picture
            )

            response.set_cookie(
                key="sre_user_id",
                value=user["id"],
                max_age=60 * 60 * 24 * 30,
                httponly=False,
                samesite="lax"
            )
            return {"status": "success", "user": user}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Authentication failed: {str(e)}"})

@app.get("/api/v1/auth/smtp-status")
async def get_smtp_status():
    from dotenv import load_dotenv
    load_dotenv(override=False)
    secret_files = []
    if os.path.isdir("/etc/secrets"):
        try:
            secret_files = os.listdir("/etc/secrets")
            for fname in secret_files:
                fpath = os.path.join("/etc/secrets", fname)
                if os.path.isfile(fpath):
                    load_dotenv(fpath, override=True)
        except Exception as e:
            secret_files = [f"error: {str(e)}"]

    has_smtp_user = bool(os.getenv("SMTP_USER"))
    has_smtp_pass = bool(os.getenv("SMTP_PASSWORD"))

    return {
        "smtp_configured": has_smtp_user and has_smtp_pass,
        "smtp_user": (os.getenv("SMTP_USER", "")[:4] + "***") if has_smtp_user else None,
        "smtp_host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": os.getenv("SMTP_PORT", "587"),
        "etc_secrets_exists": os.path.isdir("/etc/secrets"),
        "etc_secrets_files": secret_files
    }

@app.get("/api/v1/auth/smtp-test")
async def test_smtp_connection():
    import smtplib
    from dotenv import load_dotenv
    load_dotenv(override=False)
    if os.path.isdir("/etc/secrets"):
        try:
            for fname in os.listdir("/etc/secrets"):
                fpath = os.path.join("/etc/secrets", fname)
                if os.path.isfile(fpath):
                    load_dotenv(fpath, override=True)
        except Exception:
            pass

    smtp_user = os.getenv("SMTP_USER", "").strip().strip("'\"")
    smtp_pass = os.getenv("SMTP_PASSWORD", "").strip().strip("'\"").replace(" ", "")
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip().strip("'\"")

    results = {}
    
    # Check Resend HTTPS API (Port 443 - free from cloud port blocking)
    resend_key = os.getenv("RESEND_API_KEY", "").strip().strip("'\"")
    if resend_key:
        try:
            r = httpx.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
                json={
                    "from": os.getenv("RESEND_FROM_EMAIL", "SRE Copilot <onboarding@resend.dev>"),
                    "to": ["delivered@resend.dev"],
                    "subject": "Test Verification",
                    "text": "Testing Resend connection"
                },
                timeout=8.0
            )
            if r.status_code in [200, 201]:
                results["resend_https_443"] = f"OK (Resend delivery confirmed, ID: {r.json().get('id')})"
            else:
                results["resend_https_443"] = f"Error {r.status_code}: {r.text}"
        except Exception as e:
            results["resend_https_443"] = f"Exception: {type(e).__name__}: {str(e)}"
    else:
        results["resend_https_443"] = "Not configured (set RESEND_API_KEY in Render to bypass port blocks)"

    try:
        with smtplib.SMTP(smtp_host, 587, timeout=6) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(smtp_user, smtp_pass)
        results["tls_587"] = "OK"
    except Exception as e:
        results["tls_587"] = f"{type(e).__name__}: {str(e)}"

    try:
        with smtplib.SMTP_SSL(smtp_host, 465, timeout=6) as s:
            s.login(smtp_user, smtp_pass)
        results["ssl_465"] = "OK"
    except Exception as e:
        results["ssl_465"] = f"{type(e).__name__}: {str(e)}"

    can_send = results.get("resend_https_443") == "OK" or results.get("tls_587") == "OK" or results.get("ssl_465") == "OK"

    return {
        "smtp_user": (smtp_user[:4] + "***@" + smtp_user.split("@")[-1]) if "@" in smtp_user else smtp_user,
        "password_length": len(smtp_pass),
        "results": results,
        "can_send": can_send,
        "note": "Render free tier blocks raw SMTP ports 587 and 465. Use RESEND_API_KEY (HTTPS port 443) for 100% reliable email dispatch on Render."
    }

@app.post("/api/v1/auth/otp/send")
async def send_otp(payload: OTPSendPayload):
    email = (payload.email or "").strip().lower()
    if not email or "@" not in email or "." not in email:
        return JSONResponse(status_code=400, content={"error": "Please provide a valid email address."})

    purpose = payload.purpose or "member_login"

    # Strict Admin Authorization Check
    if purpose == "admin_login":
        configured_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        configured_key = os.getenv("ADMIN_KEY") or os.getenv("API_KEY")

        # 2FA Enforcement: Validate Admin Master Key if configured
        if configured_key:
            if not payload.admin_key or payload.admin_key.strip() != configured_key:
                return JSONResponse(status_code=401, content={"error": "Invalid or missing Admin Master Key."})

        # Check authorization of email
        is_admin_allowed = False
        if configured_email and email == configured_email:
            is_admin_allowed = True
        else:
            existing_user = UserRepository.get_user_by_email(email)
            if existing_user and existing_user.get("role") == "admin":
                is_admin_allowed = True
            elif not configured_email and len(UserRepository.get_all_users()) == 0:
                is_admin_allowed = True

        if not is_admin_allowed:
            return JSONResponse(
                status_code=403,
                content={"error": f"Email '{email}' is not authorized as a platform administrator."}
            )

    code, sent_smtp, message = OTPService.generate_otp(email, purpose=purpose)
    if not code:
        return JSONResponse(status_code=429, content={"error": message})

    expose_dev = os.getenv("EXPOSE_DEV_OTP", "false").lower() in ["true", "1", "yes"]

    if not sent_smtp and not expose_dev:
        return JSONResponse(status_code=400, content={"error": message})

    return {
        "status": "success",
        "message": message,
        "email": email,
        "sent_via_smtp": sent_smtp,
        "dev_code": code if expose_dev else None
    }

@app.post("/api/v1/auth/otp/verify")
async def verify_otp(payload: OTPVerifyPayload, response: Response):
    email = (payload.email or "").strip().lower()
    code = (payload.code or "").strip()
    purpose = payload.purpose or "member_login"

    # For admin login, enforce Admin Master Key before consuming OTP
    if purpose == "admin_login":
        configured_key = os.getenv("ADMIN_KEY") or os.getenv("API_KEY")
        if configured_key:
            if not payload.admin_key or payload.admin_key.strip() != configured_key:
                return JSONResponse(status_code=401, content={"error": "Invalid or missing Admin Master Key."})

    success, msg = OTPService.verify_otp(email=email, code=code, purpose=purpose)
    if not success:
        return JSONResponse(status_code=400, content={"error": msg})

    name = payload.name or email.split("@")[0]

    if purpose == "admin_login":

        configured_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        is_admin_allowed = False
        if configured_email and email == configured_email:
            is_admin_allowed = True
        else:
            existing_user = UserRepository.get_user_by_email(email)
            if existing_user and existing_user.get("role") == "admin":
                is_admin_allowed = True
            elif not configured_email and len(UserRepository.get_all_users()) == 0:
                is_admin_allowed = True

        if not is_admin_allowed:
            return JSONResponse(status_code=403, content={"error": f"Email '{email}' is not authorized as an administrator."})

        sub_id = f"admin_{hashlib.md5(email.encode()).hexdigest()[:10]}"
        user = UserRepository.get_or_create_user(
            sub_id=sub_id,
            email=email,
            name=name,
            picture="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
        )
        UserRepository.set_user_role(user["id"], "admin")
        user["role"] = "admin"
        user["is_admin"] = True

        response.set_cookie(
            key="sre_user_id",
            value=user["id"],
            max_age=60 * 60 * 24 * 30,
            httponly=False,
            samesite="lax"
        )
        return {"status": "success", "user": user, "redirect": "/admin"}

    else:
        sub_id = f"user_{hashlib.md5(email.encode()).hexdigest()[:10]}"
        first_name = (payload.first_name or "").strip() or None
        last_name = (payload.last_name or "").strip() or None
        organisation = (payload.organisation or "").strip() or None
        if first_name or last_name:
            name = f"{first_name or ''} {last_name or ''}".strip()
        else:
            name = payload.name or email.split("@")[0]

        user = UserRepository.get_or_create_user(
            sub_id=sub_id,
            email=email,
            name=name,
            first_name=first_name,
            last_name=last_name,
            organisation=organisation,
            picture="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
        )
        response.set_cookie(
            key="sre_user_id",
            value=user["id"],
            max_age=60 * 60 * 24 * 30,
            httponly=False,
            samesite="lax"
        )
        return {"status": "success", "user": user, "redirect": "/"}

@app.post("/api/v1/auth/demo-login")
async def demo_login(payload: DemoLoginPayload, response: Response):
    email = (payload.email or "").strip().lower()
    if not email:
        return JSONResponse(status_code=400, content={"error": "Email is required."})
    sub_id = f"demo_{hashlib.md5(email.encode()).hexdigest()[:10]}"
    name = payload.name or email.split("@")[0]
    user = UserRepository.get_or_create_user(
        sub_id=sub_id,
        email=email,
        name=name,
        picture="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
    )
    response.set_cookie(
        key="sre_user_id",
        value=user["id"],
        max_age=60 * 60 * 24 * 30,
        httponly=False,
        samesite="lax"
    )
    return {"status": "success", "user": user}

@app.post("/api/v1/auth/admin-login")
async def admin_login(payload: AdminLoginPayload, response: Response):
    configured_key = os.getenv("ADMIN_KEY") or os.getenv("API_KEY")
    configured_email = os.getenv("ADMIN_EMAIL", "").strip().lower()

    if configured_key:
        if not payload.admin_key or payload.admin_key.strip() != configured_key:
            return JSONResponse(status_code=401, content={"error": "Invalid or missing Admin Access Key."})

    email = (payload.email or configured_email or "").strip().lower()
    if not email:
        return JSONResponse(status_code=400, content={"error": "Email is required."})

    is_admin_allowed = False
    if configured_email and email == configured_email:
        is_admin_allowed = True
    else:
        existing_user = UserRepository.get_user_by_email(email)
        if existing_user and existing_user.get("role") == "admin":
            is_admin_allowed = True
        elif not configured_email and len(UserRepository.get_all_users()) == 0:
            is_admin_allowed = True

    if not is_admin_allowed:
        return JSONResponse(status_code=403, content={"error": f"Email '{email}' is not authorized as an administrator."})

    sub_id = f"admin_{hashlib.md5(email.encode()).hexdigest()[:10]}"
    name = payload.name or email.split("@")[0]

    user = UserRepository.get_or_create_user(
        sub_id=sub_id,
        email=email,
        name=name,
        picture="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
    )
    UserRepository.set_user_role(user["id"], "admin")
    user["role"] = "admin"
    user["is_admin"] = True

    response.set_cookie(
        key="sre_user_id",
        value=user["id"],
        max_age=60 * 60 * 24 * 30,
        httponly=False,
        samesite="lax"
    )
    return {"status": "success", "user": user, "redirect": "/admin"}

@app.post("/api/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(key="sre_user_id")
    return {"status": "logged_out"}

@app.get("/api/v1/user/me")
async def get_current_user(request: Request):
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return {"user": None}
    user = UserRepository.get_user_by_id(user_id)
    return {"user": user}

# Project Management Endpoints (Multi-Tenant)
@app.post("/api/v1/projects")
async def create_project(payload: CreateProjectPayload, request: Request):
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Please sign in to create a project."})

    project = ProjectRepository.create_project(user_id, payload.model_dump())
    return {"status": "success", "project": project}

@app.get("/api/v1/projects")
async def list_projects(request: Request):
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return {"projects": []}
    return {"projects": ProjectRepository.get_user_projects(user_id)}

@app.delete("/api/v1/projects/{project_id}")
async def delete_project(project_id: str, request: Request):
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    success = ProjectRepository.delete_project(project_id, user_id)
    if not success:
        return JSONResponse(status_code=404, content={"error": "Project not found or unauthorized."})
    return {"status": "deleted"}

@app.post("/api/v1/projects/{project_id}/simulate")
async def simulate_project_incident(project_id: str, request: Request):
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    project = ProjectRepository.get_project_by_id(project_id, user_id=user_id)
    if not project:
        return JSONResponse(status_code=404, content={"error": "Project not found."})

    user = UserRepository.get_user_by_id(project["user_id"])
    project_token = ProjectRepository.get_project_raw_token(project["id"])
    user_token = project_token or (user.get("github_token") if user else None)

    user_config = {
        "github_token": user_token,
        "github_owner": project["github_owner"],
        "github_repo": project["github_repo"],
        "github_workflow_id": project["github_workflow_id"]
    }

    payload = AlertPayload(
        service_name=project["name"],
        error_log=f"""Traceback (most recent call last):
  File "/app/services/checkout.py", line 112, in process_payment
    user_tier = user_session['subscription']['tier']
KeyError: 'tier'
[ERROR] Pod {project['service_slug']}-7d84b79b64 exited with status 1 (CrashLoopBackOff)""",
        current_commit_sha="47f0606",
        previous_commit_sha="3f43acc",
        commit_author="dev@company.com",
        commit_message=f"feat({project['service_slug']}): add checkout discount logic",
        changed_files=["services/checkout.py"],
        diff_snippet="+ user_tier = user_session['subscription']['tier']"
    )

    result = await process_incident(payload, user_config=user_config, project_id=project["id"], user_id=project["user_id"])
    return {"status": "simulated", "incident": result}

@app.post("/api/v1/projects/{project_id}/alert")
async def project_alert_webhook(project_id: str, payload: AlertPayload):
    project = ProjectRepository.get_project_by_id(project_id)
    if not project:
        return JSONResponse(status_code=404, content={"error": "Monitored project not found."})

    user = UserRepository.get_user_by_id(project["user_id"])
    project_token = ProjectRepository.get_project_raw_token(project["id"])
    user_token = project_token or (user.get("github_token") if user else None)

    user_config = {
        "github_token": user_token,
        "github_owner": project["github_owner"],
        "github_repo": project["github_repo"],
        "github_workflow_id": project["github_workflow_id"]
    }

    result = await process_incident(payload, user_config=user_config, project_id=project["id"], user_id=project["user_id"])
    return {"status": "processed", "incident": result}

@app.post("/api/v1/user/config")
async def update_user_config(payload: UserConfigPayload, request: Request):
    user_id = payload.user_id or request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return JSONResponse(status_code=401, content={"error": "Please log in to save your settings."})

    config_data = payload.model_dump(exclude_unset=True)
    if "user_id" in config_data:
        del config_data["user_id"]

    updated_user = UserRepository.update_user_config(user_id, config_data)
    if not updated_user:
        return JSONResponse(status_code=404, content={"error": "User not found."})

    return {"status": "success", "user": updated_user}

@app.post("/api/v1/user/test-github")
async def test_user_github(payload: TestGitHubPayload):
    result = await github_client.test_connection(
        token=payload.token,
        owner=payload.owner,
        repo=payload.repo
    )
    return result

@app.post("/api/v1/incident/alert", dependencies=[Depends(verify_api_key)])
async def receive_alert(payload: AlertPayload, request: Request):
    result = await process_incident(payload)
    return {"status": "processed", "incident": result}

@app.post("/api/v1/incident/{incident_id}/manual-rollback", dependencies=[Depends(verify_api_key)])
async def manual_rollback(incident_id: str, request: Request):
    incidents = IncidentRepository.get_all_incidents()
    incident = next((inc for inc in incidents if inc["incident_id"] == incident_id), None)
    if not incident:
        return JSONResponse(status_code=404, content={"error": "Incident not found"})

    user_id = request.headers.get("X-User-Id") or request.cookies.get("sre_user_id")
    user_token = None
    user_owner = None
    user_repo = None
    user_workflow = None

    if user_id:
        from src.db.database import SessionLocal
        from src.db.models import UserModel
        db = SessionLocal()
        try:
            u = db.query(UserModel).filter(UserModel.id == user_id).first()
            if u and u.github_token:
                user_token = u.github_token
                user_owner = u.github_owner
                user_repo = u.github_repo
                user_workflow = u.github_workflow_id
        finally:
            db.close()

    target_sha = incident["commit"]["previous_sha"]
    rollback_result = await github_client.trigger_rollback(
        target_sha=target_sha,
        reason=f"[Manual Operator Override] Rollback executed for incident {incident_id}",
        token=user_token,
        owner=user_owner,
        repo=user_repo,
        workflow_id=user_workflow
    )
    guardrails.record_rollback(target_sha)
    health_result = await health_verifier.verify_service_health(mock_should_succeed=True)

    IncidentRepository.update_status(
        incident_id=incident_id,
        new_status="RESOLVED",
        rollback_result=rollback_result,
        health_result=health_result
    )

    return {"status": "success", "message": f"Manual rollback triggered to {target_sha[:7]}", "rollback": rollback_result}

@app.post("/api/v1/simulate/scenario-1")
async def simulate_scenario_1():
    payload = AlertPayload(
        service_name="payment-service",
        error_log="""Traceback (most recent call last):
  File "/app/services/checkout.py", line 112, in process_payment
    user_tier = user_session['subscription']['tier']
KeyError: 'tier'
[ERROR] Pod payment-service-7d84b79b64-8x92p exited with status 1 (CrashLoopBackOff)""",
        current_commit_sha="47f0606",
        previous_commit_sha="3f43acc",
        commit_author="alex.dev@acme.com",
        commit_message="feat(checkout): add premium tier discount calculation",
        changed_files=["services/checkout.py", "tests/test_checkout.py"],
        diff_snippet="""@@ -110,3 +110,4 @@
 def process_payment(user_session, amount):
+    user_tier = user_session['subscription']['tier']
+    if user_tier == 'premium':
+        amount *= 0.9"""
    )
    result = await process_incident(payload)
    return {"status": "simulated", "scenario": "Scenario 1: Fatal Regression Auto-Rollback", "incident": result}

@app.post("/api/v1/simulate/scenario-2")
async def simulate_scenario_2():
    payload = AlertPayload(
        service_name="user-auth-service",
        error_log="""sqlalchemy.exc.ProgrammingError: (psycopg2.errors.UndefinedColumn) column users.is_verified does not exist
LINE 1: SELECT users.id, users.email, users.is_verified FROM users ...
[CRITICAL] Application crashed on startup.""",
        current_commit_sha="b8d91024fc81992019ab2",
        previous_commit_sha="9c2019aa01828471b01c3",
        commit_author="dave.dba@acme.com",
        commit_message="migration(db): add is_verified column and drop legacy_status",
        changed_files=["models/user.py", "alembic/versions/2026_09_06_add_verified_col.py"],
        diff_snippet="""@@ -0,0 +1,15 @@
+# alembic migration
+def upgrade():
+    op.add_column('users', sa.Column('is_verified', sa.Boolean(), nullable=False))
+    op.drop_column('users', 'legacy_status')"""
    )
    result = await process_incident(payload)
    return {"status": "simulated", "scenario": "Scenario 2: DB Migration Auto-Rollback Blocked", "incident": result}

@app.get("/healthz")
async def healthz():
    db_status = "connected"
    try:
        from sqlalchemy import text
        from src.db.database import engine
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    is_healthy = "unhealthy" not in db_status
    return {
        "status": "healthy" if is_healthy else "degraded",
        "app": settings.APP_NAME,
        "database": db_status
    }

@app.get("/mock-target/healthz")
async def mock_healthz():
    return {"status": "healthy", "version": "v2.4.1", "uptime": "99.99%"}

# -----------------------------------------------------------------------------
# Admin Portal & Platform Operations
# -----------------------------------------------------------------------------
def get_current_admin(request: Request) -> Optional[Dict[str, Any]]:
    # 1. Check API / Admin Secret Key (for automation / CI / platform scripts)
    admin_key = request.headers.get("X-Admin-Key") or request.query_params.get("admin_key")
    configured_key = os.getenv("ADMIN_KEY") or os.getenv("API_KEY")
    if configured_key and admin_key and admin_key == configured_key:
        return {
            "id": "admin_key_user",
            "email": "system.admin@internal",
            "name": "System Administrator",
            "role": "admin",
            "is_admin": True
        }

    # 2. Check Cookie / Session User
    user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
    if not user_id:
        return None

    user = UserRepository.get_user_by_id(user_id)
    if not user:
        return None

    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    if user.get("role") == "admin" or (bool(admin_email) and user.get("email", "").lower() == admin_email):
        if user.get("role") != "admin":
            UserRepository.set_user_role(user["id"], "admin")
            user["role"] = "admin"
            user["is_admin"] = True
        return user

    return None

def get_system_health_status() -> Dict[str, Any]:
    db_status = "Connected (Healthy)"
    db_latency_ms = 0.0
    t0 = time.time()
    try:
        from src.db.database import engine
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1;"))
        db_latency_ms = round((time.time() - t0) * 1000, 1)
    except Exception as e:
        db_status = f"Degraded ({str(e)[:30]})"

    return {
        "database": {
            "status": db_status,
            "engine": "PostgreSQL (Neon)" if "postgres" in os.getenv("DATABASE_URL", "") else "SQLite",
            "latency_ms": db_latency_ms
        },
        "retriever": {
            "status": "Operational",
            "runbooks_indexed": len(indexer.runbook_docs) if hasattr(indexer, "runbook_docs") else 2,
            "post_mortems_indexed": len(indexer.post_mortem_docs) if hasattr(indexer, "post_mortem_docs") else 2
        },
        "github_api": {
            "configured": bool(os.getenv("GITHUB_TOKEN")),
            "mode": "Simulation" if settings.SIMULATE_GITHUB_ACTIONS else "Live Actions"
        },
        "safety_guardrails": {
            "db_migration_blocker": settings.BLOCK_ON_DB_MIGRATION,
            "min_confidence_threshold": settings.MIN_CONFIDENCE_THRESHOLD,
            "auto_rollback_enabled": settings.AUTO_ROLLBACK_ENABLED
        }
    }

@app.get("/admin", response_class=HTMLResponse)
async def admin_portal(request: Request):
    admin_user = get_current_admin(request)
    if not admin_user:
        user_id = request.cookies.get("sre_user_id") or request.headers.get("X-User-Id")
        current_user = UserRepository.get_user_by_id(user_id) if user_id else None
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={
                "app_name": settings.APP_NAME,
                "current_user": current_user,
                "is_admin": False,
                "is_authenticated": bool(current_user),
                "stats": {},
                "users": [],
                "projects": [],
                "incidents": [],
                "health": {}
            }
        )

    stats = IncidentRepository.get_system_stats()
    users = UserRepository.get_all_users()
    projects = ProjectRepository.get_all_projects_admin()
    incidents = IncidentRepository.get_all_incidents(limit=100)
    health = get_system_health_status()

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "app_name": settings.APP_NAME,
            "current_user": admin_user,
            "is_admin": True,
            "stats": stats,
            "users": users,
            "projects": projects,
            "incidents": incidents,
            "health": health
        }
    )

@app.get("/api/v1/admin/stats", response_class=JSONResponse)
async def admin_stats(request: Request):
    if not get_current_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    return {
        "stats": IncidentRepository.get_system_stats(),
        "health": get_system_health_status()
    }

@app.get("/api/v1/admin/users", response_class=JSONResponse)
async def admin_users(request: Request):
    if not get_current_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    return {"users": UserRepository.get_all_users()}

@app.post("/api/v1/admin/users/{user_id}/role", response_class=JSONResponse)
async def admin_update_user_role(user_id: str, payload: UserRolePayload, request: Request):
    if not get_current_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    if payload.role not in ["admin", "user"]:
        return JSONResponse(status_code=400, content={"error": "Invalid role. Must be 'admin' or 'user'."})
    updated = UserRepository.set_user_role(user_id, payload.role)
    if not updated:
        return JSONResponse(status_code=404, content={"error": "User not found."})
    return {"status": "success", "user": updated}

@app.delete("/api/v1/admin/users/{user_id}", response_class=JSONResponse)
async def admin_delete_user(user_id: str, request: Request):
    admin = get_current_admin(request)
    if not admin:
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    if admin.get("id") == user_id:
        return JSONResponse(status_code=400, content={"error": "Cannot delete your own active administrator account."})
    success = UserRepository.delete_user(user_id)
    if not success:
        return JSONResponse(status_code=404, content={"error": "User not found."})
    return {"status": "success", "deleted_user_id": user_id}

@app.delete("/api/v1/admin/projects/{project_id}", response_class=JSONResponse)
async def admin_delete_project(project_id: str, request: Request):
    if not get_current_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    success = ProjectRepository.delete_project_admin(project_id)
    if not success:
        return JSONResponse(status_code=404, content={"error": "Project not found."})
    return {"status": "success", "deleted_project_id": project_id}

@app.get("/api/v1/admin/health", response_class=JSONResponse)
async def admin_health(request: Request):
    if not get_current_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    return get_system_health_status()
