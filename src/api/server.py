import os
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
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
from src.db.repository import IncidentRepository

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

async def process_incident(payload: AlertPayload) -> Dict[str, Any]:
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
        rollback_result = await github_client.trigger_rollback(
            target_sha=commit.previous_sha,
            reason=f"[Autonomous SRE Copilot] Rollback triggered for incident {rca.incident_id}: {rca.root_cause_summary[:80]}"
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

    # 8. Persistent Storage in SQLite / PostgreSQL
    IncidentRepository.save_incident(incident_record)
    return incident_record

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    incidents = IncidentRepository.get_all_incidents()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": settings.APP_NAME,
            "incidents": incidents,
            "auto_rollback_enabled": settings.AUTO_ROLLBACK_ENABLED,
            "guardrail_threshold": settings.MIN_CONFIDENCE_THRESHOLD,
            "simulated_mode": settings.SIMULATE_GITHUB_ACTIONS
        }
    )

@app.get("/api/v1/incidents", response_class=JSONResponse)
async def get_incidents():
    incidents = IncidentRepository.get_all_incidents()
    return {"incidents": incidents}

@app.post("/api/v1/incident/alert", dependencies=[Depends(verify_api_key)])
async def receive_alert(payload: AlertPayload):
    result = await process_incident(payload)
    return {"status": "processed", "incident": result}

@app.post("/api/v1/incident/{incident_id}/manual-rollback", dependencies=[Depends(verify_api_key)])
async def manual_rollback(incident_id: str):
    incidents = IncidentRepository.get_all_incidents()
    incident = next((inc for inc in incidents if inc["incident_id"] == incident_id), None)
    if not incident:
        return JSONResponse(status_code=404, content={"error": "Incident not found"})

    target_sha = incident["commit"]["previous_sha"]
    rollback_result = await github_client.trigger_rollback(
        target_sha=target_sha,
        reason=f"[Manual Operator Override] Rollback executed for incident {incident_id}"
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
        current_commit_sha="a7f3b199042d31289cf02",
        previous_commit_sha="e4c89211048b29104fa87",
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
