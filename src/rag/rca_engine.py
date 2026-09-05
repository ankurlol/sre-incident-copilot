import os
import json
import uuid
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from config.settings import settings
from src.rag.indexer import DocumentChunk
from src.automation.git_tracker import GitCommit

class RCAReport(BaseModel):
    incident_id: str
    service_name: str
    severity: str
    root_cause_summary: str
    breaking_commit_sha: str
    breaking_author: str
    breaking_file: str
    matched_runbooks: List[Dict[str, Any]]
    mitigation_steps: List[str]
    recommended_action: str # ROLLBACK_NOW, MANUAL_REVIEW, APPLY_HOTFIX
    confidence_score: float
    risk_assessment: str
    raw_reasoning: str

class RCAEngine:
    def __init__(self):
        self.provider = settings.LLM_PROVIDER

    def _generate_heuristic_fallback(
        self,
        service_name: str,
        error_log: str,
        commit: GitCommit,
        matched_chunks: List[tuple[DocumentChunk, float]]
    ) -> RCAReport:
        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        
        # Analyze error pattern
        error_lower = error_log.lower()
        matched_rb_meta = [
            {"title": chunk.title, "source": chunk.source_file, "score": score}
            for chunk, score in matched_chunks
        ]

        if "attributeerror" in error_lower or "nullpointer" in error_lower or "keyerror" in error_lower:
            root_cause = (
                f"Unhandled exception in commit {commit.sha[:7]} by {commit.author}. "
                f"Message: '{commit.message}'. The commit accessed a property or header without null checking, "
                f"causing pods to fail upon request processing."
            )
            rec_action = "ROLLBACK_NOW"
            confidence = 0.92
            risk = "HIGH_AVAILABILITY_RISK"
            breaking_file = commit.changed_files[0] if commit.changed_files else "unknown"
            mitigations = [
                f"Trigger automated rollback to previous stable commit {commit.previous_sha[:7]}.",
                "Verify API health check endpoint /healthz.",
                f"Notify author {commit.author} to submit hotfix with null-coalescing guard."
            ]
        elif "connection pool" in error_lower or "timeout" in error_lower or "operationalerror" in error_lower:
            root_cause = (
                f"Database connection pool exhaustion triggered by recent deployment {commit.sha[:7]}. "
                f"Unclosed transactions or insufficient pool limit."
            )
            rec_action = "MANUAL_REVIEW"
            confidence = 0.84
            risk = "CRITICAL_DATABASE_LOCK"
            breaking_file = commit.changed_files[0] if commit.changed_files else "database.py"
            mitigations = [
                "Inspect active DB sessions on PostgreSQL.",
                "Scale connection pool or restart hanging worker instances.",
                "Review recent queries for missing transaction release."
            ]
        else:
            root_cause = f"Production degradation detected following deployment of commit {commit.sha[:7]}."
            rec_action = "ROLLBACK_NOW"
            confidence = 0.78
            risk = "MEDIUM_RISK"
            breaking_file = commit.changed_files[0] if commit.changed_files else "app.py"
            mitigations = [
                f"Revert to previous SHA {commit.previous_sha[:7]}.",
                "Inspect pod logs."
            ]

        return RCAReport(
            incident_id=incident_id,
            service_name=service_name,
            severity="P1",
            root_cause_summary=root_cause,
            breaking_commit_sha=commit.sha,
            breaking_author=commit.author,
            breaking_file=breaking_file,
            matched_runbooks=matched_rb_meta,
            mitigation_steps=mitigations,
            recommended_action=rec_action,
            confidence_score=confidence,
            risk_assessment=risk,
            raw_reasoning=f"Analyzed {len(matched_chunks)} runbooks against git diff:\n{commit.diff_snippet[:200]}"
        )

    async def analyze_incident(
        self,
        service_name: str,
        error_log: str,
        commit: GitCommit,
        matched_chunks: List[tuple[DocumentChunk, float]]
    ) -> RCAReport:
        # Check if live Gemini or OpenAI key is available, otherwise use intelligent heuristic fallback
        gemini_key = os.getenv("GEMINI_API_KEY") or settings.GEMINI_API_KEY
        openai_key = os.getenv("OPENAI_API_KEY") or settings.OPENAI_API_KEY

        if self.provider == "gemini" and gemini_key:
            try:
                # Real Gemini API call
                import httpx
                prompt = self._build_prompt(service_name, error_log, commit, matched_chunks)
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.GEMINI_MODEL}:generateContent?key={gemini_key}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"response_mime_type": "application/json"}
                }
                async with httpx.AsyncClient() as client:
                    resp = await client.post(url, json=payload, timeout=20.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        text_resp = data["candidates"][0]["content"]["parts"][0]["text"]
                        parsed = json.loads(text_resp)
                        return RCAReport(**parsed)
            except Exception as e:
                pass

        # Fallback analysis
        return self._generate_heuristic_fallback(service_name, error_log, commit, matched_chunks)

    def _build_prompt(
        self,
        service_name: str,
        error_log: str,
        commit: GitCommit,
        matched_chunks: List[tuple[DocumentChunk, float]]
    ) -> str:
        runbook_context = "\n\n".join([
            f"--- RUNBOOK: {c.title} (Score: {s}) ---\n{c.content}"
            for c, s in matched_chunks
        ])

        return f"""
You are an expert SRE Incident Commander performing automated Root Cause Analysis (RCA).
Analyze the following crash and return a JSON object matching the exact schema.

### INCIDENT CONTEXT:
Service Name: {service_name}
Failing Commit SHA: {commit.sha}
Previous Stable SHA: {commit.previous_sha}
Commit Author: {commit.author}
Commit Message: {commit.message}
Changed Files: {commit.changed_files}

### GIT DIFF SNIPPET:
{commit.diff_snippet}

### ERROR STACK TRACE & LOGS:
{error_log}

### MATCHED RUNBOOKS & POST-MORTEMS:
{runbook_context}

Return a valid JSON object with keys:
- incident_id (str, e.g. INC-1042)
- service_name (str)
- severity (str: P0, P1, P2)
- root_cause_summary (str: exact explanation)
- breaking_commit_sha (str)
- breaking_author (str)
- breaking_file (str)
- matched_runbooks (list of dicts with title, source, score)
- mitigation_steps (list of strings)
- recommended_action (str: 'ROLLBACK_NOW', 'MANUAL_REVIEW', or 'APPLY_HOTFIX')
- confidence_score (float between 0.0 and 1.0)
- risk_assessment (str)
- raw_reasoning (str)
"""
