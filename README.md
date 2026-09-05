# ?? Self-Healing SRE Incident Copilot & Automated GitHub Rollback Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-green.svg)](https://fastapi.tiangolo.com)
[![RAG](https://img.shields.io/badge/RAG-Hybrid%20BM25%20%2B%20Vector-purple.svg)]()
[![License](https://img.shields.io/badge/License-MIT-orange.svg)]()

An enterprise-grade AIOps platform that ingests production crash alerts, performs **Hybrid RAG Root Cause Analysis (RCA)** over operational runbooks, post-mortems, and Git commit diffs, evaluates **Safety Guardrails** (database migration detection, anti-flapping rate limiters), and **autonomously dispatches GitHub Actions rollbacks** to restore production uptime within seconds.

---

## ??? Architecture Overview

```
 +--------------------------------------------------------+
 ¦ 1. Production Crash / Alert Payload Ingestion          ¦
 ¦    (Sentry / Prometheus / CloudWatch Webhook)          ¦
 +--------------------------------------------------------+
                            ¦
                            ?
 +--------------------------------------------------------+
 ¦ 2. Git Tracker & Diff Analyzer                         ¦
 ¦    • Extracts breaking commit, author & changed files  ¦
 ¦    • Scans for database schema migration scripts       ¦
 +--------------------------------------------------------+
                            ¦
                            ?
 +--------------------------------------------------------+
 ¦ 3. Hybrid RAG Diagnostic Engine                        ¦
 ¦    • Sparse (BM25) + Dense Vector Semantic Search      ¦
 ¦    • Reciprocal Rank Fusion (RRF) over Runbooks & SOPs ¦
 ¦    • LLM Root Cause Analysis & Confidence Scoring      ¦
 +--------------------------------------------------------+
                            ¦
                            ?
 +--------------------------------------------------------+
 ¦ 4. Enterprise Safety Guardrails                        ¦
 ¦    • DB Migration Protection (prevents data loss)      ¦
 ¦    • Anti-Flapping / Rate Limiting                     ¦
 ¦    • Minimum Confidence Threshold Filter (>= 75%)      ¦
 +--------------------------------------------------------+
               ¦ (Passed)                   ¦ (Blocked)
               ?                            ?
 +---------------------------+   +------------------------+
 ¦ 5A. Autonomous Rollback   ¦   ¦ 5B. Human-in-the-Loop  ¦
 ¦  • GitHub Actions Dispatch¦   ¦  • Flagged in SRE Feed ¦
 ¦  • Redeploys previous SHA ¦   ¦  • 1-Click Manual UI   ¦
 ¦  • Polls /healthz endpoint¦   +------------------------+
 +---------------------------+
```

---

## ? Key Features

1. **Hybrid RAG Knowledge Base:** Indexes Markdown Runbooks, Historical Post-Mortems, and Git commit diffs using Reciprocal Rank Fusion (BM25 + Semantic Vector search).
2. **LLM Diagnostic Root Cause Analysis (RCA):** Identifies exact breaking code lines, analyzes stack traces, and recommends concrete mitigation steps with confidence scores.
3. **Enterprise Safety Guardrails:**
   - **Database Migration Detection:** Prevents dangerous automated code rollbacks if a release includes un-reverted database schema changes (Alembic, Prisma, Flyway, SQL).
   - **Anti-Flapping Rate Limiter:** Protects against deployment thrashing during cascade failures.
   - **Confidence Thresholding:** Routes uncertain incidents to human engineers.
4. **Autonomous GitOps / GitHub Actions Rollback:** Dispatches workflow runs to immediately redeploy the last known good commit SHA.
5. **Post-Rollback Health Verification:** Actively polls `/healthz` endpoints to verify restoration before marking incidents resolved.
6. **Real-time Incident Command Dashboard:** Modern web interface with live incident feeds, RCA breakdown cards, and 1-click manual overrides.

---

## ?? Quickstart

### 1. Installation
```bash
git clone https://github.com/your-org/sre-incident-copilot.git
cd sre-incident-copilot

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration (Optional)
Copy `.env.example` to `.env` and configure your API keys (defaults to intelligent local heuristic simulation mode if no keys are provided):
```bash
cp .env.example .env
```

### 3. Run the SRE Command Center
```bash
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 8000 --reload
```
Open your browser at **http://localhost:8000** to access the interactive dashboard.

---

## ?? Running Tests
```bash
pytest tests/test_scenarios.py -v
```

---

## ?? API Reference & Webhook Integration

### Receive Alert Webhook
`POST /api/v1/incident/alert`

```json
{
  "service_name": "payment-service",
  "error_log": "KeyError: 'tier' in checkout.py:112",
  "current_commit_sha": "a7f3b199042d31289cf02",
  "previous_commit_sha": "e4c89211048b29104fa87",
  "commit_author": "alex.dev@acme.com",
  "commit_message": "feat(checkout): add premium tier discount calculation",
  "changed_files": ["services/checkout.py"],
  "diff_snippet": "+ user_tier = user_session['subscription']['tier']"
}
```

---

## ?? License
MIT
