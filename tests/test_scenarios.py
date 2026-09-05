import pytest
from src.rag.indexer import KnowledgeIndexer
from src.rag.retriever import HybridRetriever
from src.automation.git_tracker import GitTracker
from src.automation.guardrails import SafetyGuardrails
from src.security.sanitizer import LogSanitizer
from src.db.repository import IncidentRepository
from fastapi.testclient import TestClient
from src.api.server import app

client = TestClient(app)

def test_knowledge_indexer():
    indexer = KnowledgeIndexer("data/runbooks", "data/post_mortems")
    chunks = indexer.get_all_chunks()
    assert len(chunks) >= 4
    sources = [c.source_file for c in chunks]
    assert any("null-pointer" in s for s in sources)
    assert any("schema-migration" in s for s in sources)

def test_hybrid_retrieval():
    indexer = KnowledgeIndexer("data/runbooks", "data/post_mortems")
    retriever = HybridRetriever(indexer)
    results = retriever.search("KeyError user_tier CrashLoopBackOff", top_k=2)
    assert len(results) > 0
    top_chunk, score = results[0]
    assert score > 0
    assert "RB-001" in top_chunk.source_file or "INC-2025" in top_chunk.source_file

def test_git_migration_detection():
    tracker = GitTracker()
    assert tracker.detect_db_migrations(["services/checkout.py", "alembic/versions/001_add_col.py"]) is True
    assert tracker.detect_db_migrations(["services/checkout.py", "tests/test_app.py"]) is False
    assert tracker.detect_db_migrations(["prisma/schema.prisma"]) is True

def test_guardrails_safety():
    tracker = GitTracker()
    guardrails = SafetyGuardrails()

    commit_safe = tracker.parse_commit_payload(
        sha="a1b2c3d",
        previous_sha="e0f1g2h",
        author="dev@acme.com",
        message="fix: null check",
        changed_files=["app/main.py"],
        diff_snippet="- x\n+ y"
    )
    result_safe = guardrails.evaluate_rollback_safety(commit_safe, llm_confidence=0.90, recommended_action="ROLLBACK_NOW")
    assert result_safe.passed is True

    commit_db = tracker.parse_commit_payload(
        sha="x1y2z3",
        previous_sha="a1b2c3d",
        author="dba@acme.com",
        message="db: drop table",
        changed_files=["models/user.py", "alembic/versions/123_drop.py"],
        diff_snippet="op.drop_table(\"orders\")"
    )
    result_db = guardrails.evaluate_rollback_safety(commit_db, llm_confidence=0.95, recommended_action="ROLLBACK_NOW")
    assert result_db.passed is False
    assert "migration" in result_db.blocked_reason.lower()

def test_pii_and_secret_sanitizer():
    dirty_log = """
    Error connecting to db: postgresql://admin:SuperSecretPass123@db.prod.internal:5432/orders
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5
    GitHub token leaked: ghp_1234567890abcdef1234567890abcdef1234
    """
    clean_log, count = LogSanitizer.sanitize(dirty_log)
    assert count >= 4
    assert "SuperSecretPass123" not in clean_log
    assert "AKIAIOSFODNN7EXAMPLE" not in clean_log
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in clean_log
    assert "[REDACTED_AWS_ACCESS_KEY]" in clean_log
    assert "[REDACTED_GITHUB_TOKEN]" in clean_log

def test_database_persistence():
    incidents = IncidentRepository.get_all_incidents()
    assert isinstance(incidents, list)

def test_scenario_1_auto_rollback_api():
    resp = client.post("/api/v1/simulate/scenario-1")
    assert resp.status_code == 200
    data = resp.json()
    incident = data["incident"]
    assert incident["status"] == "RESOLVED"
    assert incident["guardrail"]["passed"] is True

def test_scenario_2_guardrail_blocked_api():
    resp = client.post("/api/v1/simulate/scenario-2")
    assert resp.status_code == 200
    data = resp.json()
    incident = data["incident"]
    assert incident["status"] == "NEEDS_REVIEW"
    assert incident["guardrail"]["passed"] is False
