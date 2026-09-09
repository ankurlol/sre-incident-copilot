import pytest
from fastapi.testclient import TestClient
from src.api.server import app
from src.db.repository import UserRepository, ProjectRepository, IncidentRepository

@pytest.fixture
def client():
    return TestClient(app)

def test_admin_access_unauthenticated(client):
    # Unauthenticated visitor to /admin now sees the dedicated Admin Sign-In Card directly on /admin
    response = client.get("/admin")
    assert response.status_code == 200
    assert "SRE Copilot Admin Console" in response.text
    assert "Access Admin Portal" in response.text

def test_admin_direct_login_endpoint(client):
    import os
    admin_key = os.getenv("ADMIN_KEY") or os.getenv("API_KEY")

    # If key is required, request without key should fail with 401
    if admin_key:
        fail_resp = client.post(
            "/api/v1/auth/admin-login",
            json={"email": "lead.architect@company.com", "name": "Lead Architect", "admin_key": "wrong_key"}
        )
        assert fail_resp.status_code == 401

    # Request with valid credentials
    resp = client.post(
        "/api/v1/auth/admin-login",
        json={"email": "lead.architect@company.com", "name": "Lead Architect", "admin_key": admin_key}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["user"]["role"] == "admin"
    assert data["user"]["is_admin"] is True

    # Now verify the user has access to full admin dashboard
    admin_id = data["user"]["id"]
    client.cookies.set("sre_user_id", admin_id)
    dash_resp = client.get("/admin")
    assert dash_resp.status_code == 200
    assert "Platform Control Center" in dash_resp.text
    assert "Registered Tenants" in dash_resp.text

def test_admin_api_telemetry_and_health(client):
    admin_user = UserRepository.get_or_create_user(
        sub_id="admin_user_test_1",
        email="sre.lead@production.internal",
        name="Platform Admin Lead"
    )
    client.cookies.set("sre_user_id", admin_user["id"])

    # Stats
    resp_stats = client.get("/api/v1/admin/stats")
    assert resp_stats.status_code == 200
    data = resp_stats.json()
    assert "stats" in data
    assert "total_users" in data["stats"]
    assert "total_projects" in data["stats"]

    # Health
    resp_health = client.get("/api/v1/admin/health")
    assert resp_health.status_code == 200
    hdata = resp_health.json()
    assert "database" in hdata
    assert "retriever" in hdata
    assert "github_api" in hdata

def test_admin_user_role_toggle(client):
    admin_user = UserRepository.get_or_create_user(
        sub_id="admin_user_test_1",
        email="sre.lead@production.internal",
        name="Platform Admin Lead"
    )
    target_user = UserRepository.get_or_create_user(
        sub_id="target_member_99",
        email="junior.sre@company.com",
        name="Junior SRE"
    )
    client.cookies.set("sre_user_id", admin_user["id"])

    # Promote to admin
    resp1 = client.post(f"/api/v1/admin/users/{target_user['id']}/role", json={"role": "admin"})
    assert resp1.status_code == 200
    assert resp1.json()["user"]["role"] == "admin"

    # Demote to user
    resp2 = client.post(f"/api/v1/admin/users/{target_user['id']}/role", json={"role": "user"})
    assert resp2.status_code == 200
    assert resp2.json()["user"]["role"] == "user"

def test_admin_project_deletion(client):
    admin_user = UserRepository.get_or_create_user(
        sub_id="admin_user_test_1",
        email="sre.lead@production.internal",
        name="Platform Admin Lead"
    )
    proj = ProjectRepository.create_project(
        user_id="target_member_99",
        data={
            "name": "Legacy Temp Service",
            "github_owner": "testorg",
            "github_repo": "temp-repo",
            "github_workflow_id": "deploy.yml"
        }
    )
    client.cookies.set("sre_user_id", admin_user["id"])

    # Admin delete
    resp_del = client.delete(f"/api/v1/admin/projects/{proj['id']}")
    assert resp_del.status_code == 200
    assert resp_del.json()["status"] == "success"

    # Verify project is gone
    check_p = ProjectRepository.get_project_by_id(proj["id"])
    assert check_p is None
