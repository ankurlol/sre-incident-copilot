import pytest
import os
from fastapi.testclient import TestClient
from src.api.server import app
from src.db.repository import UserRepository, ProjectRepository, IncidentRepository

@pytest.fixture
def client():
    return TestClient(app)

def test_admin_access_unauthenticated(client):
    # Unauthenticated visitor should be redirected to log in
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code in [302, 307]
    assert "/?open_auth=true" in response.headers.get("location", "")

def test_admin_access_forbidden_for_regular_user(client):
    # Create a regular non-admin user
    reg_user = UserRepository.get_or_create_user(
        sub_id="regular_user_test_1",
        email="developer.regular@company.com",
        name="Regular Developer"
    )
    # Ensure role is 'user'
    UserRepository.set_user_role(reg_user["id"], "user")

    client.cookies.set("sre_user_id", reg_user["id"])
    response = client.get("/admin")
    assert response.status_code == 403
    assert "Administrator Access Required" in response.text

def test_admin_access_authorized(client):
    # Create an admin user
    admin_user = UserRepository.get_or_create_user(
        sub_id="admin_user_test_1",
        email="sre.lead@production.internal",
        name="Platform Admin Lead"
    )
    UserRepository.set_user_role(admin_user["id"], "admin")

    client.cookies.set("sre_user_id", admin_user["id"])
    response = client.get("/admin")
    assert response.status_code == 200
    assert "Platform Control Center" in response.text
    assert "Registered Tenants" in response.text
    assert "Global Fleet Services" in response.text

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
    # Create project
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
