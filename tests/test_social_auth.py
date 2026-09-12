import pytest
from fastapi.testclient import TestClient
from src.db.repository import UserRepository
from src.api.server import app

@pytest.fixture
def client():
    return TestClient(app)

def test_direct_google_auth(client):
    """Test direct Google sign-up / sign-in with profile creation and session cookie."""
    email = "elena.rostova@gmail.com"
    payload = {
        "provider": "google",
        "email": email,
        "name": "Elena Rostova",
        "first_name": "Elena",
        "last_name": "Rostova",
        "organisation": "FinTech Reliability Team"
    }

    response = client.post("/api/v1/auth/social-direct", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["user"]["email"] == email
    assert data["user"]["name"] == "Elena Rostova"
    assert data["user"]["first_name"] == "Elena"
    assert data["user"]["last_name"] == "Rostova"
    assert data["user"]["organisation"] == "FinTech Reliability Team"
    assert "sre_user_id" in response.cookies

    # Verify session cookie grants access to dashboard
    client.cookies.set("sre_user_id", data["user"]["id"])
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200
    assert "Elena Rostova" in dash_resp.text

def test_direct_github_auth(client):
    """Test direct GitHub authentication with username, avatar, and config updates."""
    github_user = "octo-engineer"
    email = "octo@github.com"
    payload = {
        "provider": "github",
        "email": email,
        "name": "Octo Engineer",
        "github_username": github_user,
        "organisation": "GitHub Core SRE"
    }

    response = client.post("/api/v1/auth/social-direct", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["user"]["email"] == email
    assert f"github.com/{github_user}.png" in data["user"]["picture"]

    # Verify user config has github_owner recorded
    user_record = UserRepository.get_user_by_id(data["user"]["id"])
    assert user_record is not None
    assert user_record.get("github_owner") == github_user

def test_github_oauth_redirect_fallback(client, monkeypatch):
    """Test GitHub OAuth start endpoint falls back when client ID is not configured."""
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    resp = client.get("/api/v1/auth/github", follow_redirects=False)
    assert resp.status_code == 307
    assert "open_auth=true" in resp.headers["location"]
    assert "github_client_id_missing" in resp.headers["location"]

def test_github_oauth_redirect_with_client_id(client, monkeypatch):
    """Test GitHub OAuth start redirects to GitHub login when configured."""
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test_client_id_12345")
    resp = client.get("/api/v1/auth/github", follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "github.com/login/oauth/authorize" in location
    assert "client_id=test_client_id_12345" in location

def test_google_oauth_redirect_fallback(client, monkeypatch):
    """Test Google OAuth start endpoint falls back when client ID is not configured."""
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    resp = client.get("/api/v1/auth/google/start", follow_redirects=False)
    assert resp.status_code == 307
    assert "open_auth=true" in resp.headers["location"]
    assert "google_client_id_missing" in resp.headers["location"]

def test_google_oauth_redirect_with_client_id(client, monkeypatch):
    """Test Google OAuth start redirects to Google accounts login when configured."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "google_test_client_id_67890")
    resp = client.get("/api/v1/auth/google/start", follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "accounts.google.com/o/oauth2/v2/auth" in location
    assert "client_id=google_test_client_id_67890" in location
