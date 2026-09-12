import pytest
from fastapi.testclient import TestClient
from src.db.repository import UserRepository
from src.api.server import app

@pytest.fixture
def client():
    return TestClient(app)

def test_signup_complete_flow(client, monkeypatch):
    """Test full user registration flow with First Name, Last Name, Email, and Organisation."""
    monkeypatch.setenv("EXPOSE_DEV_OTP", "true")
    
    first_name = "Jane"
    last_name = "Doe"
    email = "jane.doe@cyberdyne.systems"
    organisation = "Cyberdyne Infrastructure"

    # 1. Request OTP for signup
    send_resp = client.post(
        "/api/v1/auth/otp/send",
        json={
            "email": email,
            "purpose": "member_signup",
            "first_name": first_name,
            "last_name": last_name,
            "organisation": organisation
        }
    )
    assert send_resp.status_code == 200
    data = send_resp.json()
    assert data["status"] == "success"
    code = data.get("dev_code")
    assert code is not None

    # 2. Verify OTP and complete registration
    verify_resp = client.post(
        "/api/v1/auth/otp/verify",
        json={
            "email": email,
            "code": code,
            "purpose": "member_signup",
            "first_name": first_name,
            "last_name": last_name,
            "organisation": organisation
        }
    )
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["status"] == "success"
    user = vdata["user"]

    # Verify all captured fields
    assert user["email"] == email
    assert user["first_name"] == first_name
    assert user["last_name"] == last_name
    assert user["name"] == f"{first_name} {last_name}"
    assert user["organisation"] == organisation
    assert user["role"] == "user"

    # 3. Check persistent database record
    db_user = UserRepository.get_user_by_email(email)
    assert db_user is not None
    assert db_user["first_name"] == first_name
    assert db_user["last_name"] == last_name
    assert db_user["organisation"] == organisation
    assert db_user["name"] == "Jane Doe"

    # 4. Authenticated session access
    client.cookies.set("sre_user_id", user["id"])
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200
    assert "Jane Doe" in dash_resp.text
