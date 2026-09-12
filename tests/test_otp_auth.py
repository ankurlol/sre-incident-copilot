import os
import pytest
from fastapi.testclient import TestClient
from src.api.server import app
from src.security.otp_service import OTPService
from src.db.repository import UserRepository

@pytest.fixture
def client():
    return TestClient(app)

def test_otp_member_flow(client):
    email = "test.developer@acme.com"

    # 1. Invalid email check
    bad_req = client.post("/api/v1/auth/otp/send", json={"email": "not-an-email"})
    assert bad_req.status_code == 400

    # 2. Send OTP for member login
    send_resp = client.post("/api/v1/auth/otp/send", json={"email": email, "purpose": "member_login"})
    assert send_resp.status_code == 200
    data = send_resp.json()
    assert data["status"] == "success"
    dev_code = data.get("dev_code")
    assert dev_code is not None
    assert len(dev_code) == 6

    # 3. Verify with incorrect code
    fail_verify = client.post("/api/v1/auth/otp/verify", json={"email": email, "code": "000000", "purpose": "member_login"})
    assert fail_verify.status_code == 400
    assert "Invalid verification code" in fail_verify.json()["error"]

    # 4. Verify with valid code
    success_verify = client.post("/api/v1/auth/otp/verify", json={
        "email": email,
        "code": dev_code,
        "name": "Test Developer",
        "purpose": "member_login"
    })
    assert success_verify.status_code == 200
    verify_data = success_verify.json()
    assert verify_data["status"] == "success"
    assert verify_data["user"]["email"] == email

    # 5. Code is consumed, second attempt with same code must fail
    second_verify = client.post("/api/v1/auth/otp/verify", json={"email": email, "code": dev_code, "purpose": "member_login"})
    assert second_verify.status_code == 400

def test_otp_admin_unauthorized_email(client, monkeypatch):
    admin_key = "secret_key_123"
    monkeypatch.setenv("ADMIN_EMAIL", "real.admin@acme.com")
    monkeypatch.setenv("ADMIN_KEY", admin_key)
    
    # Non-admin email attempting admin OTP request must be blocked even with valid key
    resp = client.post(
        "/api/v1/auth/otp/send",
        json={"email": "attacker@evil.com", "purpose": "admin_login", "admin_key": admin_key}
    )
    assert resp.status_code == 403
    assert "not authorized as a platform administrator" in resp.json()["error"]

def test_otp_admin_authorized_flow(client, monkeypatch):
    admin_email = "super.admin@company.com"
    admin_key = "secure_admin_key_999"
    monkeypatch.setenv("ADMIN_EMAIL", admin_email)
    monkeypatch.setenv("ADMIN_KEY", admin_key)

    # 1. Admin OTP with wrong admin key
    wrong_key_resp = client.post(
        "/api/v1/auth/otp/send",
        json={"email": admin_email, "purpose": "admin_login", "admin_key": "wrong_key"}
    )
    assert wrong_key_resp.status_code == 401

    # 2. Admin OTP with correct credentials
    send_resp = client.post(
        "/api/v1/auth/otp/send",
        json={"email": admin_email, "purpose": "admin_login", "admin_key": admin_key}
    )
    assert send_resp.status_code == 200
    code = send_resp.json().get("dev_code")
    assert code is not None

    # 3. Verify admin OTP
    verify_resp = client.post(
        "/api/v1/auth/otp/verify",
        json={
            "email": admin_email,
            "code": code,
            "purpose": "admin_login",
            "admin_key": admin_key
        }
    )
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["user"]["role"] == "admin"
    assert vdata["user"]["is_admin"] is True

    # 4. Confirm dashboard loads for verified admin
    admin_id = vdata["user"]["id"]
    client.cookies.set("sre_user_id", admin_id)
    dash_resp = client.get("/admin")
    assert dash_resp.status_code == 200
    assert "Platform Control Center" in dash_resp.text

def test_otp_admin_2fa_enforcement(client, monkeypatch):
    """Test that both factors (Admin Master Key and Email OTP) are strictly enforced for 2FA."""
    admin_email = "super.admin@company.com"
    admin_key = "server_master_2fa_secret"
    monkeypatch.setenv("ADMIN_EMAIL", admin_email)
    monkeypatch.setenv("ADMIN_KEY", admin_key)

    # 1. Request OTP without admin_key -> blocked with 401
    missing_key_resp = client.post(
        "/api/v1/auth/otp/send",
        json={"email": admin_email, "purpose": "admin_login"}
    )
    assert missing_key_resp.status_code == 401
    assert "Invalid or missing Admin Master Key" in missing_key_resp.json()["error"]

    # 2. Request OTP with invalid admin_key -> blocked with 401
    bad_key_resp = client.post(
        "/api/v1/auth/otp/send",
        json={"email": admin_email, "purpose": "admin_login", "admin_key": "wrong_key"}
    )
    assert bad_key_resp.status_code == 401
    assert "Invalid or missing Admin Master Key" in bad_key_resp.json()["error"]

    # 3. Request OTP with valid admin_key -> success
    send_resp = client.post(
        "/api/v1/auth/otp/send",
        json={"email": admin_email, "purpose": "admin_login", "admin_key": admin_key}
    )
    assert send_resp.status_code == 200
    code = send_resp.json().get("dev_code")
    assert code is not None

    # 4. Verify OTP without admin_key -> blocked with 401
    verify_no_key_resp = client.post(
        "/api/v1/auth/otp/verify",
        json={
            "email": admin_email,
            "code": code,
            "purpose": "admin_login"
        }
    )
    assert verify_no_key_resp.status_code == 401
    assert "Invalid or missing Admin Master Key" in verify_no_key_resp.json()["error"]

    # 5. Verify OTP with correct admin_key -> success
    verify_resp = client.post(
        "/api/v1/auth/otp/verify",
        json={
            "email": admin_email,
            "code": code,
            "purpose": "admin_login",
            "admin_key": admin_key
        }
    )
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["user"]["role"] == "admin"
    assert vdata["user"]["is_admin"] is True

