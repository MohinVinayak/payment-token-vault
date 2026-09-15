import pytest
from fastapi.testclient import TestClient

from app.main import app, request_log
from app.db import init_db, DB_PATH
from app.auth import hash_password
import app.db as db_module
import os


# ── Test Setup: use a separate test database ──────────

TEST_DB = "test_vault.db"


@pytest.fixture(autouse=True)
def setup_test_db():
    """Use a fresh test database for every test."""
    db_module.DB_PATH = TEST_DB
    init_db()
    request_log.clear()
    yield
    db_module.DB_PATH = DB_PATH
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


client = TestClient(app)


# ── Helpers ────────────────────────────────────────────

def seed_admin():
    """Directly insert an admin user into the DB (simulates pre-seeded admin)."""
    from app.db import get_connection
    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", hash_password("admin1234"), "admin"),
    )
    conn.commit()
    conn.close()


def register_and_login(username: str, password: str, role: str = "service") -> str:
    """Register a service user, login, and return the JWT token."""
    client.post("/register", json={
        "username": username, "password": password, "role": role,
    })
    resp = client.post("/login", json={
        "username": username, "password": password,
    })
    return resp.json()["access_token"]


def login_admin() -> str:
    """Seed an admin and login. Returns JWT token."""
    seed_admin()
    resp = client.post("/login", json={
        "username": "admin", "password": "admin1234",
    })
    return resp.json()["access_token"]


def auth_header(token: str) -> dict:
    """Build an Authorization header."""
    return {"Authorization": f"Bearer {token}"}


# ── Auth Tests ─────────────────────────────────────────

def test_register_success():
    resp = client.post("/register", json={
        "username": "testuser", "password": "password1", "role": "service",
    })
    assert resp.status_code == 200
    assert "registered" in resp.json()["message"]


def test_register_duplicate():
    client.post("/register", json={
        "username": "dupe", "password": "password1", "role": "service",
    })
    resp = client.post("/register", json={
        "username": "dupe", "password": "password2", "role": "service",
    })
    assert resp.status_code == 400


def test_register_admin_blocked():
    resp = client.post("/register", json={
        "username": "sneaky", "password": "password1", "role": "admin",
    })
    assert resp.status_code == 403


def test_register_weak_password():
    resp = client.post("/register", json={
        "username": "weakpw", "password": "short", "role": "service",
    })
    assert resp.status_code == 400


def test_login_success():
    client.post("/register", json={
        "username": "loginuser", "password": "password1", "role": "service",
    })
    resp = client.post("/login", json={
        "username": "loginuser", "password": "password1",
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/register", json={
        "username": "wrongpw", "password": "correct1", "role": "service",
    })
    resp = client.post("/login", json={
        "username": "wrongpw", "password": "wrong123",
    })
    assert resp.status_code == 401


# ── Tokenize Tests ─────────────────────────────────────

def test_tokenize_success():
    token = register_and_login("tok_user", "password1")
    resp = client.post(
        "/tokenize",
        json={"card_number": "4242424242424242"},
        headers=auth_header(token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["masked_pan"] == "**** **** **** 4242"


def test_tokenize_invalid_card():
    token = register_and_login("tok_invalid", "password1")
    resp = client.post(
        "/tokenize",
        json={"card_number": "1234567890123456"},
        headers=auth_header(token),
    )
    assert resp.status_code == 400


def test_tokenize_with_dashes():
    token = register_and_login("tok_dash", "password1")
    resp = client.post(
        "/tokenize",
        json={"card_number": "4242-4242-4242-4242"},
        headers=auth_header(token),
    )
    assert resp.status_code == 200
    assert resp.json()["masked_pan"] == "**** **** **** 4242"


def test_tokenize_duplicate_returns_same_token():
    token = register_and_login("tok_dedup", "password1")
    headers = auth_header(token)

    resp1 = client.post("/tokenize", json={"card_number": "4242424242424242"}, headers=headers)
    resp2 = client.post("/tokenize", json={"card_number": "4242424242424242"}, headers=headers)

    assert resp1.json()["token"] == resp2.json()["token"]


def test_tokenize_idempotency_key():
    token = register_and_login("tok_idemp", "password1")
    headers = {**auth_header(token), "x-idempotency-key": "unique-key-123"}

    resp1 = client.post("/tokenize", json={"card_number": "4242424242424242"}, headers=headers)
    resp2 = client.post("/tokenize", json={"card_number": "4242424242424242"}, headers=headers)

    assert resp1.json() == resp2.json()


# ── Detokenize Tests ───────────────────────────────────

def test_detokenize_admin_success():
    svc_token = register_and_login("det_svc", "password1")
    admin_token = login_admin()

    resp = client.post(
        "/tokenize",
        json={"card_number": "4242424242424242"},
        headers=auth_header(svc_token),
    )
    vault_token = resp.json()["token"]

    resp = client.post(
        "/detokenize",
        json={"token": vault_token, "reason": "refund"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["pan"] == "4242424242424242"


def test_detokenize_forbidden_for_non_admin():
    svc_token = register_and_login("det_denied", "password1")
    resp = client.post(
        "/detokenize",
        json={"token": "some-token", "reason": "test"},
        headers=auth_header(svc_token),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin role required"


def test_detokenize_not_found():
    admin_token = login_admin()
    resp = client.post(
        "/detokenize",
        json={"token": "nonexistent-token", "reason": "test"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404


# ── Revoke Tests ───────────────────────────────────────

def test_revoke_and_detokenize_fails():
    svc_token = register_and_login("rev_svc", "password1")
    admin_token = login_admin()

    resp = client.post(
        "/tokenize",
        json={"card_number": "4242424242424242"},
        headers=auth_header(svc_token),
    )
    vault_token = resp.json()["token"]

    resp = client.post(
        f"/token/{vault_token}/revoke",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200

    resp = client.post(
        "/detokenize",
        json={"token": vault_token, "reason": "refund"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404
    assert "revoked" in resp.json()["detail"]


# ── Metadata Tests ─────────────────────────────────────

def test_metadata_success():
    svc_token = register_and_login("meta_user", "password1")
    resp = client.post(
        "/tokenize",
        json={"card_number": "4242424242424242"},
        headers=auth_header(svc_token),
    )
    vault_token = resp.json()["token"]

    resp = client.get(f"/token/{vault_token}", headers=auth_header(svc_token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["masked_pan"] == "**** **** **** 4242"
    assert data["is_revoked"] is False


# ── Audit Log Tests ────────────────────────────────────

def test_audit_log_admin_access():
    admin_token = login_admin()
    resp = client.get("/audit-log", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_audit_log_denied_for_non_admin():
    svc_token = register_and_login("audit_denied", "password1")
    resp = client.get("/audit-log", headers=auth_header(svc_token))
    assert resp.status_code == 403


# ── Unauthenticated Tests ─────────────────────────────

def test_tokenize_without_auth():
    resp = client.post("/tokenize", json={"card_number": "4242424242424242"})
    assert resp.status_code == 401