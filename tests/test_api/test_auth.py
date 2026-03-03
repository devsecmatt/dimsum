from __future__ import annotations


def test_login_success(client, db):
    from dimsum.models.user import User

    user = User(username="logintest", email="login@example.com")
    user.set_password("password123")
    db.session.add(user)
    db.session.commit()

    resp = client.post("/api/auth/login", json={"username": "logintest", "password": "password123"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user"]["username"] == "logintest"


def test_login_invalid_credentials(client, db):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "wrong"})
    assert resp.status_code == 401


def test_login_missing_fields(client, db):
    resp = client.post("/api/auth/login", json={})
    assert resp.status_code == 400


def test_get_current_user_authenticated(auth_client):
    resp = auth_client.get("/api/auth/me")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["username"] == "testuser"


def test_get_current_user_unauthenticated(client, db):
    resp = client.get("/api/auth/me")
    assert resp.status_code in (401, 302)  # redirected or unauthorized


def test_logout(auth_client):
    resp = auth_client.post("/api/auth/logout")
    assert resp.status_code == 200
