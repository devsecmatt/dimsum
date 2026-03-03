from __future__ import annotations

import pytest

from dimsum.app import create_app
from dimsum.extensions import db as _db


@pytest.fixture(scope="session")
def app():
    """Create a Flask test application."""
    app = create_app("testing")
    yield app


@pytest.fixture(scope="function")
def db(app):
    """Create a fresh database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app, db):
    """Flask test client with database."""
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture(scope="function")
def auth_client(client, db):
    """Authenticated test client."""
    from dimsum.models.user import User

    user = User(username="testuser", email="test@example.com")
    user.set_password("testpass")
    db.session.add(user)
    db.session.commit()

    client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "testpass"},
    )
    client._user = user
    yield client
