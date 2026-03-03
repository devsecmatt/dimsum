from __future__ import annotations

from dimsum.models.user import User


def test_user_set_password(db):
    user = User(username="alice", email="alice@example.com")
    user.set_password("secret123")
    assert user.password_hash is not None
    assert user.password_hash != "secret123"


def test_user_check_password(db):
    user = User(username="bob", email="bob@example.com")
    user.set_password("mypassword")
    assert user.check_password("mypassword") is True
    assert user.check_password("wrongpassword") is False


def test_user_create_and_query(db):
    user = User(username="charlie", email="charlie@example.com")
    user.set_password("pass")
    db.session.add(user)
    db.session.commit()

    found = db.session.execute(
        db.select(User).filter_by(username="charlie")
    ).scalar_one()
    assert found.email == "charlie@example.com"
    assert found.is_active is True
