"""Tests for the Wordlist management API (Phase 6)."""

from __future__ import annotations

import io
import os
import tempfile
import uuid

import pytest

from dimsum.models.wordlist import Wordlist
from dimsum.wordlists import seed_builtin_wordlists


class TestWordlistAPI:
    def test_list_wordlists_empty(self, auth_client):
        resp = auth_client.get("/api/wordlists/")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_upload_wordlist(self, auth_client, app, db):
        with tempfile.TemporaryDirectory() as tmpdir:
            app.config["WORDLIST_FOLDER"] = tmpdir
            data = {
                "file": (io.BytesIO(b"admin\ntest\nuser\n"), "users.txt"),
                "name": "Test Users",
                "description": "A test wordlist",
            }
            resp = auth_client.post(
                "/api/wordlists/",
                data=data,
                content_type="multipart/form-data",
            )
            assert resp.status_code == 201
            body = resp.get_json()
            assert body["name"] == "Test Users"
            assert body["entry_count"] == 3
            assert body["is_builtin"] is False

    def test_upload_duplicate_name(self, auth_client, app, db):
        with tempfile.TemporaryDirectory() as tmpdir:
            app.config["WORDLIST_FOLDER"] = tmpdir
            data = {
                "file": (io.BytesIO(b"one\ntwo\n"), "dup.txt"),
                "name": "Duplicate",
            }
            resp1 = auth_client.post("/api/wordlists/", data=data, content_type="multipart/form-data")
            assert resp1.status_code == 201

            data2 = {
                "file": (io.BytesIO(b"three\nfour\n"), "dup2.txt"),
                "name": "Duplicate",
            }
            resp2 = auth_client.post("/api/wordlists/", data=data2, content_type="multipart/form-data")
            assert resp2.status_code == 409

    def test_upload_invalid_extension(self, auth_client, app):
        data = {
            "file": (io.BytesIO(b"data"), "malware.exe"),
        }
        resp = auth_client.post("/api/wordlists/", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "Invalid file type" in resp.get_json()["error"]

    def test_get_wordlist(self, auth_client, app, db):
        with tempfile.TemporaryDirectory() as tmpdir:
            app.config["WORDLIST_FOLDER"] = tmpdir
            data = {
                "file": (io.BytesIO(b"alpha\nbeta\ngamma\n"), "greek.txt"),
                "name": "Greek Letters",
            }
            resp = auth_client.post("/api/wordlists/", data=data, content_type="multipart/form-data")
            wid = resp.get_json()["id"]

            resp = auth_client.get(f"/api/wordlists/{wid}")
            assert resp.status_code == 200
            body = resp.get_json()
            assert body["name"] == "Greek Letters"
            assert "preview" in body
            assert "alpha" in body["preview"]

    def test_update_wordlist(self, auth_client, app, db):
        with tempfile.TemporaryDirectory() as tmpdir:
            app.config["WORDLIST_FOLDER"] = tmpdir
            data = {
                "file": (io.BytesIO(b"a\nb\n"), "test.txt"),
                "name": "Original",
            }
            resp = auth_client.post("/api/wordlists/", data=data, content_type="multipart/form-data")
            wid = resp.get_json()["id"]

            resp = auth_client.put(
                f"/api/wordlists/{wid}",
                json={"name": "Updated Name", "description": "New desc"},
            )
            assert resp.status_code == 200
            assert resp.get_json()["name"] == "Updated Name"

    def test_delete_wordlist(self, auth_client, app, db):
        with tempfile.TemporaryDirectory() as tmpdir:
            app.config["WORDLIST_FOLDER"] = tmpdir
            data = {
                "file": (io.BytesIO(b"x\ny\n"), "delete_me.txt"),
                "name": "Delete Me",
            }
            resp = auth_client.post("/api/wordlists/", data=data, content_type="multipart/form-data")
            wid = resp.get_json()["id"]

            resp = auth_client.delete(f"/api/wordlists/{wid}")
            assert resp.status_code == 200

            resp = auth_client.get(f"/api/wordlists/{wid}")
            assert resp.status_code == 404

    def test_cannot_delete_builtin(self, auth_client, db):
        w = Wordlist(
            name="Builtin Test",
            is_builtin=True,
            file_path="/nonexistent/builtin.txt",
            entry_count=10,
        )
        db.session.add(w)
        db.session.commit()

        resp = auth_client.delete(f"/api/wordlists/{w.id}")
        assert resp.status_code == 403

    def test_get_entries_pagination(self, auth_client, app, db):
        with tempfile.TemporaryDirectory() as tmpdir:
            app.config["WORDLIST_FOLDER"] = tmpdir
            lines = "\n".join(f"entry_{i}" for i in range(50))
            data = {
                "file": (io.BytesIO(lines.encode()), "big.txt"),
                "name": "Big List",
            }
            resp = auth_client.post("/api/wordlists/", data=data, content_type="multipart/form-data")
            wid = resp.get_json()["id"]

            resp = auth_client.get(f"/api/wordlists/{wid}/entries?offset=0&limit=10")
            assert resp.status_code == 200
            body = resp.get_json()
            assert len(body["entries"]) == 10
            assert body["total"] == 50

    def test_seed_builtin_wordlists(self, app, db):
        count = seed_builtin_wordlists()
        assert count >= 1

        wordlists = db.session.execute(
            db.select(Wordlist).filter_by(is_builtin=True)
        ).scalars().all()
        assert len(wordlists) >= 1

        # Second call should not create duplicates
        count2 = seed_builtin_wordlists()
        assert count2 == 0

    def test_requires_auth(self, client):
        resp = client.get("/api/wordlists/")
        assert resp.status_code in (401, 302)
