from __future__ import annotations


def test_create_project(auth_client):
    resp = auth_client.post("/api/projects/", json={"name": "Test Project", "description": "A test"})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["name"] == "Test Project"
    assert "id" in data


def test_list_projects(auth_client):
    auth_client.post("/api/projects/", json={"name": "Project 1"})
    auth_client.post("/api/projects/", json={"name": "Project 2"})

    resp = auth_client.get("/api/projects/")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 2


def test_get_project(auth_client):
    resp = auth_client.post("/api/projects/", json={"name": "Get Me"})
    project_id = resp.get_json()["id"]

    resp = auth_client.get(f"/api/projects/{project_id}")
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "Get Me"


def test_update_project(auth_client):
    resp = auth_client.post("/api/projects/", json={"name": "Old Name"})
    project_id = resp.get_json()["id"]

    resp = auth_client.put(f"/api/projects/{project_id}", json={"name": "New Name"})
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "New Name"


def test_delete_project(auth_client):
    resp = auth_client.post("/api/projects/", json={"name": "Delete Me"})
    project_id = resp.get_json()["id"]

    resp = auth_client.delete(f"/api/projects/{project_id}")
    assert resp.status_code == 200

    resp = auth_client.get(f"/api/projects/{project_id}")
    assert resp.status_code == 404


def test_create_project_no_name(auth_client):
    resp = auth_client.post("/api/projects/", json={"name": ""})
    assert resp.status_code == 400
