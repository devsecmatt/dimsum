from __future__ import annotations

import os
import uuid

from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required
from werkzeug.utils import secure_filename

from dimsum.extensions import db
from dimsum.models.wordlist import Wordlist

wordlists_bp = Blueprint("api_wordlists", __name__)

_ALLOWED_EXTENSIONS = {".txt", ".lst", ".csv", ".wordlist"}


@wordlists_bp.route("/", methods=["GET"])
@login_required
def list_wordlists():
    wordlists = db.session.execute(
        db.select(Wordlist).order_by(Wordlist.name)
    ).scalars().all()
    return jsonify([_serialize(w) for w in wordlists])


@wordlists_bp.route("/<wordlist_id>", methods=["GET"])
@login_required
def get_wordlist(wordlist_id):
    w = db.session.get(Wordlist, uuid.UUID(wordlist_id))
    if w is None:
        return jsonify({"error": "Wordlist not found"}), 404
    return jsonify(_serialize(w, include_preview=True))


@wordlists_bp.route("/", methods=["POST"])
@login_required
def create_wordlist():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use multipart/form-data with a 'file' field."}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        return jsonify({"error": f"Invalid file type. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}"}), 400

    name = request.form.get("name") or os.path.splitext(file.filename)[0]
    description = request.form.get("description", "")

    existing = db.session.execute(
        db.select(Wordlist).filter_by(name=name)
    ).scalar_one_or_none()
    if existing:
        return jsonify({"error": f"Wordlist '{name}' already exists"}), 409

    # Save file
    wordlist_dir = current_app.config.get("WORDLIST_FOLDER", "/app/wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)
    safe_name = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
    file_path = os.path.join(wordlist_dir, safe_name)
    file.save(file_path)

    # Count entries
    entry_count = _count_entries(file_path)

    wordlist = Wordlist(
        name=name,
        description=description,
        is_builtin=False,
        file_path=file_path,
        entry_count=entry_count,
    )
    db.session.add(wordlist)
    db.session.commit()

    return jsonify(_serialize(wordlist)), 201


@wordlists_bp.route("/<wordlist_id>", methods=["PUT"])
@login_required
def update_wordlist(wordlist_id):
    w = db.session.get(Wordlist, uuid.UUID(wordlist_id))
    if w is None:
        return jsonify({"error": "Wordlist not found"}), 404
    if w.is_builtin:
        return jsonify({"error": "Cannot modify a built-in wordlist"}), 403

    data = request.get_json(silent=True) or {}
    if "name" in data:
        w.name = data["name"]
    if "description" in data:
        w.description = data["description"]
    db.session.commit()
    return jsonify(_serialize(w))


@wordlists_bp.route("/<wordlist_id>", methods=["DELETE"])
@login_required
def delete_wordlist(wordlist_id):
    w = db.session.get(Wordlist, uuid.UUID(wordlist_id))
    if w is None:
        return jsonify({"error": "Wordlist not found"}), 404
    if w.is_builtin:
        return jsonify({"error": "Cannot delete a built-in wordlist"}), 403

    # Remove the file
    if os.path.exists(w.file_path):
        os.remove(w.file_path)

    db.session.delete(w)
    db.session.commit()
    return jsonify({"message": "Wordlist deleted"}), 200


@wordlists_bp.route("/<wordlist_id>/entries", methods=["GET"])
@login_required
def get_wordlist_entries(wordlist_id):
    w = db.session.get(Wordlist, uuid.UUID(wordlist_id))
    if w is None:
        return jsonify({"error": "Wordlist not found"}), 404

    offset = request.args.get("offset", 0, type=int)
    limit = request.args.get("limit", 100, type=int)
    limit = min(limit, 1000)

    entries = _read_entries(w.file_path, offset=offset, limit=limit)
    return jsonify({
        "wordlist_id": str(w.id),
        "total": w.entry_count,
        "offset": offset,
        "limit": limit,
        "entries": entries,
    })


def _serialize(w: Wordlist, include_preview: bool = False) -> dict:
    result = {
        "id": str(w.id),
        "name": w.name,
        "description": w.description,
        "is_builtin": w.is_builtin,
        "entry_count": w.entry_count,
        "created_at": w.created_at.isoformat() if w.created_at else None,
    }
    if include_preview:
        result["preview"] = _read_entries(w.file_path, offset=0, limit=20)
    return result


def _count_entries(file_path: str) -> int:
    try:
        with open(file_path, "r", errors="replace") as f:
            return sum(1 for line in f if line.strip() and not line.startswith("#"))
    except OSError:
        return 0


def _read_entries(file_path: str, offset: int = 0, limit: int = 100) -> list[str]:
    entries = []
    try:
        with open(file_path, "r", errors="replace") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if i < offset:
                    continue
                entries.append(line)
                if len(entries) >= limit:
                    break
    except OSError:
        pass
    return entries
