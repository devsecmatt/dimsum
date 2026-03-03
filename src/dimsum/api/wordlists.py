from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import login_required

from dimsum.extensions import db
from dimsum.models.wordlist import Wordlist

wordlists_bp = Blueprint("api_wordlists", __name__)


@wordlists_bp.route("/", methods=["GET"])
@login_required
def list_wordlists():
    wordlists = db.session.execute(
        db.select(Wordlist).order_by(Wordlist.name)
    ).scalars().all()
    return jsonify([
        {
            "id": str(w.id),
            "name": w.name,
            "description": w.description,
            "is_builtin": w.is_builtin,
            "entry_count": w.entry_count,
        }
        for w in wordlists
    ])


@wordlists_bp.route("/<wordlist_id>", methods=["GET"])
@login_required
def get_wordlist(wordlist_id):
    # Stub — will be implemented in Phase 5
    return jsonify({"error": "Not implemented"}), 501
