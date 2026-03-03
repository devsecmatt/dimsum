"""Built-in wordlists and seeding utilities."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "data")


def seed_builtin_wordlists() -> int:
    """Create Wordlist DB records for all built-in wordlist files.

    Returns the number of new wordlists created.
    """
    from dimsum.extensions import db
    from dimsum.models.wordlist import Wordlist

    os.makedirs(BUILTIN_DIR, exist_ok=True)
    created = 0

    for filename in sorted(os.listdir(BUILTIN_DIR)):
        if not filename.endswith(".txt"):
            continue

        name = os.path.splitext(filename)[0].replace("_", " ").title()
        file_path = os.path.join(BUILTIN_DIR, filename)

        existing = db.session.execute(
            db.select(Wordlist).filter_by(name=name)
        ).scalar_one_or_none()
        if existing:
            continue

        entry_count = _count_lines(file_path)
        wordlist = Wordlist(
            name=name,
            description=f"Built-in wordlist: {name}",
            is_builtin=True,
            file_path=file_path,
            entry_count=entry_count,
        )
        db.session.add(wordlist)
        created += 1
        logger.info("Seeded built-in wordlist: %s (%d entries)", name, entry_count)

    if created:
        db.session.commit()
    return created


def _count_lines(path: str) -> int:
    try:
        with open(path, "r") as f:
            return sum(1 for line in f if line.strip() and not line.startswith("#"))
    except OSError:
        return 0
