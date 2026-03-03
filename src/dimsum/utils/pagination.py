from __future__ import annotations

from flask import request


def get_pagination_params(max_per_page: int = 200) -> tuple[int, int, int]:
    """Extract pagination parameters from the request query string.

    Returns:
        (page, per_page, offset)
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    page = max(1, page)
    per_page = max(1, min(per_page, max_per_page))
    offset = (page - 1) * per_page
    return page, per_page, offset
