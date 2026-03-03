"""Regex-based source code parsers for route, parameter, and risk extraction."""

from __future__ import annotations

import re
from pathlib import Path


def detect_language(filepath: str) -> str | None:
    """Detect language from file extension."""
    ext = Path(filepath).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
    }
    return mapping.get(ext)


def parse_file(content: str, filepath: str, language: str) -> dict:
    """Parse a source file and extract routes, parameters, and risk indicators."""
    parsers = {
        "python": _parse_python,
        "javascript": _parse_javascript,
        "typescript": _parse_typescript,
    }
    parser = parsers.get(language)
    if parser is None:
        return {"routes": [], "parameters": [], "risk_indicators": []}
    return parser(content, filepath)


def _parse_python(content: str, filepath: str) -> dict:
    routes = []
    parameters = []
    risk_indicators = []

    # Flask/Quart routes: @app.route('/path') or @bp.route('/path', methods=[...])
    for m in re.finditer(
        r'@\w+\.route\(\s*["\']([^"\']+)["\'](?:.*?methods\s*=\s*\[([^\]]+)\])?',
        content,
    ):
        route_path = m.group(1)
        methods_str = m.group(2)
        methods = (
            [s.strip().strip("'\"") for s in methods_str.split(",")]
            if methods_str
            else ["GET"]
        )
        routes.append({"path": route_path, "methods": methods, "file": filepath})

    # FastAPI routes: @app.get('/path'), @router.post('/path')
    for m in re.finditer(
        r'@\w+\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']', content
    ):
        routes.append(
            {"path": m.group(2), "methods": [m.group(1).upper()], "file": filepath}
        )

    # Django URL patterns: path('route/', view)
    for m in re.finditer(r'path\(\s*["\']([^"\']+)["\']', content):
        routes.append({"path": "/" + m.group(1), "methods": ["GET"], "file": filepath})

    # Flask request params: request.args.get('x'), request.form['x'], request.json.get('x')
    for m in re.finditer(
        r'request\.(args|form|json|values)\s*[\.\[]\s*(?:get\(\s*)?["\'](\w+)["\']',
        content,
    ):
        source = m.group(1)
        param_type = "query" if source == "args" else "body"
        parameters.append(
            {"name": m.group(2), "source": param_type, "file": filepath}
        )

    # FastAPI path/query params from function signatures
    for m in re.finditer(r'def\s+\w+\([^)]*?(\w+)\s*:\s*(str|int|float|bool)', content):
        parameters.append(
            {"name": m.group(1), "type": m.group(2), "source": "query", "file": filepath}
        )

    risk_indicators.extend(_detect_risks(content, filepath))
    return {"routes": routes, "parameters": parameters, "risk_indicators": risk_indicators}


def _parse_javascript(content: str, filepath: str) -> dict:
    routes = []
    parameters = []
    risk_indicators = []

    # Express routes: app.get('/path', ...), router.post('/path', ...)
    for m in re.finditer(
        r'\.\s*(get|post|put|delete|patch|all)\(\s*["\']([^"\']+)["\']', content
    ):
        routes.append(
            {"path": m.group(2), "methods": [m.group(1).upper()], "file": filepath}
        )

    # Express params: req.body.x, req.query.x, req.params.x
    for m in re.finditer(r'req\.(body|query|params)\.(\w+)', content):
        source_map = {"body": "body", "query": "query", "params": "path"}
        parameters.append(
            {"name": m.group(2), "source": source_map[m.group(1)], "file": filepath}
        )

    # Destructured params: const { x, y } = req.body
    for m in re.finditer(r'(?:const|let|var)\s*\{([^}]+)\}\s*=\s*req\.(body|query|params)', content):
        source_map = {"body": "body", "query": "query", "params": "path"}
        names = [n.strip().split(":")[0].strip() for n in m.group(1).split(",")]
        for name in names:
            if name and re.match(r'^\w+$', name):
                parameters.append(
                    {"name": name, "source": source_map[m.group(2)], "file": filepath}
                )

    # Next.js API routes
    for m in re.finditer(r'export\s+(?:default\s+)?(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)', content):
        routes.append(
            {"path": filepath, "methods": [m.group(1)], "file": filepath}
        )

    risk_indicators.extend(_detect_risks(content, filepath))
    return {"routes": routes, "parameters": parameters, "risk_indicators": risk_indicators}


def _parse_typescript(content: str, filepath: str) -> dict:
    # TypeScript shares most patterns with JavaScript
    result = _parse_javascript(content, filepath)

    # Additionally detect NestJS decorators: @Get('/path'), @Post('/path')
    for m in re.finditer(r'@(Get|Post|Put|Delete|Patch)\(\s*["\']([^"\']+)["\']', content):
        result["routes"].append(
            {"path": m.group(2), "methods": [m.group(1).upper()], "file": filepath}
        )

    # NestJS @Body(), @Query(), @Param() decorator params
    for m in re.finditer(r'@(Body|Query|Param)\(\s*(?:["\'](\w+)["\'])?\s*\)', content):
        source_map = {"Body": "body", "Query": "query", "Param": "path"}
        name = m.group(2) or "unknown"
        result["parameters"].append(
            {"name": name, "source": source_map[m.group(1)], "file": filepath}
        )

    return result


# Risk indicator patterns shared across languages
_RISK_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("eval_usage", "Use of eval() can lead to code injection", re.compile(r'\beval\s*\(')),
    ("exec_usage", "Use of exec() can lead to code injection", re.compile(r'\bexec\s*\(')),
    ("sql_concat", "SQL query built via string concatenation", re.compile(r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*[\+%]', re.IGNORECASE)),
    ("shell_exec", "Shell command execution", re.compile(r'(?:subprocess\.(?:call|run|Popen)|os\.system|os\.popen|child_process\.exec(?:Sync)?|execSync)\s*\(')),
    ("unsafe_deserialization", "Unsafe deserialization", re.compile(r'(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|unserialize)\s*\(')),
    ("hardcoded_secret", "Potential hardcoded secret", re.compile(r'(?:password|secret|api_key|apikey|token|private_key)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE)),
    ("path_traversal_risk", "User input used in file path", re.compile(r'(?:open|readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|request\.|params|query)', re.IGNORECASE)),
    ("innerHTML_usage", "innerHTML assignment can lead to XSS", re.compile(r'\.innerHTML\s*=')),
    ("document_write", "document.write can lead to XSS", re.compile(r'document\.write\s*\(')),
]


def _detect_risks(content: str, filepath: str) -> list[dict]:
    indicators = []
    for risk_type, description, pattern in _RISK_PATTERNS:
        matches = list(pattern.finditer(content))
        if matches:
            lines = [content[:m.start()].count("\n") + 1 for m in matches[:5]]
            indicators.append({
                "type": risk_type,
                "description": description,
                "file": filepath,
                "lines": lines,
                "count": len(matches),
            })
    return indicators
