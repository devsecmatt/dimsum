"""Core source code analysis engine.

Extracts routes, parameters, and risk indicators from web application
source code using regex-based pattern matching. Supports JavaScript,
TypeScript, and Python frameworks.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ExtractedRoute:
    """A route/endpoint extracted from source code."""

    path: str
    method: str = "GET"
    file: str = ""
    line: int = 0
    framework: str = ""
    handler: str = ""


@dataclass
class ExtractedParameter:
    """A parameter extracted from source code."""

    name: str
    source: str = ""  # query, body, header, path, cookie
    file: str = ""
    line: int = 0
    param_type: str = ""  # string, int, etc.


@dataclass
class RiskIndicator:
    """A potentially risky code pattern found in source code."""

    pattern_name: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    file: str = ""
    line: int = 0
    code_snippet: str = ""
    cwe_id: int | None = None


@dataclass
class AnalysisResult:
    """Complete result from analyzing a source file."""

    file_path: str
    language: str
    routes: list[ExtractedRoute] = field(default_factory=list)
    parameters: list[ExtractedParameter] = field(default_factory=list)
    risk_indicators: list[RiskIndicator] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "routes": [
                {
                    "path": r.path,
                    "method": r.method,
                    "file": r.file,
                    "line": r.line,
                    "framework": r.framework,
                    "handler": r.handler,
                }
                for r in self.routes
            ],
            "parameters": [
                {
                    "name": p.name,
                    "source": p.source,
                    "file": p.file,
                    "line": p.line,
                    "type": p.param_type,
                }
                for p in self.parameters
            ],
            "risk_indicators": [
                {
                    "pattern_name": ri.pattern_name,
                    "description": ri.description,
                    "severity": ri.severity,
                    "file": ri.file,
                    "line": ri.line,
                    "code_snippet": ri.code_snippet,
                    "cwe_id": ri.cwe_id,
                }
                for ri in self.risk_indicators
            ],
        }


def detect_language(filename: str) -> str | None:
    """Detect language from file extension."""
    ext = Path(filename).suffix.lower()
    lang_map = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".py": "python",
    }
    return lang_map.get(ext)


def analyze_source(content: str, filename: str, language: str | None = None) -> AnalysisResult:
    """Analyze a source file and extract routes, parameters, and risk indicators.

    Args:
        content: The source code text.
        filename: The filename (used for reporting and language detection).
        language: Override the detected language.

    Returns:
        AnalysisResult with extracted data.
    """
    if language is None:
        language = detect_language(filename) or "unknown"

    result = AnalysisResult(file_path=filename, language=language)

    if language in ("javascript", "typescript"):
        _extract_js_routes(content, filename, result)
        _extract_js_params(content, filename, result)
    elif language == "python":
        _extract_python_routes(content, filename, result)
        _extract_python_params(content, filename, result)

    _extract_risk_indicators(content, filename, language, result)

    return result


# ---------- JavaScript / TypeScript Route Extraction ----------

# Generic HTTP framework route: app.get('/path', ...), router.post('/path', ...), server.use('/path', ...)
# Covers Express, Koa, Hono, and similar pattern-based frameworks
_JS_GENERIC_ROUTE = re.compile(
    r"""(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# Fastify-specific: fastify.get('/path', handler)
_JS_FASTIFY_ROUTE = re.compile(
    r"""fastify\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# React Router: <Route path="/foo" />
_JS_REACT_ROUTE = re.compile(
    r"""<Route\s+[^>]*path\s*=\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# fetch / axios calls: fetch('/api/users'), axios.get('/api/data')
_JS_FETCH_CALL = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)


def _extract_js_routes(content: str, filename: str, result: AnalysisResult) -> None:
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        # Generic framework routes (Express / Koa / Hono / etc.)
        for m in _JS_GENERIC_ROUTE.finditer(line):
            method = m.group(1).upper()
            path = m.group(2)
            if method == "USE":
                method = "ALL"
            result.routes.append(ExtractedRoute(
                path=path, method=method, file=filename,
                line=i, framework="express",
            ))

        # Fastify-specific routes
        for m in _JS_FASTIFY_ROUTE.finditer(line):
            result.routes.append(ExtractedRoute(
                path=m.group(2), method=m.group(1).upper(), file=filename,
                line=i, framework="fastify",
            ))

        # React Router
        for m in _JS_REACT_ROUTE.finditer(line):
            result.routes.append(ExtractedRoute(
                path=m.group(1), method="GET", file=filename,
                line=i, framework="react-router",
            ))

        # Fetch / axios calls → discovered API endpoints
        for m in _JS_FETCH_CALL.finditer(line):
            url = m.group(1)
            if url.startswith(("/", "http")):
                result.routes.append(ExtractedRoute(
                    path=url, method="GET", file=filename,
                    line=i, framework="client-call",
                ))


# ---------- JavaScript / TypeScript Parameter Extraction ----------

# req.query.foo, req.params.bar, req.body.baz
_JS_REQ_PARAM = re.compile(
    r"""req(?:uest)?\s*\.\s*(query|params|body|headers|cookies)\s*\.\s*(\w+)""",
)

# req.query['foo'], req.body["bar"]
_JS_REQ_BRACKET = re.compile(
    r"""req(?:uest)?\s*\.\s*(query|params|body|headers|cookies)\s*\[\s*['"`](\w+)['"`]\s*\]""",
)

# Destructuring: const { name, email } = req.body
_JS_DESTRUCTURE = re.compile(
    r"""(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*req(?:uest)?\s*\.\s*(query|params|body|headers|cookies)""",
)

# URLSearchParams: searchParams.get('foo')
_JS_SEARCH_PARAMS = re.compile(
    r"""(?:searchParams|urlParams|params)\s*\.\s*get\s*\(\s*['"`](\w+)['"`]\s*\)""",
)


def _extract_js_params(content: str, filename: str, result: AnalysisResult) -> None:
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        for m in _JS_REQ_PARAM.finditer(line):
            result.parameters.append(ExtractedParameter(
                name=m.group(2), source=m.group(1),
                file=filename, line=i,
            ))

        for m in _JS_REQ_BRACKET.finditer(line):
            result.parameters.append(ExtractedParameter(
                name=m.group(2), source=m.group(1),
                file=filename, line=i,
            ))

        for m in _JS_DESTRUCTURE.finditer(line):
            names = [n.strip().split("=")[0].strip().split(":")[0].strip() for n in m.group(1).split(",")]
            source = m.group(2)
            for name in names:
                if name and name.isidentifier():
                    result.parameters.append(ExtractedParameter(
                        name=name, source=source,
                        file=filename, line=i,
                    ))

        for m in _JS_SEARCH_PARAMS.finditer(line):
            result.parameters.append(ExtractedParameter(
                name=m.group(1), source="query",
                file=filename, line=i,
            ))


# ---------- Python Route Extraction ----------

# Flask: @app.route('/path', methods=['GET', 'POST'])
_PY_FLASK_ROUTE = re.compile(
    r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"](?:.*?methods\s*=\s*\[([^\]]+)\])?""",
)

# Django: path('url/', view), re_path(r'^url/', view)
_PY_DJANGO_PATH = re.compile(
    r"""(?:path|re_path)\s*\(\s*r?['"]([^'"]+)['"]""",
)

# FastAPI: @app.get('/path'), @router.post('/path')
_PY_FASTAPI_ROUTE = re.compile(
    r"""@\w+\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _extract_python_routes(content: str, filename: str, result: AnalysisResult) -> None:
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        for m in _PY_FLASK_ROUTE.finditer(line):
            path = m.group(1)
            methods_str = m.group(2)
            if methods_str:
                methods = [s.strip().strip("'\"").upper() for s in methods_str.split(",")]
            else:
                methods = ["GET"]
            for method in methods:
                result.routes.append(ExtractedRoute(
                    path=path, method=method, file=filename,
                    line=i, framework="flask",
                ))

        for m in _PY_DJANGO_PATH.finditer(line):
            result.routes.append(ExtractedRoute(
                path=m.group(1), method="ALL", file=filename,
                line=i, framework="django",
            ))

        for m in _PY_FASTAPI_ROUTE.finditer(line):
            result.routes.append(ExtractedRoute(
                path=m.group(2), method=m.group(1).upper(),
                file=filename, line=i, framework="fastapi",
            ))


# ---------- Python Parameter Extraction ----------

# request.args.get('foo'), request.form.get('bar')
_PY_FLASK_PARAM = re.compile(
    r"""request\.\s*(args|form|json|values|headers|cookies)\s*(?:\.\s*get\s*\(\s*['"](\w+)['"]|\.(\w+))""",
)

# FastAPI: def handler(foo: str = Query(...), bar: int = Body(...))
_PY_FASTAPI_PARAM = re.compile(
    r"""(\w+)\s*:\s*\w+\s*=\s*(Query|Body|Path|Header|Cookie)\s*\(""",
)


def _extract_python_params(content: str, filename: str, result: AnalysisResult) -> None:
    lines = content.splitlines()

    source_map = {
        "args": "query", "form": "body", "json": "body",
        "values": "query", "headers": "header", "cookies": "cookie",
    }
    fastapi_source_map = {
        "Query": "query", "Body": "body", "Path": "path",
        "Header": "header", "Cookie": "cookie",
    }

    for i, line in enumerate(lines, start=1):
        for m in _PY_FLASK_PARAM.finditer(line):
            name = m.group(2) or m.group(3)
            source = source_map.get(m.group(1), "query")
            if name and name != "get":
                result.parameters.append(ExtractedParameter(
                    name=name, source=source,
                    file=filename, line=i,
                ))

        for m in _PY_FASTAPI_PARAM.finditer(line):
            result.parameters.append(ExtractedParameter(
                name=m.group(1),
                source=fastapi_source_map.get(m.group(2), "query"),
                file=filename, line=i,
            ))


# ---------- Risk Indicator Detection ----------

_RISK_PATTERNS: list[tuple[str, re.Pattern, str, str, int | None]] = [
    # (name, pattern, description, severity, cwe_id)
    (
        "eval_usage",
        re.compile(r"""\beval\s*\("""),
        "Use of eval() can lead to code injection",
        "high",
        95,
    ),
    (
        "innerHTML_assignment",
        re.compile(r"""\.innerHTML\s*="""),
        "Direct innerHTML assignment can lead to XSS",
        "high",
        79,
    ),
    (
        "document_write",
        re.compile(r"""\bdocument\.write\s*\("""),
        "document.write can lead to XSS",
        "high",
        79,
    ),
    (
        "dangerouslySetInnerHTML",
        re.compile(r"""dangerouslySetInnerHTML"""),
        "React dangerouslySetInnerHTML can lead to XSS",
        "high",
        79,
    ),
    (
        "sql_string_concat",
        re.compile(r"""(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\+\s*(?:req|request|params|query|body|user)""", re.IGNORECASE),
        "SQL query built with string concatenation — possible SQL injection",
        "critical",
        89,
    ),
    (
        "sql_fstring",
        re.compile(r"""f['"]{1,3}(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)""", re.IGNORECASE),
        "SQL query built with f-string — possible SQL injection",
        "critical",
        89,
    ),
    (
        "sql_template_literal",
        re.compile(r"""`(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\$\{""", re.IGNORECASE),
        "SQL query with template literal interpolation — possible SQL injection",
        "critical",
        89,
    ),
    (
        "exec_usage",
        re.compile(r"""\bexec\s*\("""),
        "Use of exec() can lead to code execution",
        "high",
        95,
    ),
    (
        "os_system",
        re.compile(r"""\bos\.system\s*\("""),
        "os.system() can lead to command injection",
        "critical",
        78,
    ),
    (
        "subprocess_shell",
        re.compile(r"""\bsubprocess\.\w+\(.*?shell\s*=\s*True"""),
        "subprocess with shell=True can lead to command injection",
        "high",
        78,
    ),
    (
        "child_process_exec",
        re.compile(r"""\bexec\s*\(\s*['"`]|child_process\.exec\s*\("""),
        "child_process.exec can lead to command injection",
        "critical",
        78,
    ),
    (
        "hardcoded_secret",
        re.compile(r"""(?:password|secret|api_?key|token|auth)\s*[:=]\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
        "Possible hardcoded secret or credential",
        "high",
        798,
    ),
    (
        "cors_wildcard",
        re.compile(r"""Access-Control-Allow-Origin[^*]*\*""", re.IGNORECASE),
        "CORS wildcard allows requests from any origin",
        "medium",
        942,
    ),
    (
        "debug_mode",
        re.compile(r"""(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|'1')"""),
        "Debug mode may be enabled",
        "medium",
        489,
    ),
    (
        "unvalidated_redirect",
        re.compile(r"""(?:redirect|location\.href|window\.location)\s*=.*?(?:req|request|params|query|url)""", re.IGNORECASE),
        "Redirect using user-controlled input — possible open redirect",
        "medium",
        601,
    ),
    (
        "jwt_none_algorithm",
        re.compile(r"""algorithm[s'":\s]+none""", re.IGNORECASE),
        "JWT with 'none' algorithm allows token forgery",
        "critical",
        345,
    ),
    (
        "weak_random",
        re.compile(r"""\bMath\.random\s*\("""),
        "Math.random() is not cryptographically secure",
        "low",
        338,
    ),
    (
        "disable_ssl_verify",
        re.compile(r"""(?:verify\s*[:=]\s*(?:False|false)|rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED)"""),
        "SSL/TLS verification disabled",
        "high",
        295,
    ),
]


def _extract_risk_indicators(
    content: str, filename: str, language: str, result: AnalysisResult
) -> None:
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip comments
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue

        for name, pattern, description, severity, cwe_id in _RISK_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()[:200]
                result.risk_indicators.append(RiskIndicator(
                    pattern_name=name,
                    description=description,
                    severity=severity,
                    file=filename,
                    line=i,
                    code_snippet=snippet,
                    cwe_id=cwe_id,
                ))
