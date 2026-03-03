"""Tests for source code analysis engine (Phase 7)."""

from __future__ import annotations

import pytest

from dimsum.source_analysis.analyzer import (
    AnalysisResult,
    analyze_source,
    detect_language,
)


class TestLanguageDetection:
    def test_javascript(self):
        assert detect_language("app.js") == "javascript"
        assert detect_language("index.jsx") == "javascript"
        assert detect_language("module.mjs") == "javascript"

    def test_typescript(self):
        assert detect_language("app.ts") == "typescript"
        assert detect_language("component.tsx") == "typescript"

    def test_python(self):
        assert detect_language("views.py") == "python"

    def test_unknown(self):
        assert detect_language("file.rb") is None
        assert detect_language("file.go") is None


class TestExpressRouteExtraction:
    def test_basic_routes(self):
        code = """
const express = require('express');
const app = express();

app.get('/api/users', getUsers);
app.post('/api/users', createUser);
app.put('/api/users/:id', updateUser);
app.delete('/api/users/:id', deleteUser);
"""
        result = analyze_source(code, "server.js")
        routes = result.routes
        assert len(routes) == 4
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[1].method == "POST"
        assert routes[2].path == "/api/users/:id"
        assert routes[2].method == "PUT"
        assert routes[3].method == "DELETE"

    def test_router_routes(self):
        code = """
const router = express.Router();
router.get('/items', listItems);
router.post('/items', addItem);
"""
        result = analyze_source(code, "routes.js")
        assert len(result.routes) == 2
        assert result.routes[0].framework == "express"

    def test_app_use_middleware(self):
        code = """
app.use('/api/v2', apiRouter);
"""
        result = analyze_source(code, "app.js")
        assert len(result.routes) == 1
        assert result.routes[0].method == "ALL"


class TestReactRouteExtraction:
    def test_route_paths(self):
        code = """
<Route path="/dashboard" element={<Dashboard />} />
<Route path="/users/:id" element={<UserProfile />} />
<Route path="/settings" element={<Settings />} />
"""
        result = analyze_source(code, "App.jsx")
        assert len(result.routes) == 3
        assert result.routes[0].path == "/dashboard"
        assert result.routes[1].path == "/users/:id"
        assert result.routes[2].framework == "react-router"


class TestFetchCallExtraction:
    def test_fetch_calls(self):
        code = """
fetch('/api/data')
axios.get('/api/users')
axios.post('/api/items')
"""
        result = analyze_source(code, "client.js")
        assert len(result.routes) >= 3
        paths = [r.path for r in result.routes]
        assert "/api/data" in paths
        assert "/api/users" in paths
        assert "/api/items" in paths


class TestJSParameterExtraction:
    def test_req_dot_access(self):
        code = """
const name = req.query.name;
const id = req.params.id;
const email = req.body.email;
const token = req.headers.authorization;
"""
        result = analyze_source(code, "handler.js")
        params = result.parameters
        assert len(params) == 4
        assert params[0].name == "name"
        assert params[0].source == "query"
        assert params[1].name == "id"
        assert params[1].source == "params"
        assert params[2].name == "email"
        assert params[2].source == "body"
        assert params[3].name == "authorization"
        assert params[3].source == "headers"

    def test_bracket_access(self):
        code = """
const q = req.query['search'];
const data = req.body["payload"];
"""
        result = analyze_source(code, "api.js")
        params = result.parameters
        assert len(params) == 2
        assert params[0].name == "search"
        assert params[1].name == "payload"

    def test_destructuring(self):
        code = """
const { username, password, remember } = req.body;
const { page, limit } = req.query;
"""
        result = analyze_source(code, "auth.js")
        params = result.parameters
        names = {p.name for p in params}
        assert "username" in names
        assert "password" in names
        assert "remember" in names
        assert "page" in names
        assert "limit" in names

    def test_search_params(self):
        code = """
const q = searchParams.get('query');
const page = urlParams.get('page');
"""
        result = analyze_source(code, "page.js")
        params = result.parameters
        assert len(params) == 2
        assert params[0].name == "query"
        assert params[0].source == "query"


class TestFlaskRouteExtraction:
    def test_basic_flask_routes(self):
        code = """
@app.route('/api/users', methods=['GET', 'POST'])
def users():
    pass

@bp.route('/api/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    pass
"""
        result = analyze_source(code, "views.py")
        routes = result.routes
        assert len(routes) == 3  # GET + POST for users, DELETE for items
        methods = {r.method for r in routes}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    def test_default_get_method(self):
        code = """
@app.route('/home')
def home():
    pass
"""
        result = analyze_source(code, "app.py")
        assert len(result.routes) == 1
        assert result.routes[0].method == "GET"


class TestFastAPIRouteExtraction:
    def test_fastapi_routes(self):
        code = """
@app.get('/api/items')
async def list_items():
    pass

@router.post('/api/items')
async def create_item():
    pass
"""
        result = analyze_source(code, "main.py")
        assert len(result.routes) == 2
        assert result.routes[0].method == "GET"
        assert result.routes[0].framework == "fastapi"
        assert result.routes[1].method == "POST"


class TestDjangoRouteExtraction:
    def test_django_paths(self):
        code = """
urlpatterns = [
    path('users/', views.users),
    path('users/<int:pk>/', views.user_detail),
    re_path(r'^api/v1/', include('api.urls')),
]
"""
        result = analyze_source(code, "urls.py")
        assert len(result.routes) == 3
        assert result.routes[0].framework == "django"


class TestPythonParameterExtraction:
    def test_flask_params(self):
        code = """
name = request.args.get('name')
email = request.form.get('email')
data = request.json.get('payload')
token = request.headers.get('Authorization')
"""
        result = analyze_source(code, "views.py")
        params = result.parameters
        assert len(params) == 4
        names = {p.name for p in params}
        assert "name" in names
        assert "email" in names
        assert "payload" in names
        assert "Authorization" in names

    def test_fastapi_params(self):
        code = """
async def handler(
    q: str = Query(...),
    body: dict = Body(...),
    user_id: int = Path(...),
):
    pass
"""
        result = analyze_source(code, "api.py")
        params = result.parameters
        names_sources = {(p.name, p.source) for p in params}
        assert ("q", "query") in names_sources
        assert ("body", "body") in names_sources
        assert ("user_id", "path") in names_sources


class TestRiskIndicators:
    def test_eval_usage(self):
        code = "const result = eval(userInput);"
        result = analyze_source(code, "script.js")
        risks = [r for r in result.risk_indicators if r.pattern_name == "eval_usage"]
        assert len(risks) >= 1
        assert risks[0].cwe_id == 95

    def test_innerhtml(self):
        code = "element.innerHTML = userContent;"
        result = analyze_source(code, "dom.js")
        risks = [r for r in result.risk_indicators if r.pattern_name == "innerHTML_assignment"]
        assert len(risks) == 1
        assert risks[0].severity == "high"

    def test_sql_injection_concat(self):
        code = 'query = "SELECT * FROM users WHERE name = " + req.body.name;'
        result = analyze_source(code, "db.js")
        risks = [r for r in result.risk_indicators if r.pattern_name == "sql_string_concat"]
        assert len(risks) >= 1
        assert risks[0].cwe_id == 89

    def test_sql_fstring(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = analyze_source(code, "db.py")
        risks = [r for r in result.risk_indicators if r.pattern_name == "sql_fstring"]
        assert len(risks) == 1
        assert risks[0].severity == "critical"

    def test_hardcoded_secret(self):
        code = 'const api_key = "PLACEHOLDER_SECRET_VALUE_FOR_TESTING";'
        result = analyze_source(code, "config.js")
        risks = [r for r in result.risk_indicators if r.pattern_name == "hardcoded_secret"]
        assert len(risks) >= 1
        assert risks[0].cwe_id == 798

    def test_cors_wildcard(self):
        code = """res.setHeader('Access-Control-Allow-Origin', '*');"""
        result = analyze_source(code, "middleware.js")
        risks = [r for r in result.risk_indicators if r.pattern_name == "cors_wildcard"]
        assert len(risks) == 1

    def test_os_system(self):
        code = "os.system(user_input)"
        result = analyze_source(code, "util.py")
        risks = [r for r in result.risk_indicators if r.pattern_name == "os_system"]
        assert len(risks) == 1
        assert risks[0].severity == "critical"

    def test_ssl_verify_disabled(self):
        code = "requests.get(url, verify=False)"
        result = analyze_source(code, "client.py")
        risks = [r for r in result.risk_indicators if r.pattern_name == "disable_ssl_verify"]
        assert len(risks) == 1

    def test_dangerously_set_innerHTML(self):
        code = '<div dangerouslySetInnerHTML={{__html: userInput}} />'
        result = analyze_source(code, "component.jsx")
        risks = [r for r in result.risk_indicators if r.pattern_name == "dangerouslySetInnerHTML"]
        assert len(risks) == 1

    def test_skips_comments(self):
        code = """
// eval(userInput)
# os.system(cmd)
* document.write(content)
"""
        result = analyze_source(code, "safe.js")
        assert len(result.risk_indicators) == 0

    def test_debug_mode(self):
        code = "DEBUG = True"
        result = analyze_source(code, "settings.py")
        risks = [r for r in result.risk_indicators if r.pattern_name == "debug_mode"]
        assert len(risks) == 1

    def test_weak_random(self):
        code = "const token = Math.random().toString(36);"
        result = analyze_source(code, "auth.js")
        risks = [r for r in result.risk_indicators if r.pattern_name == "weak_random"]
        assert len(risks) == 1


class TestAnalysisResultSerialization:
    def test_to_dict(self):
        result = analyze_source(
            "app.get('/test', handler);\nconst x = req.query.foo;",
            "app.js",
        )
        d = result.to_dict()
        assert "routes" in d
        assert "parameters" in d
        assert "risk_indicators" in d
        assert d["language"] == "javascript"
        assert len(d["routes"]) >= 1
        assert len(d["parameters"]) >= 1
