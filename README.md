# dimsum

A Dynamic Application Security Testing (DAST) scanner built with Python and Flask. Dimsum scans web applications for OWASP Top 10 vulnerabilities using a plugin-based architecture, with source-code-guided fuzzing, ASVS compliance mapping, and multi-format reporting.

## Features

### Scanning — 11 Plugins in 3 Categories

| Category | Plugin | OWASP / Purpose |
|----------|--------|-----------------|
| **Enumeration** | Web Crawler | Discovers links, forms, and endpoints by spidering the target |
| | Directory Brute-Force | Finds exposed files and directories (65+ default paths, soft-404 filtering) |
| | Tech Fingerprinting | Identifies frameworks and servers via headers, cookies, and HTML patterns |
| **Injection** | Reflected XSS | A03:2021 — Injection |
| | SQL Injection (Error + Time-Based) | A03:2021 — Injection |
| | OS Command Injection | A03:2021 — Injection |
| **Misconfiguration & Auth** | Security Headers | A05:2021 — Security Misconfiguration |
| | CORS Misconfiguration | A05:2021 — Security Misconfiguration |
| | Broken Authentication | A07:2021 — Identification & Auth Failures |
| | TLS & Cryptographic Failures | A02:2021 — Cryptographic Failures |
| | Server-Side Request Forgery | A10:2021 — SSRF |

### Source Code Analysis

Upload application source code (JavaScript, TypeScript, Python) and dimsum extracts:

- **Routes** — endpoints from Express, Flask, Django, FastAPI, React Router, and more
- **Parameters** — query, body, header, path, and cookie params with source location
- **Risk indicators** — 17 patterns including SQL injection, eval usage, hardcoded secrets, CORS wildcards, and debug mode

Extracted routes and parameters are fed directly into scans as fuzz targets, so injection plugins test real parameters from your codebase instead of guessing common names.

### Report Generation

Four output formats:

| Format | Use Case |
|--------|----------|
| **JSON** | Structured data for automation and dashboards |
| **CSV** | Spreadsheet-compatible tabular export |
| **SARIF 2.1.0** | CI/CD integration (GitHub Advanced Security, Azure DevOps) |
| **HTML** | Print-ready report with severity color-coding and summary cards |

### ASVS Compliance

40+ OWASP ASVS 4.0.3 checks mapped to CWE IDs and dimsum plugins. Run a compliance report to see pass/fail/partial/not-tested status for each requirement, with gap analysis for remediation planning. Supports ASVS levels 1, 2, and 3.

### Wordlist Management

Built-in wordlists for common paths, subdomains, and parameters. Upload custom wordlists for targeted enumeration. CRUD API with pagination and built-in list protection.

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose

### Run with Docker

```bash
git clone https://github.com/devsecmatt/dimsum.git
cd dimsum
docker compose up -d
```

The app will be available at **http://localhost:5050**.

Default credentials: `admin` / `admin`

### What starts

| Service | Description | Port |
|---------|-------------|------|
| **web** | Flask app + web UI | 5050 |
| **celery-worker** | Async scan executor | — |
| **postgres** | PostgreSQL 16 database | 5432 |
| **redis** | Message broker + result backend | 6379 |

## Workflows

### Standard Scan

Create a project, add targets, and launch a scan. Dimsum crawls the target, runs all security plugins, and produces findings with severity, evidence, and remediation guidance.

```bash
# Login
curl -c cookies.txt -X POST http://localhost:5050/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Create project + add target
curl -b cookies.txt -X POST http://localhost:5050/api/projects/ \
  -H "Content-Type: application/json" \
  -d '{"name":"My App"}'

curl -b cookies.txt -X POST http://localhost:5050/api/projects/<project_id>/targets \
  -H "Content-Type: application/json" \
  -d '{"target_type":"url","value":"https://example.com"}'

# Launch scan
curl -b cookies.txt -X POST http://localhost:5050/api/projects/<project_id>/scans \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"full","target_ids":["<target_id>"]}'
```

### Source-Guided Scan

Upload your application source code so dimsum can extract real routes and parameters, then use them as fuzz targets during scanning.

```bash
# 1. Upload source files
curl -b cookies.txt -X POST \
  http://localhost:5050/api/projects/<project_id>/source/upload \
  -F "file=@server.js"

curl -b cookies.txt -X POST \
  http://localhost:5050/api/projects/<project_id>/source/upload \
  -F "file=@app.py"

# 2. Trigger analysis
curl -b cookies.txt -X POST \
  http://localhost:5050/api/projects/<project_id>/source/analyze

# 3. Review extracted routes, parameters, and risk indicators
curl -b cookies.txt \
  http://localhost:5050/api/projects/<project_id>/source/results

# 4. Create a scan config with source analysis enabled
curl -b cookies.txt -X POST \
  http://localhost:5050/api/projects/<project_id>/configs \
  -H "Content-Type: application/json" \
  -d '{"name":"Source-guided","enable_source_analysis":true}'

# 5. Launch scan with that config — injection plugins now test
#    the exact parameters found in your source code
curl -b cookies.txt -X POST \
  http://localhost:5050/api/projects/<project_id>/scans \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"full","config_id":"<config_id>","target_ids":["<target_id>"]}'
```

When `enable_source_analysis` is true, the scan engine:
1. Loads all completed source analysis results for the project
2. Converts extracted routes into discoverable endpoints
3. Passes extracted parameters to injection plugins (XSS, SQLi, CMDi)
4. Plugins fuzz each parameter based on its source type (query → GET params, body → POST data)

### Compliance Audit

After a scan completes, generate an ASVS compliance report to see which security requirements pass, fail, or need manual testing.

```bash
# Run compliance report against a completed scan
curl -b cookies.txt \
  http://localhost:5050/api/asvs/compliance/<scan_id>?level=1

# Get gap analysis (failed + untested checks)
curl -b cookies.txt \
  http://localhost:5050/api/asvs/gaps/<scan_id>?level=1

# Generate a SARIF report for CI/CD
curl -b cookies.txt -X POST \
  http://localhost:5050/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"scan_id":"<scan_id>","format":"sarif"}' \
  -o report.sarif
```

## API Reference

All endpoints require authentication via session cookie.

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Log in |
| POST | `/api/auth/logout` | Log out |
| GET | `/api/auth/me` | Current user info |

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects/` | List projects |
| POST | `/api/projects/` | Create project |
| GET | `/api/projects/<id>` | Get project details |
| PUT | `/api/projects/<id>` | Update project |
| DELETE | `/api/projects/<id>` | Delete project |
| GET | `/api/projects/<id>/stats` | Project statistics (finding counts by severity) |

### Targets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects/<id>/targets` | List targets |
| POST | `/api/projects/<id>/targets` | Add target (url, domain, ip, api_spec) |
| DELETE | `/api/projects/<id>/targets/<tid>` | Remove target |
| POST | `/api/projects/<id>/targets/import-urls` | Bulk URL import |
| POST | `/api/projects/<id>/targets/import-spec` | Import OpenAPI / Swagger / Postman spec |

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects/<id>/scans` | List scans |
| POST | `/api/projects/<id>/scans` | Launch scan (`scan_type`: full, quick, enumeration, source_only) |
| GET | `/api/projects/<id>/scans/<sid>` | Scan details |
| GET | `/api/projects/<id>/scans/<sid>/progress` | Real-time progress |
| POST | `/api/projects/<id>/scans/<sid>/cancel` | Cancel running scan |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/findings/?scan_id=<sid>` | List findings (filter by `severity`, `plugin_id`, `false_positive`) |
| GET | `/api/findings/<fid>` | Get finding details |
| PATCH | `/api/findings/<fid>` | Update finding (mark false positive, add notes) |

### Source Code Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/projects/<id>/source/upload` | Upload source file (.js, .ts, .py) |
| GET | `/api/projects/<id>/source/files` | List uploaded files with analysis status |
| POST | `/api/projects/<id>/source/analyze` | Trigger analysis (optionally specify `file_ids`) |
| GET | `/api/projects/<id>/source/results` | Get extracted routes, parameters, and risk indicators |
| DELETE | `/api/projects/<id>/source/<upload_id>` | Delete uploaded file |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/reports/generate` | Generate report (`format`: json, csv, sarif, html) |
| GET | `/api/reports/preview/<scan_id>` | Preview HTML report inline |
| GET | `/api/reports/summary/<scan_id>` | Quick summary (counts by severity and plugin) |

### ASVS Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/asvs/checks` | List ASVS checks (filter by `chapter`, `level`, `automatable`) |
| GET | `/api/asvs/checks/<asvs_id>` | Get ASVS check details |
| GET | `/api/asvs/compliance/<scan_id>` | Full compliance report (filter by `level`) |
| GET | `/api/asvs/gaps/<scan_id>` | Gap analysis: failed and untested checks |
| POST | `/api/asvs/seed` | Seed/update ASVS checks database |

### Wordlists

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/wordlists/` | List all wordlists (built-in + custom) |
| GET | `/api/wordlists/<wid>` | Get wordlist metadata with 20-entry preview |
| POST | `/api/wordlists/` | Upload custom wordlist (.txt, .lst, .csv) |
| PUT | `/api/wordlists/<wid>` | Update wordlist name/description |
| DELETE | `/api/wordlists/<wid>` | Delete custom wordlist (built-in protected) |
| GET | `/api/wordlists/<wid>/entries` | Paginated wordlist entries (`offset`, `limit`) |

### Scan Configs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects/<id>/configs` | List scan configurations |
| POST | `/api/projects/<id>/configs` | Create scan configuration |
| GET | `/api/projects/<id>/configs/<cid>` | Get configuration |
| PUT | `/api/projects/<id>/configs/<cid>` | Update configuration |
| DELETE | `/api/projects/<id>/configs/<cid>` | Delete configuration |

### Plugins

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/plugins/` | List available plugins with metadata |

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌─────────────┐
│   Web UI    │────>│ Flask API│────>│  PostgreSQL  │
│ (Jinja2)    │     │          │     │   (Models)   │
└─────────────┘     └────┬─────┘     └──────┬──────┘
                         │                   │
                    ┌────▼─────┐      ┌──────▼──────┐
                    │  Celery  │      │   Source     │
                    │  Worker  │      │  Uploads     │
                    └────┬─────┘      └──────┬──────┘
                         │                   │
                    ┌────▼─────┐      ┌──────▼──────┐
                    │  Scan    │◄─────│   Source     │
                    │  Engine  │      │  Analysis    │
                    └────┬─────┘      │  (routes,   │
                         │            │  params,     │
          ┌──────────────┼────┐       │  risks)      │
          ▼              ▼    ▼       └─────────────┘
   ┌───────────┐  ┌─────────┐ ┌─────────┐
   │Enumeration│  │Injection│ │ Misconf  │
   │ Plugins   │  │ Plugins │ │ Plugins  │
   │           │  │         │ │          │
   │ crawler   │  │ xss     │ │ headers  │
   │ dir_brute │  │ sqli    │ │ cors     │
   │ tech_fp   │  │ cmdi    │ │ auth     │
   └───────────┘  └─────────┘ │ tls      │
                               │ ssrf     │
          ┌────────────────────┘──────────┘
          ▼
   ┌─────────────┐     ┌─────────────┐
   │  Findings   │────>│   Reports   │
   │  (DB)       │     │ JSON/CSV/   │
   └─────────────┘     │ SARIF/HTML  │
          │             └─────────────┘
          ▼
   ┌─────────────┐
   │    ASVS     │
   │ Compliance  │
   │ (40+ checks)│
   └─────────────┘
```

### Adding a Plugin

Create a new file in `src/dimsum/scanner/plugins/<category>/` and use the decorator:

```python
from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity

@PluginRegistry.register(
    "my_plugin",
    name="My Security Check",
    category="injection",
    owasp_category="A03:2021-Injection",
    cwe_ids=[79],
    description="Checks for something.",
)
class MyPlugin(BaseScanPlugin):
    async def run(self) -> list[ScanFinding]:
        findings = []
        for url in self.get_target_urls():
            resp = await self.http.get(url)
            if resp and "vulnerable" in resp.text:
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title="Vulnerability Found",
                    description="...",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    url=url,
                    method="GET",
                ))
        return findings
```

Plugins can also consume source-analysis-extracted parameters via `self.get_extracted_params_by_source("query", "body")`.

The plugin is automatically discovered and available in the next scan.

## Development

### Local Setup (without Docker)

Requires Python 3.11+, PostgreSQL, and Redis running locally.

```bash
pip install -e ".[dev]"
make init-db
make dev            # Flask dev server on :5050
make celery-worker  # In another terminal
```

### Running Tests

Tests use SQLite in-memory for portability (no PostgreSQL required):

```bash
make test           # or: python -m pytest tests/ -v
```

### Makefile Targets

```
make install        Install dependencies
make dev            Run Flask dev server
make test           Run tests with pytest
make lint           Run ruff linter
make lint-fix       Auto-fix lint issues
make init-db        Initialize database
make docker-build   Build Docker images
make docker-up      Start all services
make docker-down    Stop all services
make docker-logs    Tail container logs
make docker-shell   Shell into web container
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret | `dev-secret-key` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://dimsum:dimsum@localhost:5432/dimsum` |
| `CELERY_BROKER_URL` | Redis broker URL | `redis://localhost:6379/0` |
| `CELERY_RESULT_BACKEND` | Redis result backend URL | `redis://localhost:6379/1` |
| `ADMIN_USERNAME` | Initial admin username | — |
| `ADMIN_PASSWORD` | Initial admin password | — |
| `ADMIN_EMAIL` | Initial admin email | — |

### Scan Configuration Options

Reusable scan configs can be created per-project via the API:

| Option | Default | Range / Type |
|--------|---------|-------------|
| `max_concurrency` | 10 | 1–100 |
| `request_delay_ms` | 100 | 0–10000 |
| `timeout_seconds` | 30 | 1–300 |
| `max_depth` | 3 | 1–20 |
| `asvs_level` | 1 | 1–3 |
| `custom_headers` | `{}` | JSON object |
| `enabled_plugins` | `[]` | Array of plugin IDs |
| `enable_enumeration` | false | boolean |
| `enable_source_analysis` | false | boolean — loads extracted routes/params into scan |
| `wordlist_ids` | `[]` | Array of wordlist UUIDs |
| `auth_config` | null | `{"type":"basic","username":"...","password":"..."}` or `{"type":"bearer","token":"..."}` |

## Tech Stack

- **Backend**: Flask, SQLAlchemy, Alembic, Marshmallow
- **Database**: PostgreSQL 16 (SQLite for tests)
- **Task Queue**: Celery + Redis
- **HTTP Client**: httpx (async)
- **Auth**: Flask-Login (session-based)
- **Frontend**: Jinja2 templates, vanilla JS
- **Deployment**: Docker Compose

## License

MIT
