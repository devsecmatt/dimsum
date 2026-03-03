# dimsum

A Dynamic Application Security Testing (DAST) scanner built with Python and Flask. Dimsum scans web applications for OWASP Top 10 vulnerabilities using a plugin-based architecture, with async scanning powered by Celery and a web-based management UI.

## Features

- **Multi-target scanning** — URLs, domains, IPs, API specs (OpenAPI 3, Swagger 2, Postman)
- **8 security plugins** covering OWASP Top 10 categories:
  | Plugin | OWASP Category |
  |--------|---------------|
  | Reflected XSS | A03:2021 Injection |
  | SQL Injection (Error + Time-Based) | A03:2021 Injection |
  | OS Command Injection | A03:2021 Injection |
  | Security Headers Check | A05:2021 Security Misconfiguration |
  | CORS Misconfiguration | A05:2021 Security Misconfiguration |
  | Broken Authentication | A07:2021 Identification & Auth Failures |
  | TLS & Cryptographic Failures | A02:2021 Cryptographic Failures |
  | Server-Side Request Forgery | A10:2021 SSRF |
- **Async scan engine** with rate limiting, concurrency control, and real-time progress
- **Web UI** with project management, target configuration, scan monitoring, and findings browser
- **REST API** for programmatic access to all features
- **Multi-project support** with per-project targets, configs, and scan history
- **Plugin registry** — decorator-based auto-discovery makes adding new checks straightforward

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

## Usage

### Web UI

1. Log in at http://localhost:5050
2. Create a project from the dashboard
3. Add targets (URLs, domains, or IPs) on the project page
4. Click **Launch Scan** to start
5. Monitor progress in real-time on the scan detail page
6. Review findings with severity, evidence, and remediation guidance

### API

All endpoints require authentication. Log in first to get a session cookie:

```bash
# Login
curl -c cookies.txt -X POST http://localhost:5050/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Create a project
curl -b cookies.txt -X POST http://localhost:5050/api/projects/ \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","description":"Production web app"}'

# Add a target
curl -b cookies.txt -X POST http://localhost:5050/api/projects/<project_id>/targets \
  -H "Content-Type: application/json" \
  -d '{"target_type":"url","value":"https://example.com"}'

# Launch a scan
curl -b cookies.txt -X POST http://localhost:5050/api/projects/<project_id>/scans \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"full","target_ids":["<target_id>"]}'

# Check scan progress
curl -b cookies.txt http://localhost:5050/api/projects/<project_id>/scans/<scan_id>/progress

# List findings
curl -b cookies.txt http://localhost:5050/api/findings/?scan_id=<scan_id>

# List available plugins
curl -b cookies.txt http://localhost:5050/api/plugins/
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Log in |
| POST | `/api/auth/logout` | Log out |
| GET | `/api/auth/me` | Current user info |
| GET/POST | `/api/projects/` | List / create projects |
| GET/PUT/DELETE | `/api/projects/<id>` | Get / update / delete project |
| GET | `/api/projects/<id>/stats` | Project statistics |
| GET/POST | `/api/projects/<id>/targets` | List / create targets |
| POST | `/api/projects/<id>/targets/import-urls` | Bulk URL import |
| POST | `/api/projects/<id>/targets/import-spec` | Import API spec |
| DELETE | `/api/projects/<id>/targets/<tid>` | Remove target |
| GET/POST | `/api/projects/<id>/scans` | List / launch scans |
| GET | `/api/projects/<id>/scans/<sid>` | Scan details |
| GET | `/api/projects/<id>/scans/<sid>/progress` | Scan progress |
| POST | `/api/projects/<id>/scans/<sid>/cancel` | Cancel scan |
| GET | `/api/findings/` | List findings (filterable) |
| GET/PATCH | `/api/findings/<fid>` | Get / update finding |
| GET/POST | `/api/projects/<id>/configs` | List / create scan configs |
| GET/PUT/DELETE | `/api/projects/<id>/configs/<cid>` | Manage scan configs |
| GET | `/api/plugins/` | List available plugins |

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌─────────────┐
│   Web UI    │────>│ Flask API│────>│  PostgreSQL  │
│ (Jinja2)    │     │          │     │   (Models)   │
└─────────────┘     └────┬─────┘     └─────────────┘
                         │
                    ┌────▼─────┐     ┌─────────────┐
                    │  Celery  │────>│    Redis     │
                    │  Worker  │     │  (Broker)    │
                    └────┬─────┘     └─────────────┘
                         │
                    ┌────▼─────┐
                    │  Scan    │
                    │  Engine  │
                    └────┬─────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ Plugin 1 │  │ Plugin 2 │  │ Plugin N │
    │ (XSS)    │  │ (SQLi)   │  │  (...)   │
    └──────────┘  └──────────┘  └──────────┘
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

Per-project scan configs can be set via the UI or API:

| Option | Default | Range |
|--------|---------|-------|
| Max concurrency | 10 | 1-100 |
| Request delay (ms) | 100 | 0-10000 |
| Timeout (s) | 30 | 1-300 |
| Max depth | 3 | 1-20 |
| ASVS level | 1 | 1-3 |
| Custom headers | `{}` | JSON object |
| Enable enumeration | false | — |

## Tech Stack

- **Backend**: Flask, SQLAlchemy, Alembic, Marshmallow
- **Database**: PostgreSQL 16
- **Task Queue**: Celery + Redis
- **HTTP Client**: httpx (async)
- **Auth**: Flask-Login (session-based)
- **Frontend**: Jinja2 templates, vanilla JS
- **Deployment**: Docker Compose

## License

MIT
