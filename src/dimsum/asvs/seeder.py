"""Seed the database with ASVS 4.0.3 checks.

This module provides a curated subset of ASVS checks that can be
validated through DAST scanning, along with their associated CWE IDs
and the dimsum plugin IDs that test them.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Curated ASVS 4.0.3 checks relevant to DAST scanning
# (asvs_id, chapter, section, requirement, level, cwe_id, can_be_automated, plugin_ids)
ASVS_CHECKS = [
    # V2: Authentication
    ("V2.1.1", 2, "2.1", "Verify that user set passwords are at least 12 characters in length.", 1, 521, False, []),
    ("V2.2.1", 2, "2.2", "Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks.", 1, 307, True, ["broken_auth"]),
    ("V2.5.4", 2, "2.5", "Verify that shared or default accounts are not present (e.g. root, admin, sa).", 1, 798, True, ["broken_auth"]),

    # V3: Session Management
    ("V3.1.1", 3, "3.1", "Verify the application never reveals session tokens in URL parameters.", 1, 598, True, ["security_headers"]),
    ("V3.2.1", 3, "3.2", "Verify the application generates a new session token on user authentication.", 1, 384, False, []),
    ("V3.4.1", 3, "3.4", "Verify that cookie-based session tokens have the Secure attribute set.", 1, 614, True, ["security_headers"]),
    ("V3.4.2", 3, "3.4", "Verify that cookie-based session tokens have the HttpOnly attribute set.", 1, 1004, True, ["security_headers"]),
    ("V3.4.3", 3, "3.4", "Verify that cookie-based session tokens utilize the SameSite attribute.", 1, 1275, True, ["security_headers"]),

    # V4: Access Control
    ("V4.1.1", 4, "4.1", "Verify that the application enforces access control rules on a trusted service layer.", 1, 602, False, []),
    ("V4.2.1", 4, "4.2", "Verify that sensitive data and APIs are protected against IDOR attacks.", 1, 639, False, []),

    # V5: Validation, Sanitization and Encoding
    ("V5.1.1", 5, "5.1", "Verify that the application has defenses against HTTP parameter pollution attacks.", 1, 235, True, ["reflected_xss"]),
    ("V5.2.1", 5, "5.2", "Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized.", 1, 116, True, ["reflected_xss"]),
    ("V5.3.3", 5, "5.3", "Verify that the application sanitizes user input before passing to mail systems.", 2, 147, False, []),
    ("V5.3.4", 5, "5.3", "Verify that the application does not use eval() or other dynamic code execution features.", 2, 95, True, ["reflected_xss"]),
    ("V5.3.7", 5, "5.3", "Verify that the application is not vulnerable to SQL Injection.", 1, 89, True, ["sql_injection"]),
    ("V5.3.8", 5, "5.3", "Verify that the application is not vulnerable to OS Command Injection.", 1, 78, True, ["command_injection"]),

    # V6: Stored Cryptography
    ("V6.2.1", 6, "6.2", "Verify that all cryptographic modules fail securely.", 1, 310, False, []),

    # V7: Error Handling and Logging
    ("V7.1.1", 7, "7.1", "Verify that the application does not log credentials or payment details.", 1, 532, False, []),
    ("V7.4.1", 7, "7.4", "Verify that a generic message is shown when an unexpected or security sensitive error occurs.", 1, 210, True, ["security_headers"]),

    # V8: Data Protection
    ("V8.1.1", 8, "8.1", "Verify the application protects sensitive data from being cached in server components.", 1, 524, True, ["security_headers"]),
    ("V8.3.1", 8, "8.3", "Verify that sensitive data is sent to the server in the HTTP message body or headers.", 1, 319, True, ["tls_crypto"]),

    # V9: Communication
    ("V9.1.1", 9, "9.1", "Verify that TLS is used for all client connectivity.", 1, 319, True, ["tls_crypto"]),
    ("V9.1.2", 9, "9.1", "Verify using up to date TLS testing tools that only strong cipher suites are enabled.", 2, 326, True, ["tls_crypto"]),
    ("V9.1.3", 9, "9.1", "Verify that old versions of SSL and TLS protocols, algorithms, ciphers, and configuration are disabled.", 1, 326, True, ["tls_crypto"]),

    # V10: Malicious Code
    ("V10.3.1", 10, "10.3", "Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels.", 1, 16, False, []),

    # V11: Business Logic
    ("V11.1.1", 11, "11.1", "Verify the application will only process business logic flows for the same user in sequential step order.", 1, 841, False, []),

    # V12: Files and Resources
    ("V12.1.1", 12, "12.1", "Verify that the application will not accept large files that could fill up storage.", 1, 400, False, []),
    ("V12.3.1", 12, "12.3", "Verify that user-submitted filename metadata is not used directly by system or framework filesystems.", 1, 22, False, []),

    # V13: API and Web Service
    ("V13.1.1", 13, "13.1", "Verify that all application components use the same encodings and parsers to avoid parsing attacks.", 1, 116, True, ["reflected_xss"]),
    ("V13.2.1", 13, "13.2", "Verify that enabled RESTful HTTP methods are a valid choice for the user or action.", 1, 650, True, ["broken_auth"]),
    ("V13.2.5", 13, "13.2", "Verify that REST services explicitly check the incoming Content-Type to be the expected one.", 2, 436, False, []),

    # V14: Configuration
    ("V14.2.1", 14, "14.2", "Verify that all components are up to date.", 1, 1104, False, []),
    ("V14.4.1", 14, "14.4", "Verify that every HTTP response contains a Content-Type header specifying a safe character set.", 1, 173, True, ["security_headers"]),
    ("V14.4.3", 14, "14.4", "Verify that a Content-Security-Policy response header is in place.", 1, 693, True, ["security_headers"]),
    ("V14.4.4", 14, "14.4", "Verify that all responses contain a X-Content-Type-Options: nosniff header.", 1, 116, True, ["security_headers"]),
    ("V14.4.5", 14, "14.4", "Verify that a Strict-Transport-Security header is included on all responses.", 1, 523, True, ["security_headers"]),
    ("V14.4.6", 14, "14.4", "Verify that an appropriate Referrer-Policy header is included.", 1, 116, True, ["security_headers"]),
    ("V14.4.7", 14, "14.4", "Verify that the content of a web application cannot be embedded in a third-party site by default.", 1, 1021, True, ["security_headers"]),
    ("V14.5.1", 14, "14.5", "Verify that the application server only accepts the HTTP methods in use by the application/API.", 1, 749, True, ["cors_misconfig"]),
    ("V14.5.3", 14, "14.5", "Verify that the Origin header is validated against a defined list of allowed origins.", 2, 346, True, ["cors_misconfig"]),

    # V10.2: SSRF
    ("V10.2.1", 10, "10.2", "Verify that the application does not perform SSRF attacks.", 1, 918, True, ["ssrf"]),
]


def seed_asvs_checks() -> int:
    """Insert ASVS checks into the database. Returns count of new records created."""
    from dimsum.extensions import db
    from dimsum.models.asvs_check import ASVSCheck

    created = 0
    for asvs_id, chapter, section, requirement, level, cwe_id, automated, plugin_ids in ASVS_CHECKS:
        existing = db.session.execute(
            db.select(ASVSCheck).filter_by(asvs_id=asvs_id)
        ).scalar_one_or_none()
        if existing:
            # Update plugin_ids if they changed
            if existing.plugin_ids != plugin_ids:
                existing.plugin_ids = plugin_ids
            continue

        check = ASVSCheck(
            asvs_id=asvs_id,
            chapter=chapter,
            section=section,
            requirement=requirement,
            level=level,
            cwe_id=cwe_id,
            can_be_automated=automated,
            plugin_ids=plugin_ids,
        )
        db.session.add(check)
        created += 1

    if created:
        db.session.commit()
        logger.info("Seeded %d ASVS checks", created)
    return created
