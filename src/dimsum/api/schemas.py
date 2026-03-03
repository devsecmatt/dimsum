from __future__ import annotations

from marshmallow import Schema, fields, validate, validates, ValidationError


# --- Auth ---

class LoginSchema(Schema):
    username = fields.String(required=True, validate=validate.Length(min=1, max=80))
    password = fields.String(required=True, validate=validate.Length(min=1))


# --- Projects ---

class ProjectCreateSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1, max=200))
    description = fields.String(load_default=None, validate=validate.Length(max=2000))


class ProjectUpdateSchema(Schema):
    name = fields.String(validate=validate.Length(min=1, max=200))
    description = fields.String(allow_none=True, validate=validate.Length(max=2000))


# --- Targets ---

VALID_TARGET_TYPES = ("url", "url_list", "domain", "ip", "api_spec")
VALID_API_SPEC_FORMATS = ("openapi_3", "swagger_2", "postman")


class TargetCreateSchema(Schema):
    target_type = fields.String(
        required=True, validate=validate.OneOf(VALID_TARGET_TYPES)
    )
    value = fields.String(required=True, validate=validate.Length(min=1, max=2048))
    api_spec_format = fields.String(
        load_default=None, validate=validate.OneOf(VALID_API_SPEC_FORMATS)
    )
    api_spec_content = fields.Dict(load_default=None)

    @validates("value")
    def validate_value(self, value):
        # Basic sanity — detailed validation in url_utils
        if not value.strip():
            raise ValidationError("Target value cannot be empty.")


class APISpecImportSchema(Schema):
    base_url = fields.String(required=True, validate=validate.Length(min=1, max=2048))
    format = fields.String(
        load_default="openapi_3", validate=validate.OneOf(VALID_API_SPEC_FORMATS)
    )
    spec = fields.Raw(required=True)


class URLListImportSchema(Schema):
    urls = fields.List(fields.String(validate=validate.Length(min=1, max=2048)), required=True)


# --- Scans ---

VALID_SCAN_TYPES = ("full", "quick", "enumeration", "source_only")


class ScanCreateSchema(Schema):
    scan_type = fields.String(
        load_default="full", validate=validate.OneOf(VALID_SCAN_TYPES)
    )
    target_ids = fields.List(fields.String(), load_default=[])
    config_id = fields.String(load_default=None)


# --- Scan Configuration ---

class ScanConfigCreateSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1, max=200))
    enabled_plugins = fields.List(fields.String(), load_default=[])
    max_concurrency = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))
    request_delay_ms = fields.Integer(load_default=100, validate=validate.Range(min=0, max=10000))
    timeout_seconds = fields.Integer(load_default=30, validate=validate.Range(min=1, max=300))
    max_depth = fields.Integer(load_default=3, validate=validate.Range(min=1, max=20))
    custom_headers = fields.Dict(keys=fields.String(), values=fields.String(), load_default={})
    auth_config = fields.Dict(load_default=None, allow_none=True)
    wordlist_ids = fields.List(fields.String(), load_default=[])
    enable_enumeration = fields.Boolean(load_default=False)
    enable_source_analysis = fields.Boolean(load_default=False)
    asvs_level = fields.Integer(load_default=1, validate=validate.OneOf([1, 2, 3]))


class ScanConfigUpdateSchema(Schema):
    name = fields.String(validate=validate.Length(min=1, max=200))
    enabled_plugins = fields.List(fields.String())
    max_concurrency = fields.Integer(validate=validate.Range(min=1, max=100))
    request_delay_ms = fields.Integer(validate=validate.Range(min=0, max=10000))
    timeout_seconds = fields.Integer(validate=validate.Range(min=1, max=300))
    max_depth = fields.Integer(validate=validate.Range(min=1, max=20))
    custom_headers = fields.Dict(keys=fields.String(), values=fields.String())
    auth_config = fields.Dict(allow_none=True)
    wordlist_ids = fields.List(fields.String())
    enable_enumeration = fields.Boolean()
    enable_source_analysis = fields.Boolean()
    asvs_level = fields.Integer(validate=validate.OneOf([1, 2, 3]))


# --- Findings ---

class FindingUpdateSchema(Schema):
    is_false_positive = fields.Boolean()
    notes = fields.String(allow_none=True, validate=validate.Length(max=5000))


# --- Reports ---

VALID_REPORT_FORMATS = ("json", "pdf", "csv", "sarif")


class ReportGenerateSchema(Schema):
    scan_id = fields.String(required=True)
    format = fields.String(
        load_default="json", validate=validate.OneOf(VALID_REPORT_FORMATS)
    )
    options = fields.Dict(load_default={})
