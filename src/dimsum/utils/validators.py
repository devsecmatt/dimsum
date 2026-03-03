from __future__ import annotations

from dimsum.utils.url_utils import is_valid_domain, is_valid_ip, is_valid_url, normalize_url


def validate_target(target_type: str, value: str) -> tuple[bool, str, str]:
    """Validate a target value based on its type.

    Returns:
        (is_valid, normalized_value, error_message)
    """
    value = value.strip()
    if not value:
        return False, value, "Target value cannot be empty."

    if target_type == "url":
        normalized = normalize_url(value)
        if not is_valid_url(normalized):
            return False, value, f"Invalid URL: {value}"
        return True, normalized, ""

    if target_type == "domain":
        value_lower = value.lower()
        if not is_valid_domain(value_lower):
            return False, value, f"Invalid domain: {value}"
        return True, value_lower, ""

    if target_type == "ip":
        if not is_valid_ip(value):
            return False, value, f"Invalid IP address: {value}"
        return True, value, ""

    if target_type == "url_list":
        # Value should be a URL for url_list entries
        normalized = normalize_url(value)
        if not is_valid_url(normalized):
            return False, value, f"Invalid URL in list: {value}"
        return True, normalized, ""

    if target_type == "api_spec":
        # Value is the base URL for the API
        normalized = normalize_url(value)
        if not is_valid_url(normalized):
            return False, value, f"Invalid base URL: {value}"
        return True, normalized, ""

    return False, value, f"Unknown target type: {target_type}"


def validate_api_spec(spec: dict, spec_format: str) -> tuple[bool, str]:
    """Validate an API specification document.

    Returns:
        (is_valid, error_message)
    """
    if not isinstance(spec, dict):
        return False, "API spec must be a JSON object."

    if spec_format == "openapi_3":
        if "openapi" not in spec:
            return False, "Missing 'openapi' version field."
        if "paths" not in spec:
            return False, "Missing 'paths' field."
        return True, ""

    if spec_format == "swagger_2":
        if "swagger" not in spec:
            return False, "Missing 'swagger' version field."
        if "paths" not in spec:
            return False, "Missing 'paths' field."
        return True, ""

    if spec_format == "postman":
        if "info" not in spec and "item" not in spec:
            return False, "Missing 'info' or 'item' field for Postman collection."
        return True, ""

    return False, f"Unknown spec format: {spec_format}"
