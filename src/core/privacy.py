"""Shared best-effort redaction for scanner evidence and exported artifacts."""
from __future__ import annotations

import json
import re
from typing import Any


_SECRET_NAMES = r"password|passwd|private[_-]?key|secret[_-]?key|secret|credentials|client[_-]?secret|(?:access[_-]?|refresh[_-]?)?token|api[_-]?key|x[_-]?(?:zap[_-]?)?api[_-]?key|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|session[_-]?id"
_SECRET_KEY = re.compile(r"^(?:" + _SECRET_NAMES + r")$", re.I)
_HEADER = re.compile(r"(?i)(\b(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-ZAP-API-Key)\s*:\s*)[^\r\n]*")
_ASSIGNMENT = re.compile(
    r'''(?i)(\b(?:''' + _SECRET_NAMES + r''')\b["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)'''
)
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^/\s@]+@")
_QUERY = re.compile(r"(?i)([?&](?:" + _SECRET_NAMES + r")=)[^&#\s\"']*")

_PROVIDER_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def sanitize_text(value: str, _depth: int = 0) -> str:
    # Evidence often contains an encoded JSON object. Parse it so raw request
    # headers can be redacted after escaped newlines are decoded.
    if _depth < 24 and value.lstrip().startswith(("{", "[")):
        try:
            structured = json.loads(value)
        except (ValueError, RecursionError):
            pass
        else:
            if isinstance(structured, (dict, list)):
                return json.dumps(sanitize_data(structured, _depth + 1), ensure_ascii=False)
    value = _HEADER.sub(r"\1[REDACTED]", value)
    value = _AUTH_SCHEME.sub(r"\1 [REDACTED]", value)
    value = _QUERY.sub(r"\1[REDACTED]", value)
    value = _ASSIGNMENT.sub(r"\1[REDACTED]", value)
    value = _URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    value = _PROVIDER_TOKEN.sub("[REDACTED_TOKEN]", value)
    return _JWT.sub("[REDACTED_JWT]", value)


def sanitize_data(value: Any, _depth: int = 0) -> Any:
    """Return a redacted copy; never mutate database/model objects in place."""
    if _depth > 24:
        return "[REDACTED_NESTED_DATA]"
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if _SECRET_KEY.fullmatch(str(key))
                else sanitize_data(item, _depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_data(item, _depth + 1) for item in value]
    if isinstance(value, str):
        return sanitize_text(value, _depth)
    return value
