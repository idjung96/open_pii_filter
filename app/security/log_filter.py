"""Logging filter that scrubs PII patterns from emitted records (T6.1).

Installed at the root logger via :func:`install_pii_log_filter` from the
FastAPI lifespan startup. Every ``LogRecord`` flowing through any handler
has its ``msg`` / ``args`` / ``exc_text`` rewritten so the original PII
plaintext is replaced with ``[REDACTED-{TYPE}]``.

The filter is deliberately conservative: false positives (e.g. a 13-digit
order ID misread as a credit-card number) are acceptable because the
goal is privacy compliance, not log fidelity. Whatever a regex *might*
match is scrubbed.
"""

from __future__ import annotations

import logging
import re
from typing import Any

# ── Patterns ──────────────────────────────────────────────────────────────
# Each entry is (compiled regex, replacement label). Order matters: more
# specific patterns first so a digit run that *could* be an RRN is not
# captured by the looser credit-card matcher.

# Korean RRN: 6 digits, "-", 7 digits.
_RRN = re.compile(r"\b\d{6}-\d{7}\b")

# Korean business registration number: XXX-XX-XXXXX.
_BIZ_NUM = re.compile(r"\b\d{3}-\d{2}-\d{5}\b")

# Korean phone numbers — 010/02/0XX with optional separators.
# 02-XXXX-XXXX (Seoul) and 0XX-XXX(X)-XXXX (mobile / region) variants.
_PHONE_HYPHEN = re.compile(r"\b0\d{1,2}-\d{3,4}-\d{4}\b")
_PHONE_PLAIN = re.compile(r"\b01[016789]\d{7,8}\b")

# Email — simplified RFC 5322; good enough for log scrubbing.
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Credit-card-like: 13-19 consecutive digits, optionally separated by space
# or hyphen in groups of 4. Luhn check is intentionally NOT applied -
# privacy first, log fidelity second.
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_RRN, "[REDACTED-RRN]"),
    (_BIZ_NUM, "[REDACTED-BIZ]"),
    (_PHONE_HYPHEN, "[REDACTED-PHONE]"),
    (_PHONE_PLAIN, "[REDACTED-PHONE]"),
    (_EMAIL, "[REDACTED-EMAIL]"),
    # Card last so we don't swallow shorter PII first.
    (_CARD, "[REDACTED-CARD]"),
)


def _scrub_text(text: str) -> str:
    if not text:
        return text
    for pat, label in _PATTERNS:
        text = pat.sub(label, text)
    return text


def _scrub_value(value: Any) -> Any:
    """Recursively scrub values stashed in record.args / record.exc_text."""
    if isinstance(value, str):
        return _scrub_text(value)
    if isinstance(value, tuple):
        return tuple(_scrub_value(v) for v in value)
    if isinstance(value, list):
        return [_scrub_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub_value(v) for k, v in value.items()}
    return value


class PIIScrubFilter(logging.Filter):
    """logging.Filter that replaces matched PII patterns with redaction tags.

    The filter mutates ``record.msg``, ``record.args``, and any cached
    ``record.exc_text`` in place so the redacted form is what every
    downstream handler emits.
    """

    name = "pii-scrub"

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _scrub_text(record.msg)
        if record.args:
            record.args = _scrub_value(record.args)
        if record.exc_text:
            record.exc_text = _scrub_text(record.exc_text)
        # Pre-formatted message from getMessage() may already be cached.
        cached = getattr(record, "message", None)
        if isinstance(cached, str):
            record.message = _scrub_text(cached)
        return True


_INSTALLED = False


def install_pii_log_filter() -> None:
    """Attach :class:`PIIScrubFilter` to the root logger and every existing
    handler. Idempotent — safe to call multiple times.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    flt = PIIScrubFilter()
    root = logging.getLogger()
    root.addFilter(flt)
    for h in root.handlers:
        h.addFilter(flt)
    # Also patch existing named loggers' handlers — uvicorn / fastapi
    # configure their own handlers before the lifespan starts.
    for name in list(logging.Logger.manager.loggerDict.keys()):
        lg = logging.getLogger(name)
        for h in getattr(lg, "handlers", []) or []:
            h.addFilter(flt)
    _INSTALLED = True


def uninstall_pii_log_filter() -> None:
    """Test hook — remove the filter from root + handlers."""
    global _INSTALLED
    root = logging.getLogger()
    root.filters = [f for f in root.filters if not isinstance(f, PIIScrubFilter)]
    for h in root.handlers:
        h.filters = [f for f in h.filters if not isinstance(f, PIIScrubFilter)]
    for name in list(logging.Logger.manager.loggerDict.keys()):
        lg = logging.getLogger(name)
        for h in getattr(lg, "handlers", []) or []:
            h.filters = [f for f in h.filters if not isinstance(f, PIIScrubFilter)]
    _INSTALLED = False
