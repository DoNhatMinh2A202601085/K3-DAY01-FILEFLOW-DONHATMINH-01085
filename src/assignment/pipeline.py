"""
Assignment 11 - Defense-in-depth pipeline assembly (TODO).
  TODO 8: is_egress_allowed
  TODO 8: build_production_plugins
  TODO 8: build_observability
  TODO 8: run_assignment_suite

Wire rate limiter + lab guardrails + judge + audit + monitoring.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert


# ============================================================
# TODO 8A: Implement is_egress_allowed()
#
# Enforce a destination allowlist before any data leaves the agent.
# Return True only for an approved VinBank HTTPS endpoint and ordinary
# banking payload.
#
# BLOCK if:
# - Unknown domains (not in allowlist)
# - Fake domains (e.g., api.vinbank.example.evil.com)
# - Payload contains password, API key, database host, phone, email
#
# DO NOT let the LLM decide this policy.
# ============================================================

# Allowlist of approved VinBank domains (exact match required)
VINBANK_ALLOWED_HOSTS = {
    "api.vinbank.example",           # API domain
    "api.vinbank.com",               # Production API
    "www.vinbank.com",               # Website
    "secure.vinbank.com",            # Secure portal
    "api.vinbank.vn",               # Vietnamese domain
}


def is_egress_allowed(destination: str, payload: str) -> bool:
    """Check if egress is allowed for given destination and payload.

    Security policy enforcement - does NOT use LLM for decision.

    Args:
        destination: URL or hostname to send data to
        payload: Data that would be sent

    Returns:
        True if allowed, False if should be blocked
    """
    if not destination:
        return False

    # Step 1: Parse and validate destination
    # Remove protocol prefix if present for consistent parsing
    clean_dest = destination.strip()

    # Handle full URLs
    if '://' in clean_dest:
        parsed = urlparse(clean_dest)
        hostname = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme
    else:
        # Just a hostname
        hostname = clean_dest.split(':')[0].split('/')[0]
        port = None
        scheme = None

    # Normalize hostname to lowercase
    hostname = hostname.lower()

    # Step 2: Check scheme (must be HTTPS for production)
    if scheme and scheme.lower() != 'https':
        # Allow http only for localhost/internal during dev
        if not (hostname in ['localhost', '127.0.0.1'] or hostname.endswith('.local')):
            return False

    # Step 3: Check hostname against allowlist (EXACT MATCH ONLY)
    # This prevents subdomain attacks like api.vinbank.example.evil.com
    if hostname not in VINBANK_ALLOWED_HOSTS:
        return False

    # Step 4: Check payload for sensitive data
    if payload:
        payload_lower = payload.lower()

        # Check for secrets
        SENSITIVE_PATTERNS = {
            # Passwords
            "password": r'\b(password|passwd|pwd)\s*[:=]\s*\S+',
            # API keys
            "api_key": r'\b(api[_-]?key|apikey)\s*[:=]\s*\S+',
            "sk_key": r'\bsk-[a-z0-9-_]{10,}\b',
            # Database
            "db_host": r'\b(db|database)\s*[:=]\s*[\w.-]+',
            # Generic secrets
            "secret": r'\b(secret|token)\s*[:=]\s*\S+',
        }

        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, payload_lower):
                return False

        # Check for known VinBank secrets
        VINBANK_SECRETS = [
            'admin123',
            'sk-vinbank-secret-2024',
            'db.vinbank.internal',
        ]
        for secret in VINBANK_SECRETS:
            if secret.lower() in payload_lower:
                return False

        # Check for PII in payload
        PII_PATTERNS = {
            "phone": r'\b0\d{9,10}\b',  # Vietnamese phone
            "email": r'[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}',
        }
        for pattern_name, pattern in PII_PATTERNS.items():
            if re.search(pattern, payload_lower):
                return False

    # Step 5: All checks passed - allow egress
    return True


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = True,
) -> list:
    """
    TODO 8: Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin / LlmJudge  (from guardrails.output_guardrails)
    4. (optional) NeMo wrapper

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    from guardrails.input_guardrails import InputGuardrailPlugin
    from guardrails.output_guardrails import OutputGuardrailPlugin, _init_judge

    plugins = []

    # 1. Rate Limiter - blocks flood attacks
    plugins.append(RateLimitPlugin(
        max_requests=max_requests,
        window_seconds=window_seconds
    ))

    # 2. Input Guardrail - blocks injection and off-topic
    plugins.append(InputGuardrailPlugin())

    # 3. Output Guardrail - blocks PII and secret leakage
    if use_llm_judge:
        _init_judge()  # Initialize LLM judge
    plugins.append(OutputGuardrailPlugin(use_llm_judge=use_llm_judge))

    return plugins


def build_observability():
    """Return AuditLogPlugin and MonitoringAlert instances."""
    return AuditLogPlugin(), MonitoringAlert()


async def run_assignment_suite(pipeline, student_id: str) -> dict:
    """
    TODO: Run Tests 1-4 from assignment11.md and
    return a dict matching schemas/results.schema.json.

    Write:
      outputs/results.json
      outputs/audit_log.json
      outputs/metrics.json
    """
    raise NotImplementedError("Implement run_assignment_suite")
