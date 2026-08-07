"""
Assignment 11 — Audit Log

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline).

    Records:
    - Request ID (correlation ID for tracing)
    - User ID
    - Input text
    - Output text
    - Block decision and which layer blocked
    - Latency
    - Timestamps
    """

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}  # request_id -> start_time

    def _generate_request_id(self) -> str:
        """Generate a unique request ID for correlation."""
        return str(uuid.uuid4())[:16]

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id.

        Args:
            user_id: Identifier for the user
            text: The user's input message
            request_id: Optional request ID (auto-generated if not provided)
        """
        if request_id is None:
            request_id = self._generate_request_id()

        start_time = datetime.now(timezone.utc)
        self._open[request_id] = start_time.timestamp()

        log_entry = {
            "request_id": request_id,
            "user_id": user_id,
            "event": "input",
            "text": text[:1000] if text else "",  # Truncate long inputs
            "text_length": len(text) if text else 0,
            "timestamp": start_time.isoformat(),
        }
        self.logs.append(log_entry)

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs.

        Args:
            user_id: Identifier for the user
            text: The agent's output message
            blocked: Whether the output was blocked by a guardrail
            layer: Which layer blocked (if blocked)
            request_id: Request ID to correlate with input
        """
        if request_id is None:
            request_id = self._generate_request_id()

        end_time = datetime.now(timezone.utc)
        start_timestamp = self._open.get(request_id)

        # Calculate latency in milliseconds
        latency_ms = None
        if start_timestamp:
            latency_ms = (end_time.timestamp() - start_timestamp) * 1000

        log_entry = {
            "request_id": request_id,
            "user_id": user_id,
            "event": "output",
            "text": text[:1000] if text else "",  # Truncate long outputs
            "text_length": len(text) if text else 0,
            "blocked": blocked,
            "blocked_by_layer": layer,
            "timestamp": end_time.isoformat(),
            "latency_ms": round(latency_ms, 2) if latency_ms else None,
        }
        self.logs.append(log_entry)

        # Clean up open request
        if request_id in self._open:
            del self._open[request_id]

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array).

        Args:
            filepath: Path to write the JSON file
        """
        out_path = Path(filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, ensure_ascii=False, indent=2)


def utc_now_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()
