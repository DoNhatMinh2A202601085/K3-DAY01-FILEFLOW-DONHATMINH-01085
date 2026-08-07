"""
Assignment 11 — Monitoring & Alerts

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class Alert:
    """Represents a monitoring alert."""
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts.

    Tracks:
    - Total requests
    - Blocked requests
    - Block rate
    - Rate limit hits
    - Judge checks and failures
    - Judge fail rate
    """

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        """Compute rates and append Alert objects when thresholds exceeded.

        Checks:
        1. Block rate > block_rate_threshold (50% by default)
        2. Rate limit hits > rate_limit_hit_threshold (5 by default)
        3. Judge fail rate > judge_fail_rate_threshold (30% by default)
        """
        new_alerts = []

        # Calculate rates
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests > 0
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks
            if self.judge_checks > 0
            else 0.0
        )

        # Check block rate
        if block_rate > self.block_rate_threshold:
            alert = Alert(
                metric="block_rate",
                value=block_rate,
                threshold=self.block_rate_threshold,
                message=f"Block rate {block_rate:.1%} exceeds threshold {self.block_rate_threshold:.1%}"
            )
            new_alerts.append(alert)

        # Check rate limit hits
        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            alert = Alert(
                metric="rate_limit_hits",
                value=float(self.rate_limit_hits),
                threshold=float(self.rate_limit_hit_threshold),
                message=f"Rate limit hits {self.rate_limit_hits} exceeds threshold {self.rate_limit_hit_threshold}"
            )
            new_alerts.append(alert)

        # Check judge fail rate
        if judge_fail_rate > self.judge_fail_rate_threshold:
            alert = Alert(
                metric="judge_fail_rate",
                value=judge_fail_rate,
                threshold=self.judge_fail_rate_threshold,
                message=f"Judge fail rate {judge_fail_rate:.1%} exceeds threshold {self.judge_fail_rate_threshold:.1%}"
            )
            new_alerts.append(alert)

        # Update stored alerts
        self.alerts.extend(new_alerts)

        return new_alerts

    def export_json(self, filepath: str = "outputs/metrics.json"):
        """Write metrics + alerts to JSON.

        Args:
            filepath: Path to write the JSON file
        """
        snapshot = self.snapshot()
        out_path = Path(filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)

    def snapshot(self) -> dict:
        """Get current metrics snapshot as a dictionary."""
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )

        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": round(block_rate, 4),
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": round(judge_fail_rate, 4),
            "alerts": [asdict(a) for a in self.alerts],
        }
