"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router ✓
  TODO 12: Design 3 HITL decision points ✓
"""
from dataclasses import dataclass


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto_send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue_review
        LOW:    confidence < 0.7 -> escalate

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # Step 1: Check if action_type is HIGH_RISK
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # Step 2: Check confidence thresholds
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large Money Transfer",
        "trigger": "Customer requests transfer > 50,000,000 VND (~$2,000 USD)",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Customer ID, account balance, transfer destination, recent transaction history, fraud score",
        "example": "Customer wants to transfer 100,000,000 VND to a new account they've never sent to before",
        "approval_path": """
Approve: Human clicks 'Approve' — transfer proceeds, logged in audit trail
Reject: Human clicks 'Reject' — transfer blocked, customer notified via SMS/email
Timeout (24h): Auto-escalate to manager, send notification to customer
""",
        "audit_fields": "correlation_id, customer_id, intent=large_transfer, amount=100000000, destination_account, fraud_score, reviewer_id, decision=approve/reject/timeout, timestamp",
    },
    {
        "id": 2,
        "name": "Account Closure Request",
        "trigger": "Customer requests to close account or delete banking relationship",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Customer ID, account type, current balance, pending transactions, reason for closure, tenure with bank",
        "example": "Customer who has been with VinBank for 3 years with 50,000,000 VND balance requests immediate account closure",
        "approval_path": """
Approve: Human reviews reason — if legitimate, initiate closure with balance transfer
Reject: Human calls customer to understand situation, offer alternatives
Timeout (48h): Follow up with customer, escalate to relationship manager
""",
        "audit_fields": "correlation_id, customer_id, intent=account_closure, account_type, balance, closure_reason, reviewer_id, decision, timestamp",
    },
    {
        "id": 3,
        "name": "Suspicious Activity Flagged",
        "trigger": "System or confidence router flags potential fraud (confidence < 0.7 or fraud_score > 0.8)",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Customer profile, recent transactions (last 30 days), device/location data, fraud score breakdown, customer contact history",
        "example": "Customer typically transfers 5,000,000 VND/month suddenly requests 100,000,000 VND to overseas account at 2 AM from new device",
        "approval_path": """
Approve: Human confirms legitimate — unblock transaction, update customer profile
Reject: Human blocks transaction — initiate fraud investigation, contact customer
Escalate: If confirmed fraud, freeze account, notify security team
Timeout (1h for urgent): Auto-freeze account pending review
""",
        "audit_fields": "correlation_id, customer_id, intent=suspicious_activity, fraud_score, transaction_amount, destination_country, device_fingerprint, reviewer_id, decision, timestamp",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
