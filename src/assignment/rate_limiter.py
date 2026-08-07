"""
Assignment 11 — Rate Limiter

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds.

    Uses a sliding window algorithm:
    - Each user has a deque of timestamps
    - When a request comes in:
      1. Remove timestamps older than window_seconds
      2. If count >= max_requests: block
      3. Otherwise: allow and add timestamp
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # Step 1: Remove timestamps older than window_seconds
        while window and (now - window[0]) > self.window_seconds:
            window.popleft()

        # Step 2: Check if rate limit exceeded
        if len(window) >= self.max_requests:
            # Calculate wait time
            wait = self.window_seconds - (now - window[0])
            self.blocked_count += 1
            return self._block_response(
                f"Rate limit exceeded. Please wait {wait:.0f} seconds before trying again."
            )

        # Step 3: Allow request and add timestamp
        window.append(now)
        return None
