"""Bandwidth throttling and request rate limiting.

Both primitives are shared between WSGI worker threads and Qt worker threads,
so both are internally locked.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Deque, Optional


class TokenBucket:
    """Classic token bucket used to smooth transfer rates.

    A ``fill_rate`` of 0 disables throttling entirely.  :meth:`consume` blocks
    until enough tokens accumulate, but never for longer than ``max_wait`` in
    one call so a stopping worker stays responsive.
    """

    #: Smallest useful capacity: one 64 KiB transfer chunk.
    MIN_CAPACITY = 64 * 1024

    def __init__(self, capacity_bytes: float, fill_rate_bps: float):
        self.fill_rate = max(0.0, float(fill_rate_bps))
        self.capacity = max(1.0, float(capacity_bytes))
        self._tokens = self.capacity
        self._timestamp = time.monotonic()
        self._lock = threading.Lock()

    @classmethod
    def from_rate(cls, fill_rate_bps: float, burst_seconds: float = 2.0) -> "TokenBucket":
        """Build a bucket for ``fill_rate_bps`` allowing a short burst."""
        rate = max(0.0, float(fill_rate_bps))
        return cls(max(cls.MIN_CAPACITY, rate * burst_seconds), rate)

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = now - self._timestamp
        if elapsed <= 0:
            return
        self._tokens = min(self.capacity, self._tokens + elapsed * self.fill_rate)
        self._timestamp = now

    def consume(self, num_bytes: int, *, should_continue: Optional[Callable[[], bool]] = None) -> None:
        """Block until ``num_bytes`` tokens are available.

        ``should_continue`` is polled between waits; returning False aborts the
        wait so a cancelled transfer does not stall on a slow limit.
        """
        if self.fill_rate <= 0 or num_bytes <= 0:
            return

        # A request larger than the bucket could never be satisfied, since
        # tokens are capped at capacity — clamp it instead of spinning forever.
        needed = min(float(num_bytes), self.capacity)

        while True:
            if should_continue is not None and not should_continue():
                return

            with self._lock:
                self._refill_locked()
                if self._tokens >= needed:
                    self._tokens -= needed
                    return
                shortage = needed - self._tokens

            # Sleep outside the lock so other threads can make progress.
            wait = min(0.25, max(0.005, shortage / self.fill_rate))
            time.sleep(wait)


class SlidingWindowRateLimiter:
    """Global sliding-window request limiter.

    Every request through a Tor hidden service arrives from 127.0.0.1, so
    per-IP limiting is meaningless here; this caps total request volume.
    """

    def __init__(self, max_requests: int = 600, window_seconds: float = 60.0):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = float(window_seconds)
        self._events: Deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            if len(self._events) >= self.max_requests:
                return False
            self._events.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
