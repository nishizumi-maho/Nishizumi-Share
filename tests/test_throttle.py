"""Token bucket and rate limiter."""

from __future__ import annotations

import threading
import time

from nishizumi_share.throttle import SlidingWindowRateLimiter, TokenBucket


class TestTokenBucket:
    def test_zero_rate_means_unlimited(self):
        bucket = TokenBucket.from_rate(0)
        start = time.monotonic()
        for _ in range(100):
            bucket.consume(10**6)
        assert time.monotonic() - start < 0.5

    def test_burst_is_served_immediately(self):
        bucket = TokenBucket(capacity_bytes=1000, fill_rate_bps=1000)
        start = time.monotonic()
        bucket.consume(1000)
        assert time.monotonic() - start < 0.2

    def test_throttles_once_the_burst_is_spent(self):
        bucket = TokenBucket(capacity_bytes=1000, fill_rate_bps=1000)
        bucket.consume(1000)  # drain the burst
        start = time.monotonic()
        bucket.consume(200)  # needs ~0.2 s to refill
        assert time.monotonic() - start >= 0.15

    def test_request_larger_than_capacity_does_not_deadlock(self):
        # Tokens are capped at capacity, so an unclamped request could never
        # be satisfied and consume() would spin forever.
        bucket = TokenBucket(capacity_bytes=100, fill_rate_bps=10_000)
        start = time.monotonic()
        bucket.consume(5000)
        assert time.monotonic() - start < 2.0

    def test_capacity_never_below_one(self):
        assert TokenBucket(capacity_bytes=0, fill_rate_bps=10).capacity >= 1

    def test_from_rate_capacity_covers_a_transfer_chunk(self):
        # A slow limit must still admit a whole 64 KiB chunk.
        assert TokenBucket.from_rate(1024).capacity >= 64 * 1024

    def test_should_continue_aborts_wait(self):
        bucket = TokenBucket(capacity_bytes=10, fill_rate_bps=1)
        bucket.consume(10)
        start = time.monotonic()
        bucket.consume(10_000, should_continue=lambda: False)
        assert time.monotonic() - start < 0.5

    def test_thread_safe(self):
        bucket = TokenBucket.from_rate(10**7)
        errors = []

        def worker():
            try:
                for _ in range(200):
                    bucket.consume(1024)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors

    def test_negative_consume_is_ignored(self):
        bucket = TokenBucket.from_rate(100)
        bucket.consume(-5)  # must not block or raise


class TestRateLimiter:
    def test_allows_up_to_the_limit(self):
        limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        assert [limiter.allow() for _ in range(4)] == [True, True, True, False]

    def test_window_expiry_restores_capacity(self):
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=0.2)
        assert limiter.allow() and limiter.allow()
        assert not limiter.allow()
        time.sleep(0.3)
        assert limiter.allow()

    def test_reset(self):
        limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60)
        assert limiter.allow()
        assert not limiter.allow()
        limiter.reset()
        assert limiter.allow()
