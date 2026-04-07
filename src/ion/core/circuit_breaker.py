"""Circuit breaker pattern for external service calls.

Prevents cascading failures when external services (ES, OpenCTI, TIDE) are down.
After a threshold of failures, the circuit "opens" and immediately returns errors
for a cooldown period instead of waiting for timeouts.

Usage:
    breaker = CircuitBreaker("elasticsearch", failure_threshold=5, reset_timeout=60)

    if not breaker.can_execute():
        return {"error": "Service temporarily unavailable (circuit open)"}

    try:
        result = call_external_service()
        breaker.record_success()
        return result
    except Exception as e:
        breaker.record_failure()
        raise
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation — requests pass through
    OPEN = "open"          # Failures exceeded threshold — reject immediately
    HALF_OPEN = "half_open"  # Cooldown expired — allow one test request


@dataclass
class CircuitBreaker:
    """Circuit breaker for an external service."""

    name: str
    failure_threshold: int = 5       # failures before opening circuit
    reset_timeout: int = 60          # seconds before trying again (half-open)
    success_threshold: int = 2       # successes in half-open before closing

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _last_state_change: float = field(default=0.0, init=False)

    def can_execute(self) -> bool:
        """Check if a request should be allowed through."""
        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.reset_timeout:
                self._transition(CircuitState.HALF_OPEN)
                return True
            return False

        # HALF_OPEN: allow through (testing)
        return True

    def record_success(self):
        """Record a successful external call."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._transition(CircuitState.CLOSED)
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self):
        """Record a failed external call."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        self._success_count = 0

        if self._state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.failure_threshold:
                self._transition(CircuitState.OPEN)

    def _transition(self, new_state: CircuitState):
        old = self._state
        self._state = new_state
        self._last_state_change = time.time()
        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._success_count = 0
        logger.warning(
            "Circuit breaker [%s]: %s -> %s (failures: %d)",
            self.name, old.value, new_state.value, self._failure_count,
        )

    @property
    def state(self) -> str:
        # Auto-transition from OPEN to HALF_OPEN if cooldown elapsed
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.reset_timeout:
                self._transition(CircuitState.HALF_OPEN)
        return self._state.value

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def get_status(self) -> dict:
        return {
            "name": self.name,
            "state": self.state,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "reset_timeout": self.reset_timeout,
            "seconds_since_last_failure": round(time.time() - self._last_failure_time, 1) if self._last_failure_time else None,
        }


# Global circuit breakers for each external service
_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a circuit breaker for a named service."""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name=name, **kwargs)
    return _breakers[name]


def get_all_breaker_status() -> list[dict]:
    """Get status of all circuit breakers."""
    return [b.get_status() for b in _breakers.values()]


# Pre-configured breakers for ION's external services
es_breaker = get_breaker("elasticsearch", failure_threshold=5, reset_timeout=60)
opencti_breaker = get_breaker("opencti", failure_threshold=3, reset_timeout=90)
tide_breaker = get_breaker("tide", failure_threshold=3, reset_timeout=60)
ollama_breaker = get_breaker("ollama", failure_threshold=3, reset_timeout=120)
kibana_breaker = get_breaker("kibana", failure_threshold=5, reset_timeout=60)
