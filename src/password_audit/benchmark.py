"""Per-algorithm throughput benchmark.

Measures CPU-bound hashing throughput on the local machine for one algorithm
at a time, in-process (no IPC), over a fixed wall-clock slice. Results are
informational — they help pick realistic brute-force budgets — and are never
written to history.
"""

from __future__ import annotations

import time

from .hashing import hash_candidate


def measure_algorithm(
    algorithm: str,
    seconds: float = 2.0,
    salt: str | None = None,
    sample: str = "benchmark-sample-candidate-0001",
) -> dict:
    """Hash a synthetic candidate repeatedly for ``seconds``; return throughput.

    Returns ``{"algorithm": name, "hashes_per_second": float, "elapsed_ms": int,
    "hashed": int}``. Each iteration hashes the sample with a growing suffix so
    the digest input varies (avoids trivial cache effects dominating).
    """
    hashed = 0
    started = time.monotonic()
    deadline = started + seconds
    while True:
        hash_candidate(f"{sample}-{hashed}", algorithm, salt)
        hashed += 1
        now = time.monotonic()
        if now >= deadline:
            break
    elapsed_ms = int((now - started) * 1000)
    rate = hashed / max((now - started), 1e-6)
    return {
        "algorithm": algorithm,
        "hashes_per_second": rate,
        "elapsed_ms": elapsed_ms,
        "hashed": hashed,
    }


def measure_all(algorithms: list[str], seconds: float = 2.0) -> list[dict]:
    """Measure each algorithm in turn, fastest first in the result order given."""
    return [measure_algorithm(algorithm, seconds=seconds) for algorithm in algorithms]
