"""Fermat factorisation — breaks RSA keys whose primes are too close together.

Idea
----
Write N = p*q with p > q. Let a = (p+q)/2 and b = (p-q)/2, so
    N = a**2 - b**2.
If p and q are close then b is small and a is only just above sqrt(N). Scan a
upward from ceil(sqrt(N)); for each a check whether a**2 - N is a perfect square
b**2. The first hit gives p = a + b, q = a - b.

Steps needed grow with the prime gap: roughly (p - q)**2 / (4*sqrt(N)). For a
well-generated key the gap is ~sqrt(N), so this never terminates — which is
exactly why it is only a weakness for *close* primes.
"""

from __future__ import annotations

from ..utils import exact_sqrt, isqrt


def factor(n: int, max_steps: int = 10_000_000) -> tuple[int, int] | None:
    """Return (p, q) with p*q == n and p >= q, or None within max_steps."""
    a = isqrt(n)
    if a * a < n:
        a += 1  # ceil(sqrt(n))
    for _ in range(max_steps):
        b2 = a * a - n
        b = exact_sqrt(b2)
        if b is not None:
            p, q = a + b, a - b
            if p * q == n and p != 1 and q != 1:
                return (p, q) if p >= q else (q, p)
        a += 1
    return None


def attack(public: dict, max_steps: int = 10_000_000) -> dict | None:
    """Attack from public data {'n': ...}. Returns {'p','q','steps'} or None."""
    n = public["n"]
    a = isqrt(n)
    if a * a < n:
        a += 1
    steps = 0
    while steps < max_steps:
        b = exact_sqrt(a * a - n)
        steps += 1
        if b is not None:
            p, q = a + b, a - b
            if p >= q:
                return {"p": p, "q": q, "steps": steps}
            return {"p": q, "q": p, "steps": steps}
        a += 1
    return None
