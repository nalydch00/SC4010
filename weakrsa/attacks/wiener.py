"""Wiener's attack — recovers a small private exponent d from the public (e, N).

Idea
----
From e*d = 1 (mod phi(N)) we have e*d - k*phi(N) = 1 for some integer k, so
    e/N  ≈  k/d.
Because phi(N) = N - (p + q) + 1 is very close to N, the fraction k/d is an
excellent rational approximation to e/N — good enough that k/d appears among the
*convergents* of the continued fraction of e/N, provided d < N**0.25 / 3.

For each convergent k/d we test the guess:
  phi = (e*d - 1) / k   (must be a positive integer)
  then solve x**2 - (N - phi + 1)*x + N = 0; integer roots are p and q.
The first convergent that yields integer roots factoring N wins.
"""

from __future__ import annotations

from ..utils import continued_fraction, convergents, exact_sqrt


def attack(public: dict) -> dict | None:
    """Attack from {'n', 'e'}. Returns {'d','p','q'} or None if d is not small."""
    n, e = public["n"], public["e"]
    cf = continued_fraction(e, n)

    for k, d in convergents(cf):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - s*x + n = 0 where s = p + q = n - phi + 1.
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root = exact_sqrt(disc)
        if root is None:
            continue
        if (s + root) % 2 != 0:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == n:
            return {"d": d, "p": max(p, q), "q": min(p, q)}
    return None


# --------------------------------------------------------------------------- #
# Step-by-step variant, for the interactive visualizer.
# --------------------------------------------------------------------------- #
def iter_steps(public: dict):
    """Yield one frame per convergent k/d of e/N tested.

    Each frame: {'idx', 'k', 'd', 'phi_integer', 'found', 'p', 'q'}.
    Stops after the convergent that factors N (found=True), if any.
    """
    n, e = public["n"], public["e"]
    cf = continued_fraction(e, n)
    for idx, (k, d) in enumerate(convergents(cf)):
        if k == 0 or d == 0:
            yield {"idx": idx, "k": k, "d": d, "phi_integer": False,
                   "found": False, "p": None, "q": None}
            continue
        phi_integer = (e * d - 1) % k == 0
        found = False
        p = q = None
        if phi_integer:
            phi = (e * d - 1) // k
            s = n - phi + 1
            disc = s * s - 4 * n
            if disc >= 0:
                root = exact_sqrt(disc)
                if root is not None and (s + root) % 2 == 0:
                    pp = (s + root) // 2
                    qq = (s - root) // 2
                    if pp * qq == n:
                        found, p, q = True, max(pp, qq), min(pp, qq)
        yield {"idx": idx, "k": k, "d": d, "phi_integer": phi_integer,
               "found": found, "p": p, "q": q}
        if found:
            return
