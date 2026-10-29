"""Small integer-maths helpers shared by the attacks.

Nothing here is RSA-specific; it is the number theory the attacks lean on:
exact integer roots, the Chinese Remainder Theorem, and continued fractions.
gmpy2 provides fast, *exact* big-integer roots, which matters because the
attacks test "is this a perfect square / cube?" on real-size numbers.
"""

from __future__ import annotations

import gmpy2
from gmpy2 import mpz


def isqrt(n: int) -> int:
    """Floor of the integer square root."""
    return int(gmpy2.isqrt(mpz(n)))


def is_perfect_square(n: int) -> bool:
    return n >= 0 and gmpy2.is_square(mpz(n))


def exact_sqrt(n: int) -> int | None:
    """Return r with r*r == n, or None if n is not a perfect square."""
    if n < 0:
        return None
    r = isqrt(n)
    return r if r * r == n else None


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root. Returns (root, is_exact) where root == floor(n ** (1/k))."""
    r, exact = gmpy2.iroot(mpz(n), k)
    return int(r), bool(exact)


def exact_iroot(n: int, k: int) -> int | None:
    """Return r with r**k == n, or None if n has no exact integer k-th root."""
    r, exact = iroot(n, k)
    return r if exact else None


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m (m need not be prime)."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (gcd = {g})")
    return x % m


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """Chinese Remainder Theorem for pairwise-coprime moduli.

    Returns (x, M) with x ≡ residues[i] (mod moduli[i]) for all i, 0 <= x < M,
    and M the product of the moduli.
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have equal length")
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r_i, m_i in zip(residues, moduli):
        M_i = M // m_i
        x += r_i * M_i * modinv(M_i, m_i)
    return x % M, M


def continued_fraction(num: int, den: int) -> list[int]:
    """Continued-fraction expansion [a0; a1, a2, ...] of num/den."""
    terms: list[int] = []
    while den:
        q = num // den
        terms.append(q)
        num, den = den, num - q * den
    return terms


def convergents(cf: list[int]):
    """Yield the convergents (h/k) of a continued fraction, in order."""
    h_prev, h = 1, cf[0] if cf else 0
    k_prev, k = 0, 1
    yield h, k
    for a in cf[1:]:
        h_prev, h = h, a * h + h_prev
        k_prev, k = k, a * k + k_prev
        yield h, k
