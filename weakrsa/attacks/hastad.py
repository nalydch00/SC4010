"""Håstad's broadcast attack — recovers a message encrypted to many recipients
with a small public exponent and no padding.

Idea
----
Suppose the same plaintext m is sent to e recipients, each with exponent e and a
distinct modulus N_i (textbook RSA, no padding):
    c_i = m**e (mod N_i).
By CRT there is a unique C < N_1*...*N_e with C ≡ c_i (mod N_i). But C = m**e as
*integers* too, because m**e < N_1*...*N_e (each N_i > m). So an exact integer
e-th root of C recovers m directly — no factoring needed.

Needs at least e ciphertexts with pairwise-coprime moduli.
"""

from __future__ import annotations

from ..utils import crt, exact_iroot


def attack(ciphertexts: list[int], moduli: list[int], e: int) -> int | None:
    """Recover m from >= e broadcasts. Returns m, or None if not enough data."""
    if len(ciphertexts) < e or len(moduli) < e:
        return None
    # Use exactly e congruences (more is fine, but e suffices).
    c = ciphertexts[:e]
    mod = moduli[:e]
    combined, _ = crt(c, mod)
    m = exact_iroot(combined, e)
    return m
