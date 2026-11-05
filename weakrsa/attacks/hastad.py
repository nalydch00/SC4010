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


# --------------------------------------------------------------------------- #
# Step-by-step variant, for the interactive visualizer.
# --------------------------------------------------------------------------- #
def iter_steps(ciphertexts: list[int], moduli: list[int], e: int):
    """Yield frames as the e ciphertexts are combined by CRT, then cube-rooted.

    One 'combine' frame per ciphertext folded in, then a final 'root' frame:
      combine: {'stage','added','count','combined','product','enough','message'}
      root:    {'stage':'root','combined','product','message'}
    'message' is the recovered integer once enough (>= e) congruences are in and
    the e-th root is exact; otherwise None.
    """
    for idx in range(len(moduli)):
        c = ciphertexts[: idx + 1]
        mod = moduli[: idx + 1]
        combined, product = crt(c, mod)
        enough = (idx + 1) >= e
        m = exact_iroot(combined, e) if enough else None
        yield {"stage": "combine", "added": idx, "count": idx + 1,
               "combined": combined, "product": product, "enough": enough, "message": m}
    combined, product = crt(ciphertexts[:e], moduli[:e])
    yield {"stage": "root", "combined": combined, "product": product,
           "message": exact_iroot(combined, e)}
