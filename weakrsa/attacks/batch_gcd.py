"""Batch GCD — factors every key in a set that shares a prime with another key.

Idea
----
If two RSA moduli share a prime, N_i = p*q_i and N_j = p*q_j, then
    gcd(N_i, N_j) = p,
and both keys fall at once. Low-entropy RNGs cause exactly this across a fleet of
devices (Heninger et al., "Mind your Ps and Qs", 2012).

Doing all O(n**2) pairwise GCDs is wasteful. The product/remainder tree computes,
for every modulus N_i, gcd(N_i, (product of all other N) ) in near-linear time:

  1. Build a product tree whose root is P = prod(N_i).
  2. Walk back down computing P mod N_i**2 at each leaf.
  3. gcd(N_i, (P mod N_i**2) / N_i) is the product of primes N_i shares with the
     rest of the set; for RSA that is a single prime p.

This module ships both: a clear O(n**2) reference (``pairwise``) and the fast
tree (``batch_gcd``), so you can show the speedup in the demo.
"""

from __future__ import annotations

from math import gcd


def pairwise(moduli: list[int]) -> dict[int, int]:
    """Reference implementation: for each index, the recovered shared prime.

    Returns {index: prime}. O(n**2) GCDs — fine for a few hundred keys, and the
    baseline the tree is compared against.
    """
    found: dict[int, int] = {}
    n = len(moduli)
    for i in range(n):
        for j in range(i + 1, n):
            g = gcd(moduli[i], moduli[j])
            if g != 1:
                found[i] = g
                found[j] = g
    return found


def _product_tree(leaves: list[int]) -> list[list[int]]:
    """Bottom-up product tree over a power-of-two number of leaves.

    Level 0 is the (padded) leaves; the last level is a single element, the
    product of everything. Leaves are padded with 1 so the tree is a perfect
    binary tree and parent/child indexing (child i -> parent i//2) is exact.
    """
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [cur[i] * cur[i + 1] for i in range(0, len(cur), 2)]
        levels.append(nxt)
    return levels


def _remainder_tree(levels: list[list[int]]) -> list[int]:
    """Walk the product tree down, giving (product of all) mod leaf**2 per leaf."""
    remainders = [levels[-1][0]]  # root holds the full product P
    for depth in range(len(levels) - 1, 0, -1):
        child_level = levels[depth - 1]
        nxt = []
        for i, node in enumerate(child_level):
            parent = remainders[i // 2]
            nxt.append(parent % (node * node))
        remainders = nxt
    return remainders


def _pad_pow2(moduli: list[int]) -> list[int]:
    size = 1
    while size < len(moduli):
        size <<= 1
    return list(moduli) + [1] * (size - len(moduli))


def batch_gcd(moduli: list[int]) -> dict[int, int]:
    """Fast batch GCD via product/remainder trees.

    Returns {index: shared_prime} for every modulus that shares a factor with at
    least one other modulus in the list.
    """
    if len(moduli) < 2:
        return {}
    leaves = _pad_pow2(moduli)
    levels = _product_tree(leaves)
    rem = _remainder_tree(levels)
    found: dict[int, int] = {}
    for i, n_i in enumerate(moduli):  # real moduli only; padding (value 1) ignored
        # rem[i] == P mod n_i**2 ; (rem[i] // n_i) mod n_i == (P / n_i) mod n_i,
        # whose gcd with n_i is the product of primes n_i shares with other keys.
        z = (rem[i] // n_i) % n_i
        g = gcd(z, n_i)
        if g != 1 and g != n_i:
            found[i] = g
    return found


def recover_key(n: int, shared_prime: int, e: int) -> dict:
    """Given one modulus and a recovered prime, return the full private data."""
    from ..utils import modinv

    p = shared_prime
    q = n // p
    assert p * q == n, "shared_prime does not divide n"
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return {"p": max(p, q), "q": min(p, q), "d": d}
