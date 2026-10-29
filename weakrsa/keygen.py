"""Deliberately weak RSA key generators — one per weakness we attack.

Each function returns a dataclass carrying exactly the public information an
attacker would have (N, e, and ciphertexts), plus the secret factors so the
demo can *verify* the attack recovered them. In a real system the secret part
would never leave the key owner; here it is the answer key.

There is also ``safe_key`` as a baseline: the same interface, but generated the
right way, so you can confirm every attack *fails* against it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import gmpy2
from gmpy2 import mpz
from sympy import nextprime, randprime

from .utils import modinv


@dataclass
class RSAKey:
    """A generated RSA key. Public: n, e. Secret: p, q, d (for verification)."""

    n: int
    e: int
    p: int
    q: int
    d: int
    bits: int
    weakness: str

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    def encrypt(self, m: int) -> int:
        return int(pow(mpz(m), self.e, self.n))

    def public(self) -> dict:
        """Only the data an attacker legitimately sees."""
        return {"n": self.n, "e": self.e, "bits": self.bits}


def _rand_prime(bits: int) -> int:
    lo = 1 << (bits - 1)
    hi = (1 << bits) - 1
    return int(randprime(lo, hi))


# --------------------------------------------------------------------------- #
# Weakness 1: close primes  ->  Fermat factorisation
# --------------------------------------------------------------------------- #
def close_primes_key(bits: int = 2048, gap_bits: int = 100, e: int = 65537) -> RSAKey:
    """p and q only ~2**gap_bits apart.

    FIX: draw p and q independently; |p - q| should be ~2**(bits/2), astronomically
    large. Here we force them close so Fermat's method converges in a few steps.
    """
    half = bits // 2
    p = _rand_prime(half)
    # q = next prime a little above p, with a small random offset.
    offset = int(gmpy2.mpz_random(gmpy2.random_state(), 1 << gap_bits)) | 1
    q = int(nextprime(p + offset))
    n = p * q
    d = modinv(e, (p - 1) * (q - 1))
    return RSAKey(n=n, e=e, p=p, q=q, d=d, bits=bits, weakness="close_primes")


# --------------------------------------------------------------------------- #
# Weakness 2: tiny private exponent  ->  Wiener's attack
# --------------------------------------------------------------------------- #
def small_d_key(bits: int = 2048, d_bits: int | None = None) -> RSAKey:
    """Private exponent d chosen small (for 'fast' decryption), then e = d**-1.

    Wiener breaks this whenever d < N**0.25 / 3. We default d_bits safely inside
    that bound.

    FIX: never pick d first; pick e (e.g. 65537) and derive d. A small d is fatal.
    """
    half = bits // 2
    if d_bits is None:
        # N**0.25 ~ 2**(bits/4). Stay comfortably below with a margin.
        d_bits = bits // 4 - 8
    while True:
        p = _rand_prime(half)
        q = _rand_prime(half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        # pick an odd d of the requested size, coprime to phi
        d = (_rand_prime(d_bits)) | 1
        if gmpy2.gcd(d, phi) != 1:
            continue
        e = modinv(d, phi)
        n = p * q
        return RSAKey(n=n, e=e, p=p, q=q, d=d, bits=bits, weakness="small_d")


# --------------------------------------------------------------------------- #
# Weakness 3: e = 3 with no padding  ->  Håstad broadcast
# --------------------------------------------------------------------------- #
def small_e_key(bits: int = 2048, e: int = 3) -> RSAKey:
    """A normal-looking key but with e = 3 and (implicitly) textbook RSA, no pad.

    Dangerous only when the *same* message is sent to >= e recipients. The demo
    builds several of these and broadcasts one plaintext.

    FIX: always use OAEP padding (and e = 65537). Textbook RSA of a small message
    is never safe.
    """
    half = bits // 2
    while True:
        p = _rand_prime(half)
        q = _rand_prime(half)
        phi = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) != 1:
            continue  # e must be coprime to phi
        n = p * q
        d = modinv(e, phi)
        return RSAKey(n=n, e=e, p=p, q=q, d=d, bits=bits, weakness="small_e")


# --------------------------------------------------------------------------- #
# Weakness 4: low-entropy RNG  ->  shared primes across a key set (Batch GCD)
# --------------------------------------------------------------------------- #
@dataclass
class KeyFarm:
    """A batch of public moduli, some of which secretly share a prime."""

    keys: list[RSAKey] = field(default_factory=list)
    colliding_pairs: list[tuple[int, int]] = field(default_factory=list)

    @property
    def moduli(self) -> list[int]:
        return [k.n for k in self.keys]


def low_entropy_farm(
    count: int = 200,
    bits: int = 2048,
    entropy_primes: int = 20,
    e: int = 65537,
    seed: int = 1234,
) -> KeyFarm:
    """Simulate a fleet of embedded devices with a bad boot-time RNG.

    This models the real *Mind your Ps and Qs* failure: the FIRST prime is drawn
    just after boot, when the entropy pool is nearly empty, so it comes from only
    ``entropy_primes`` possible values. The SECOND prime is generated a moment
    later with more entropy, so it is effectively unique per device.

    Consequence: two devices that happened to pick the same first prime p produce
    moduli p*q1 and p*q2 whose gcd is exactly p (q1 != q2) — batch GCD factors
    both. Because only one prime collides, the recovered gcd is a true prime, not
    the whole modulus.

    FIX: block until the CSPRNG is properly seeded before generating *any* prime.
    With both primes unique, gcd of any two moduli is 1 and the attack vanishes.
    """
    import random

    rng = random.Random(seed)
    half = bits // 2
    # Low-entropy pool for the first prime only.
    weak_pool = [_rand_prime(half) for _ in range(entropy_primes)]

    keys: list[RSAKey] = []
    first_prime_to_keys: dict[int, list[int]] = {}
    for _ in range(count):
        p = rng.choice(weak_pool)          # low-entropy first prime
        q = _rand_prime(half)              # high-entropy, effectively unique
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) != 1:
            continue
        d = modinv(e, phi)
        n = p * q
        keys.append(RSAKey(n=n, e=e, p=p, q=q, d=d, bits=bits, weakness="low_entropy"))
        first_prime_to_keys.setdefault(p, []).append(len(keys) - 1)

    colliding: list[tuple[int, int]] = []
    for sharers in first_prime_to_keys.values():
        for i in range(len(sharers)):
            for j in range(i + 1, len(sharers)):
                colliding.append((sharers[i], sharers[j]))

    return KeyFarm(keys=keys, colliding_pairs=sorted(set(colliding)))


# --------------------------------------------------------------------------- #
# Baseline: a correctly generated key (every attack should FAIL on this)
# --------------------------------------------------------------------------- #
def safe_key(bits: int = 2048, e: int = 65537) -> RSAKey:
    """A key generated the right way, for negative-control testing."""
    half = bits // 2
    while True:
        p = _rand_prime(half)
        q = _rand_prime(half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) != 1:
            continue
        n = p * q
        d = modinv(e, phi)
        return RSAKey(n=n, e=e, p=p, q=q, d=d, bits=bits, weakness="none")
