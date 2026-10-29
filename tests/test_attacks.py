"""Correctness tests. Run with: python -m pytest

Uses smaller moduli (512-1024 bit) to keep the suite fast; the attacks are
size-independent, so passing here means they work at 2048 bit too (the demo
shows that).
"""

from __future__ import annotations

import pytest

from weakrsa import keygen
from weakrsa.attacks import batch_gcd, fermat, hastad, wiener
from weakrsa.utils import crt, exact_iroot, exact_sqrt, modinv


# --------------------------- utils ---------------------------------------- #
def test_exact_sqrt():
    assert exact_sqrt(144) == 12
    assert exact_sqrt(145) is None


def test_exact_iroot():
    assert exact_iroot(27, 3) == 3
    assert exact_iroot(28, 3) is None


def test_crt():
    x, M = crt([2, 3, 2], [3, 5, 7])
    assert M == 105 and x % 3 == 2 and x % 5 == 3 and x % 7 == 2


def test_modinv():
    assert (modinv(3, 11) * 3) % 11 == 1


# --------------------------- attacks -------------------------------------- #
def test_fermat_breaks_close_primes():
    key = keygen.close_primes_key(bits=512, gap_bits=40)
    res = fermat.attack(key.public())
    assert res is not None
    assert {res["p"], res["q"]} == {key.p, key.q}


def test_fermat_resists_safe_key():
    key = keygen.safe_key(bits=512)
    assert fermat.attack(key.public(), max_steps=5000) is None


def test_wiener_breaks_small_d():
    key = keygen.small_d_key(bits=1024)
    res = wiener.attack(key.public())
    assert res is not None
    assert res["d"] == key.d
    assert {res["p"], res["q"]} == {key.p, key.q}


def test_wiener_resists_safe_key():
    key = keygen.safe_key(bits=1024)
    assert wiener.attack(key.public()) is None


def test_hastad_recovers_message():
    e = 3
    message = 42424242424242
    keys = [keygen.small_e_key(bits=512, e=e) for _ in range(e)]
    cts = [k.encrypt(message) for k in keys]
    mods = [k.n for k in keys]
    assert hastad.attack(cts, mods, e) == message


def test_hastad_needs_enough_ciphertexts():
    e = 3
    keys = [keygen.small_e_key(bits=512, e=e) for _ in range(2)]
    cts = [k.encrypt(7) for k in keys]
    mods = [k.n for k in keys]
    assert hastad.attack(cts, mods, e) is None


def test_batch_gcd_matches_pairwise():
    farm = keygen.low_entropy_farm(count=80, bits=512, entropy_primes=12)
    tree = batch_gcd.batch_gcd(farm.moduli)
    pair = batch_gcd.pairwise(farm.moduli)
    # every key the pairwise method breaks, the tree also breaks
    assert set(pair) <= set(tree)
    # and recovered primes actually divide their modulus
    for idx, prime in tree.items():
        assert farm.moduli[idx] % prime == 0


def test_batch_gcd_recovers_full_key():
    farm = keygen.low_entropy_farm(count=80, bits=512, entropy_primes=12)
    found = batch_gcd.batch_gcd(farm.moduli)
    assert found, "expected at least one collision"
    idx, prime = next(iter(found.items()))
    key = farm.keys[idx]
    rec = batch_gcd.recover_key(key.n, prime, key.e)
    assert rec["d"] == key.d


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
