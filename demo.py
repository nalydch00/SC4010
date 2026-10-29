#!/usr/bin/env python3
"""End-to-end demo: generate a weak key, break it from public data, verify.

Run:  python demo.py            # all four attacks at 2048-bit
      python demo.py --bits 1024
      python demo.py --only wiener

This is the 8-minute presentation script. Each section prints:
  - the weakness,
  - what the attacker sees (public N, e only),
  - the recovered secret,
  - a PASS/FAIL check against the real key.
"""

from __future__ import annotations

import argparse
import time

from weakrsa import keygen
from weakrsa.attacks import batch_gcd, fermat, hastad, wiener


def banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def show_n(n: int) -> str:
    s = str(n)
    return f"{s[:24]}...{s[-12:]}  ({n.bit_length()} bits)"


def demo_fermat(bits: int) -> bool:
    banner("1. CLOSE PRIMES  ->  Fermat factorisation")
    key = keygen.close_primes_key(bits=bits, gap_bits=100)
    print(f"  weakness : p and q differ by only ~2^100")
    print(f"  attacker sees N = {show_n(key.n)}, e = {key.e}")
    t0 = time.perf_counter()
    res = fermat.attack(key.public(), max_steps=5_000_000)
    dt = time.perf_counter() - t0
    if res is None:
        print("  FAIL: attack did not converge")
        return False
    ok = {res["p"], res["q"]} == {key.p, key.q}
    print(f"  recovered p in {res['steps']} steps, {dt:.3f}s")
    print(f"  check    : {'PASS' if ok else 'FAIL'} (factors match real key)")
    return ok


def demo_wiener(bits: int) -> bool:
    banner("2. SMALL PRIVATE EXPONENT  ->  Wiener's attack")
    key = keygen.small_d_key(bits=bits)
    print(f"  weakness : d is only {key.d.bit_length()} bits (< N^0.25)")
    print(f"  attacker sees N = {show_n(key.n)}, e = {show_n(key.e)}")
    t0 = time.perf_counter()
    res = wiener.attack(key.public())
    dt = time.perf_counter() - t0
    if res is None:
        print("  FAIL: no small d found")
        return False
    ok = res["d"] == key.d and {res["p"], res["q"]} == {key.p, key.q}
    print(f"  recovered d = {res['d']}  ({dt:.3f}s)")
    print(f"  check    : {'PASS' if ok else 'FAIL'} (d and factors match)")
    return ok


def demo_hastad(bits: int) -> bool:
    banner("3. e = 3, NO PADDING, BROADCAST  ->  Hastad's attack")
    e = 3
    secret_message = 0xC0FFEE_DEADBEEF_1234567890
    recipients = [keygen.small_e_key(bits=bits, e=e) for _ in range(e)]
    cts = [k.encrypt(secret_message) for k in recipients]
    mods = [k.n for k in recipients]
    print(f"  weakness : same message sent to {e} people, e=3, textbook RSA")
    print(f"  attacker sees {e} ciphertexts + their public moduli")
    t0 = time.perf_counter()
    m = hastad.attack(cts, mods, e)
    dt = time.perf_counter() - t0
    ok = m == secret_message
    print(f"  recovered m = {hex(m) if m is not None else None}  ({dt:.3f}s)")
    print(f"  check    : {'PASS' if ok else 'FAIL'} (plaintext matches)")
    return ok


def demo_batch_gcd(bits: int) -> bool:
    banner("4. LOW-ENTROPY RNG  ->  Batch GCD across a key set")
    farm = keygen.low_entropy_farm(count=200, bits=bits, entropy_primes=25)
    print(f"  weakness : {len(farm.keys)} devices, RNG can only pick 25 primes")
    print(f"  attacker sees only the {len(farm.moduli)} public moduli")

    t0 = time.perf_counter()
    found = batch_gcd.batch_gcd(farm.moduli)
    dt_tree = time.perf_counter() - t0

    t0 = time.perf_counter()
    found_ref = batch_gcd.pairwise(farm.moduli)
    dt_pair = time.perf_counter() - t0

    print(f"  broken   : {len(found)} of {len(farm.keys)} keys")
    print(f"  batch-GCD tree : {dt_tree:.3f}s   vs   all-pairs : {dt_pair:.3f}s")

    # verify one recovered key fully
    ok = len(found) > 0
    if ok:
        idx, prime = next(iter(found.items()))
        key = farm.keys[idx]
        rec = batch_gcd.recover_key(key.n, prime, key.e)
        ok = rec["d"] == key.d
        print(f"  check    : {'PASS' if ok else 'FAIL'} (recovered d of key #{idx})")
    else:
        print("  check    : FAIL (no collisions found — raise count or lower entropy)")
    return ok


def demo_safe_negative_control(bits: int) -> bool:
    banner("NEGATIVE CONTROL: a correctly generated key resists everything")
    key = keygen.safe_key(bits=bits)
    f = fermat.attack(key.public(), max_steps=20_000)
    w = wiener.attack(key.public())
    ok = f is None and w is None
    print(f"  Fermat   : {'resisted' if f is None else 'BROKE (bug!)'}")
    print(f"  Wiener   : {'resisted' if w is None else 'BROKE (bug!)'}")
    print(f"  check    : {'PASS' if ok else 'FAIL'} (good key should resist)")
    return ok


ATTACKS = {
    "fermat": demo_fermat,
    "wiener": demo_wiener,
    "hastad": demo_hastad,
    "batch_gcd": demo_batch_gcd,
    "safe": demo_safe_negative_control,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bits", type=int, default=2048, help="RSA modulus size")
    ap.add_argument("--only", choices=sorted(ATTACKS), help="run a single attack")
    args = ap.parse_args()

    print(f"\nWeak-RSA attack demo  —  {args.bits}-bit moduli")
    to_run = [args.only] if args.only else list(ATTACKS)
    results = {name: ATTACKS[name](args.bits) for name in to_run}

    banner("SUMMARY")
    for name, ok in results.items():
        print(f"  {name:12s} : {'PASS' if ok else 'FAIL'}")
    if all(results.values()):
        print("\n  All checks passed.\n")


if __name__ == "__main__":
    main()
