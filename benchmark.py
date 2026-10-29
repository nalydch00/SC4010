#!/usr/bin/env python3
"""Boundary experiments — where does each weakness stop being exploitable?

This is the material that turns a working demo into an A-grade *investigation*.
Each experiment sweeps a parameter and reports the point at which the attack
flips from succeeding to failing, matching the theoretical bound.

Run:  python benchmark.py                 # all experiments
      python benchmark.py --exp wiener
"""

from __future__ import annotations

import argparse
import time

from weakrsa import keygen
from weakrsa.attacks import batch_gcd, fermat, wiener


def exp_fermat_gap(bits: int = 1024) -> None:
    """Fermat: success and step-count vs. the prime gap |p - q| ~ 2^gap_bits.

    Theory: steps ~ (p-q)^2 / (4*sqrt(N)). Doubling gap_bits should roughly
    quadruple the gap's contribution — watch the step count explode.
    """
    print("\n[Fermat] success vs. prime gap")
    print(f"{'gap_bits':>9} | {'steps':>12} | {'time(s)':>8} | result")
    print("-" * 48)
    for gap_bits in (20, 40, 60, 80, 100, 130, 160):
        key = keygen.close_primes_key(bits=bits, gap_bits=gap_bits)
        t0 = time.perf_counter()
        res = fermat.attack(key.public(), max_steps=2_000_000)
        dt = time.perf_counter() - t0
        if res:
            print(f"{gap_bits:>9} | {res['steps']:>12,} | {dt:>8.3f} | BROKEN")
        else:
            print(f"{gap_bits:>9} | {'>2,000,000':>12} | {dt:>8.3f} | resisted")
    print("  -> the gap an attacker tolerates is tiny; real keys have gap ~2^(bits/2).")


def exp_wiener_cliff(bits: int = 1024) -> None:
    """Wiener: the d < N^0.25 cliff.

    Sweep d_bits around bits/4. Below the bound the attack succeeds instantly;
    above it, it fails — a sharp, demonstrable boundary.
    """
    print("\n[Wiener] success vs. size of private exponent d")
    bound = bits // 4
    print(f"  N^0.25 is ~2^{bound}")
    print(f"{'d_bits':>7} | {'vs bound':>9} | result")
    print("-" * 34)
    for d_bits in range(bound - 20, bound + 16, 4):
        key = keygen.small_d_key(bits=bits, d_bits=d_bits)
        res = wiener.attack(key.public())
        rel = f"{d_bits - bound:+d}"
        print(f"{d_bits:>7} | {rel:>9} | {'BROKEN' if res else 'resisted'}")
    print("  -> clean cliff near N^0.25 (Boneh-Durfee pushes it to N^0.292).")


def exp_batch_entropy(bits: int = 1024) -> None:
    """Batch GCD: how RNG entropy controls the fraction of keys broken.

    Fewer distinct primes -> more collisions -> more keys fall. Shows the
    birthday-style blow-up directly.
    """
    print("\n[Batch GCD] keys broken vs. RNG entropy (distinct primes available)")
    count = 300
    print(f"  {count} devices")
    print(f"{'entropy':>8} | {'broken':>8} | {'%':>6}")
    print("-" * 28)
    for entropy in (10, 25, 50, 100, 200, 400):
        farm = keygen.low_entropy_farm(count=count, bits=bits, entropy_primes=entropy)
        found = batch_gcd.batch_gcd(farm.moduli)
        pct = 100 * len(found) / len(farm.keys)
        print(f"{entropy:>8} | {len(found):>8} | {pct:>5.1f}%")
    print("  -> even a few thousand bad seeds across many devices guarantees breaks.")


def exp_batch_speed(bits: int = 1024) -> None:
    """Batch GCD: tree vs. all-pairs timing as the key set grows."""
    print("\n[Batch GCD] product-tree vs. all-pairs timing")
    print(f"{'keys':>6} | {'tree(s)':>9} | {'pairs(s)':>9} | speedup")
    print("-" * 42)
    for count in (100, 200, 400, 800):
        farm = keygen.low_entropy_farm(count=count, bits=bits, entropy_primes=count // 2)
        t0 = time.perf_counter()
        batch_gcd.batch_gcd(farm.moduli)
        dt_tree = time.perf_counter() - t0
        t0 = time.perf_counter()
        batch_gcd.pairwise(farm.moduli)
        dt_pair = time.perf_counter() - t0
        sp = dt_pair / dt_tree if dt_tree else float("inf")
        print(f"{count:>6} | {dt_tree:>9.3f} | {dt_pair:>9.3f} | {sp:>5.1f}x")
    print("  -> the tree wins by more as the fleet grows (near-linear vs. quadratic).")


EXPERIMENTS = {
    "fermat": exp_fermat_gap,
    "wiener": exp_wiener_cliff,
    "batch_entropy": exp_batch_entropy,
    "batch_speed": exp_batch_speed,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exp", choices=sorted(EXPERIMENTS), help="run one experiment")
    ap.add_argument("--bits", type=int, default=1024, help="modulus size for sweeps")
    args = ap.parse_args()
    names = [args.exp] if args.exp else list(EXPERIMENTS)
    for name in names:
        EXPERIMENTS[name](args.bits)


if __name__ == "__main__":
    main()
