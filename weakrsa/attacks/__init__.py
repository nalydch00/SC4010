"""The four attacks, plus a note on the lattice-based stretch goal.

Each module exposes one function that takes only *public* data and returns the
recovered secret (the factors, the private exponent, or the plaintext), or None
when the attack does not apply.

Stretch goal (A+): Coppersmith's method / Boneh--Durfee.
-------------------------------------------------------
When part of a factor leaks, or when d < N**0.292, these lattice attacks still
break real-size RSA. They rely on LLL lattice reduction, which is far cleaner in
SageMath than in pure Python, so they are intentionally *not* implemented here.
To add it:

  1. Install SageMath.
  2. Build the lattice of shifted polynomials for f(x) = (p_high + x) and reduce
     it with ``.LLL()``; the short vector gives the low bits of p.
  3. See Coppersmith (1996) and Boneh--Durfee (1999); Sage's
     ``small_roots`` recipe is a good starting point.

Mentioning the boundary (why d < N**0.25 for Wiener but < N**0.292 for
Boneh--Durfee) is strong Q&A material.
"""

from . import batch_gcd, fermat, hastad, wiener

__all__ = ["fermat", "wiener", "hastad", "batch_gcd"]
