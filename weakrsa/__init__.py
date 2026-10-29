"""weakrsa — deliberately weak RSA key generation and the attacks that break it.

Educational cryptography coursework. Every attack operates only on keys produced
by this package's own ``keygen`` module.
"""

__all__ = ["keygen", "utils", "attacks"]
