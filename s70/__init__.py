"""S70 Recovery -- offline recovery of CrypDefi wallet backup keys.

Two phases:

**Phase 1 -- recover and import.** Decrypt the RSA-OAEP-protected wallet
private keys from a backup file, verify each one two independent ways
(``original_sha256`` and re-deriving the recorded address), and render it in
the exact string form the target browser extension accepts.

**Phase 2 -- prepare a transfer.** Read chain state online with no keys
loaded, then sign a sweep transaction offline. This tool never submits a
transaction.

Start with :mod:`s70.cli`, or ``s70 tui <backup.json>``.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
