"""S70 Recovery -- offline recovery of wallet keys from a Station70 backup.

The keys in the backup belong to wallets held at Fortkey (formerly CrypDefi).
This tool does four things:

1. **Decrypt.** Recover the RSA-OAEP-protected wallet private keys using the
   recovery key the backup itself carries.
2. **Verify.** Check each key two independent ways -- the ``original_sha256``
   recorded in the backup, and re-deriving the recorded address from the key --
   and state which of them actually passed.
3. **Display.** Render each key in the exact string form the target browser
   extension accepts, with the steps to import it.
4. **Export to AWS KMS.** Optionally wrap one key as KMS importable key
   material, so signing happens in KMS rather than here.

It opens no sockets. Getting funds out is done with a wallet extension or with
the KMS key; this tool's job ends at handing you one or the other.

Start with :mod:`s70.cli`, or ``s70 tui <backup.json>``.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
