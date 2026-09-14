"""Exception hierarchy.

Everything the tool raises deliberately derives from :class:`S70Error` so the
CLI and the TUI can present a clean message instead of a traceback. Tracebacks
in this tool are a mild security problem in their own right: local variables
in a decryption frame hold key material, and some terminals log scrollback.
"""

from __future__ import annotations


class S70Error(Exception):
    """Base class for all expected failures."""


class BackupFormatError(S70Error):
    """The backup file is missing or malformed."""


class RecoveryKeyError(S70Error):
    """The recovery key could not be loaded or is the wrong kind of key."""


class DecryptionError(S70Error):
    """A share failed to decrypt."""


class KeyMaterialError(S70Error):
    """Decrypted plaintext was not in a recognised private-key format."""


class KmsParametersError(S70Error):
    """AWS KMS import parameters are missing, malformed, or ambiguous."""


class KmsKeySpecError(S70Error):
    """The requested KMS key spec contradicts the recovered key's curve."""


class KmsWrapError(S70Error):
    """The key material could not be wrapped for import into KMS."""
