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


class IntegrityError(S70Error):
    """A share decrypted but failed its integrity check."""


class KeyMaterialError(S70Error):
    """Decrypted plaintext was not in a recognised private-key format."""


class ChainDetectionError(S70Error):
    """The chain behind an address could not be determined."""


class UnsupportedChainError(S70Error):
    """The chain was identified but this tool does not handle it."""


class MissingDependencyError(S70Error):
    """An optional phase-2 SDK is not installed."""

    def __init__(self, package: str, purpose: str) -> None:
        super().__init__(
            f"{purpose} needs the '{package}' package, which is not installed.\n"
            f"Install the transaction extras:  pip install -r requirements-tx.txt"
        )
        self.package = package


class JobFileError(S70Error):
    """A phase-2 job file is missing, malformed, or stale."""
