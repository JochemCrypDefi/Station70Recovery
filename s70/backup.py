"""Backup file parsing.

Schema, as emitted by CrypDefi (``version`` ``"1.0"``)::

    {
      "version": "1.0",
      "wallet_provider": "CrypDefi",
      "recovery_key": "<base64 DER RSA-4096 private key>",
      "keys": [
        {
          "key_id": "...",
          "key_type": "EDDSA_ED25519" | "ECDSA_SECP256k1",
          "key_name": "Treasury EVM",
          "share_algorithm": "single",
          "shares": [
            {
              "metadata": { "address": "0x...", "chain_id": "ch-60" },
              "encryption": {
                "ciphersuite": "RSA-4096-OAEP-SHA256",
                "ciphertext": "<base64>",
                "original_sha256": "<base64 sha256 of plaintext>"
              }
            }
          ]
        }
      ]
    }

Two fields carry information the tool would otherwise have to guess, and both
are treated as authoritative:

* ``key_type`` gives the curve. A raw 32-byte scalar is a valid key on both
  Ed25519 and secp256k1, so without it the tool must derive both and see which
  reproduces the address.
* ``metadata.chain_id`` is ``ch-<SLIP-44 coin type>``. It is the only thing
  that separates Aptos (``ch-637``) from Sui (``ch-784``), which have
  identically shaped addresses.

The address is still re-derived and compared in every case -- the declared
fields choose *what* to derive, they never stand in for the check.

Everything else is read defensively. A backup missing ``key_name``,
``metadata.address`` or ``metadata.chain_id`` is still usable; you lose the
corresponding cross-check, which the UI reports rather than hides.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from s70.errors import BackupFormatError
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1

EXPECTED_CIPHERSUITE = "RSA-4096-OAEP-SHA256"


@dataclass(frozen=True)
class Share:
    """One encrypted share of one wallet key."""

    index: int
    encryption: dict[str, Any]
    metadata: dict[str, Any]

    @property
    def ciphersuite(self) -> str:
        return str(self.encryption.get("ciphersuite") or "unspecified")

    @property
    def ciphertext_b64(self) -> str | None:
        value = self.encryption.get("ciphertext")
        return str(value) if value else None

    @property
    def original_sha256(self) -> str | None:
        value = self.encryption.get("original_sha256")
        return str(value) if value else None

    @property
    def address(self) -> str | None:
        value = self.metadata.get("address")
        return str(value).strip() if value else None

    @property
    def declared_chain_id(self) -> str | None:
        """The backup's own ``ch-<SLIP-44>`` chain identifier, e.g. ``ch-60``.

        Authoritative when present. It is the only thing that separates Aptos
        (``ch-637``) from Sui (``ch-784``), whose addresses are identical in
        shape.
        """
        value = self.metadata.get("chain_id")
        return str(value).strip().lower() if value else None


@dataclass(frozen=True)
class KeyEntry:
    """One wallet key, which may be split across several shares."""

    index: int
    key_name: str
    shares: tuple[Share, ...]
    key_type: str = ""

    @property
    def display_name(self) -> str:
        return self.key_name or "<unnamed>"

    @property
    def declared_curve(self) -> str | None:
        """Curve stated by the backup's ``key_type``, as a ``CURVE_*`` value.

        ``EDDSA_ED25519`` / ``ECDSA_SECP256k1`` in the file. Authoritative when
        present: a raw 32-byte scalar is a valid key on either curve, so
        without this the tool has to derive both and see which reproduces the
        address.
        """
        value = self.key_type.strip().upper()
        if not value:
            return None
        if "ED25519" in value:
            return CURVE_ED25519
        if "SECP256K1" in value:
            return CURVE_SECP256K1
        return None


@dataclass(frozen=True, repr=False)
class Backup:
    """A parsed backup file.

    ``repr`` is suppressed deliberately: ``recovery_key_b64`` is the RSA
    *private* key that decrypts every wallet in the file. With the dataclass
    default, one ``print(backup)`` or a traceback that renders frame locals
    would dump it to the terminal.
    """

    path: Path
    wallet_provider: str
    recovery_key_b64: str | None
    keys: tuple[KeyEntry, ...]
    raw: dict[str, Any]

    def __repr__(self) -> str:
        return (
            f"<Backup {self.path.name} provider={self.wallet_provider!r} "
            f"keys={len(self.keys)} shares={self.share_count} "
            f"recovery_key={'present' if self.recovery_key_b64 else 'absent'}>"
        )

    __str__ = __repr__

    @property
    def share_count(self) -> int:
        return sum(len(entry.shares) for entry in self.keys)

    def iter_shares(self):
        """Yield ``(KeyEntry, Share)`` pairs in file order."""
        for entry in self.keys:
            for share in entry.shares:
                yield entry, share


def load(path: str | Path) -> Backup:
    """Read and parse a backup JSON file."""
    path = Path(path).expanduser()

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise BackupFormatError(f"file not found: {path}") from None
    except OSError as exc:
        raise BackupFormatError(f"could not read {path}: {exc}") from exc

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BackupFormatError(f"{path} is not valid JSON: {exc}") from exc

    if isinstance(document, list):
        raise BackupFormatError(
            f"{path.name} is a JSON array. This tool expects the object-shaped backup "
            "file with a top-level 'recovery_key' and 'keys' list. A JSON array of "
            "{encrypted_key, wallet_address, ...} objects is the batch-backup format, "
            "which uses ECIES rather than RSA-OAEP and is not handled here."
        )
    if not isinstance(document, dict):
        raise BackupFormatError(f"{path.name} should contain a JSON object at the top level")

    raw_keys = document.get("keys")
    if raw_keys is None:
        raise BackupFormatError(
            f"{path.name} has no 'keys' field -- this does not look like a wallet backup file"
        )
    if not isinstance(raw_keys, list):
        raise BackupFormatError("'keys' must be a list")

    entries: list[KeyEntry] = []
    share_index = 0
    for key_index, raw_entry in enumerate(raw_keys):
        if not isinstance(raw_entry, dict):
            raise BackupFormatError(f"keys[{key_index}] is not an object")

        raw_shares = raw_entry.get("shares") or []
        if not isinstance(raw_shares, list):
            raise BackupFormatError(f"keys[{key_index}].shares must be a list")

        shares: list[Share] = []
        for raw_share in raw_shares:
            if not isinstance(raw_share, dict):
                raise BackupFormatError(f"keys[{key_index}] contains a non-object share")
            encryption = raw_share.get("encryption") or {}
            metadata = raw_share.get("metadata") or {}
            if not isinstance(encryption, dict) or not isinstance(metadata, dict):
                raise BackupFormatError(
                    f"keys[{key_index}] share has a non-object 'encryption' or 'metadata'"
                )
            shares.append(Share(index=share_index, encryption=encryption, metadata=metadata))
            share_index += 1

        entries.append(
            KeyEntry(
                index=key_index,
                key_name=str(raw_entry.get("key_name") or ""),
                shares=tuple(shares),
                key_type=str(raw_entry.get("key_type") or ""),
            )
        )

    if share_index == 0:
        raise BackupFormatError(f"{path.name} contains no shares to decrypt")

    recovery_key = document.get("recovery_key")

    # Keep exactly one copy of the RSA private key, in the field that is
    # documented to hold it. Leaving a second copy in `raw` means every
    # incidental dump of the parsed document leaks it.
    redacted = {k: v for k, v in document.items() if k != "recovery_key"}

    return Backup(
        path=path,
        wallet_provider=str(document.get("wallet_provider") or "?"),
        recovery_key_b64=str(recovery_key) if recovery_key else None,
        keys=tuple(entries),
        raw=redacted,
    )
