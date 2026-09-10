"""The job file: the seam between the online and offline halves of phase 2.

None of these chains can build a valid transaction fully offline. Every one
needs at least a sequence number, and most need more: a recent blockhash, a
gas price, live object references. So the tool splits in two:

* ``s70 inspect`` runs **online** with **no keys loaded**. It reads chain
  state and asset balances and writes a job file. A job file contains only
  public data -- addresses, balances, sequence numbers -- so it is safe to
  carry on a USB stick between machines.
* ``s70 sign`` runs **offline** with the backup and the job file. It opens no
  sockets. It emits a signed blob.

Submission is always a third, manual step. This tool never submits.

Job files go stale, and how fast varies enormously by chain: a Solana
blockhash dies in 60-90 seconds, while a Stellar sequence number lasts until
the account transacts. :attr:`TransferJob.staleness_warning` spells out the
specific deadline for the chain in question rather than giving a generic
"this may be out of date".
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from s70.errors import JobFileError

JOB_VERSION = 1


@dataclass
class Precondition:
    """One thing that must hold for the planned transaction to succeed."""

    name: str
    satisfied: bool
    detail: str = ""
    #: True when the user must act before the sweep can work at all.
    blocking: bool = True

    @property
    def symbol(self) -> str:
        return "ok" if self.satisfied else ("BLOCKED" if self.blocking else "warn")


@dataclass
class Asset:
    """One holding discovered at the source address."""

    symbol: str
    #: Human-readable amount, as a decimal string. Never a float.
    amount: str
    #: Chain-native identifier: mint, coin type, asset code, currency.
    identifier: str = ""
    decimals: int | None = None
    #: Chain-specific extras the signer needs (object refs, token accounts).
    extra: dict[str, Any] = field(default_factory=dict)
    #: Set when the asset cannot be swept and why.
    blocked: str | None = None


@dataclass
class TransferJob:
    """Everything the offline signer needs, and nothing secret."""

    chain: str
    source_address: str
    destination_address: str
    #: Chain state read online: sequence numbers, blockhashes, fees.
    network: dict[str, Any] = field(default_factory=dict)
    assets: list[Asset] = field(default_factory=list)
    preconditions: list[Precondition] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Free-text description of the plan, shown before signing.
    plan: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    version: int = JOB_VERSION
    #: Seconds after creation beyond which the job is very likely useless.
    ttl_seconds: int | None = None
    ttl_note: str = ""

    # -- state ------------------------------------------------------------

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def blocking_failures(self) -> list[Precondition]:
        return [p for p in self.preconditions if not p.satisfied and p.blocking]

    @property
    def ready(self) -> bool:
        return not self.blocking_failures

    @property
    def staleness_warning(self) -> str | None:
        """A chain-specific warning about the age of this job, if relevant."""
        if self.ttl_seconds is None:
            return None
        age = self.age_seconds
        if age < self.ttl_seconds * 0.5:
            return None
        if age >= self.ttl_seconds:
            return (
                f"This job is {age:.0f}s old and its useful life was about "
                f"{self.ttl_seconds}s. {self.ttl_note} Re-run `s70 inspect` before signing."
            )
        return (
            f"This job is {age:.0f}s old of about {self.ttl_seconds}s. {self.ttl_note}"
        )

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write(self, path: str | Path) -> Path:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path

    @classmethod
    def read(cls, path: str | Path) -> TransferJob:
        path = Path(path).expanduser()
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise JobFileError(f"job file not found: {path}") from None
        except json.JSONDecodeError as exc:
            raise JobFileError(f"{path.name} is not valid JSON: {exc}") from exc

        if document.get("version") != JOB_VERSION:
            raise JobFileError(
                f"{path.name} is job format version {document.get('version')}, "
                f"but this tool writes and reads version {JOB_VERSION}"
            )

        document["assets"] = [Asset(**a) for a in document.get("assets", [])]
        document["preconditions"] = [
            Precondition(**p) for p in document.get("preconditions", [])
        ]
        try:
            return cls(**document)
        except TypeError as exc:
            raise JobFileError(f"{path.name} has unexpected fields: {exc}") from exc


@dataclass
class SignedBundle:
    """A signed, unsubmitted transaction."""

    chain: str
    #: The blob(s) to submit, in submission order.
    blobs: list[str]
    #: "hex", "base64", or "base64-xdr".
    encoding: str
    #: Copy-pasteable submission command.
    submit_command: str
    #: Prose instructions, including where to verify before submitting.
    submit_notes: list[str] = field(default_factory=list)
    #: What this transaction does, restated from the signed bytes where possible.
    summary: list[str] = field(default_factory=list)
    #: Absolute deadline, if the chain gives the blob one.
    expires_note: str = ""

    def write(self, path: str | Path) -> Path:
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "chain": self.chain,
                    "encoding": self.encoding,
                    "blobs": self.blobs,
                    "submit_command": self.submit_command,
                    "submit_notes": self.submit_notes,
                    "summary": self.summary,
                    "expires_note": self.expires_note,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path
