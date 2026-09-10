"""Recovery session: the layer the CLI and the TUI both drive.

Keeping this separate from both front ends means the decryption logic is
exercised identically whether you run ``s70 list``, ``s70 verify`` or the
TUI, and it keeps key material out of widget state.

Decryption is lazy and per-wallet on purpose. The tool never decrypts every
key in the backup because you wanted to look at one -- each reveal is an
explicit, individually confirmed action.

Every wallet is decryptable. Chains this tool cannot derive an address for are
still recovered and still show their raw key bytes; what they lose is the
address cross-check, which the UI reports rather than hides.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from s70 import chains, recovery
from s70.backup import Backup, KeyEntry, Share
from s70.chains import ChainSpec, Identification, Status
from s70.errors import S70Error
from s70.keymaterial import KeyMaterial, parse_candidates
from s70.recovery import DecryptedShare


@dataclass
class WalletRecord:
    """One wallet in the backup, plus whatever we have learned about it."""

    entry: KeyEntry
    share: Share

    # Populated on load, from the address alone.
    shape_candidates: tuple[ChainSpec, ...] = ()

    # Populated by recover(). These hold key material.
    decrypted: DecryptedShare | None = None
    identification: Identification | None = None
    error: str | None = None
    skipped_reason: str | None = None

    # Verdicts, retained after forget() discards the key material above. They
    # are what the inventory table displays, so verifying everything does not
    # force us to keep 23 private keys in memory to remember the results.
    integrity_result: bool | None = None
    verdict: Status | None = None
    verdict_detail: str = ""
    verdict_chain_id: str | None = None

    @property
    def address(self) -> str | None:
        return self.share.address

    @property
    def name(self) -> str:
        return self.entry.display_name

    @property
    def supported(self) -> bool:
        """Whether this tool can re-derive the address to cross-check the key.

        False means the key is still recovered and displayed -- it just cannot
        be proved against the recorded address. A share with no recorded
        address is not "unsupported", it is uncheckable; conflating the two
        would flag a perfectly good key because the backup omitted a field.
        """
        if self.address is None:
            return True
        if chains.spec_for_chain_id(self.share.declared_chain_id) is not None:
            return True
        return bool(self.shape_candidates)

    @property
    def recovered(self) -> bool:
        return self.decrypted is not None and self.error is None

    @property
    def key(self) -> KeyMaterial | None:
        """The recovered key, whatever the address verdict turned out to be.

        The private key is the deliverable. A failed or impossible address
        cross-check is information to show alongside it, not grounds for
        withholding it -- see :attr:`verified_for_signing` for the stricter
        test the transfer flow uses.
        """
        if self.identification:
            return self.identification.key
        return None

    @property
    def verified_for_signing(self) -> bool:
        """True only when the key provably controls the recorded address."""
        return bool(self.identification and self.identification.ok)

    @property
    def chain(self) -> ChainSpec | None:
        if self.identification and self.identification.chain:
            return self.identification.chain
        if self.verdict_chain_id:
            resolved = chains.by_id(self.verdict_chain_id)
            if resolved is not None:
                return resolved
        # The backup's own chain_id, before anything has been decrypted. This
        # is what distinguishes Aptos from Sui in the inventory table.
        declared = chains.spec_for_chain_id(self.share.declared_chain_id)
        if declared is not None:
            return declared
        if len(self.shape_candidates) == 1:
            return self.shape_candidates[0]
        return None

    @property
    def chain_label(self) -> str:
        """Best available chain name, hedged when the address shape is ambiguous."""
        chain = self.chain
        if chain is not None:
            return chain.label
        # Plain name. That the address cannot be derived is already the
        # verdict column's job to say; repeating it here is noise.
        named = chains.label_for_chain_id(self.share.declared_chain_id)
        if named:
            return named
        if not self.shape_candidates:
            return "unrecognised"
        return "/".join(spec.label for spec in self.shape_candidates)

    @property
    def status_label(self) -> str:
        if self.skipped_reason:
            return "skipped"
        if self.error:
            return "error"
        if self.integrity_result is False:
            return "HASH MISMATCH"
        if self.verdict is None:
            return "not recovered"
        return self.verdict.value

    @property
    def soft_verified(self) -> bool:
        """The recorded SHA-256 of the plaintext matched.

        Weaker than :attr:`fully_verified`: it proves the decryption returned
        exactly the bytes that were encrypted, which catches a wrong recovery
        key or a corrupt share. It does *not* prove the key controls the
        address in the backup -- only re-deriving the address does that.
        """
        return self.integrity_result is True

    @property
    def fully_verified(self) -> bool:
        """Both integrity checks passed: SHA-256 and address derivation."""
        return self.integrity_result is not False and self.verdict is Status.VERIFIED

    @property
    def integrity_label(self) -> str:
        if self.verdict is None and self.integrity_result is None:
            return "-"
        if self.integrity_result is True:
            return "verified (sha256 matches)"
        if self.integrity_result is None:
            return "no hash in backup"
        return "HASH MISMATCH"


@dataclass
class SessionStats:
    total: int = 0
    verified: int = 0
    unverifiable: int = 0
    mismatched: int = 0
    failed: int = 0
    #: Decrypted and SHA-256-checked, but no address derivation exists for the
    #: chain, so the key was never proved to control the recorded address.
    sha_only: int = 0


class RecoverySession:
    """Holds a parsed backup and a loaded recovery key."""

    def __init__(self, backup: Backup, recovery_key: rsa.RSAPrivateKey) -> None:
        self.backup = backup
        self.recovery_key = recovery_key
        self.records: list[WalletRecord] = [
            WalletRecord(
                entry=entry,
                share=share,
                shape_candidates=tuple(chains.shape_candidates(share.address)),
            )
            for entry, share in backup.iter_shares()
        ]

    # -- construction -----------------------------------------------------

    @classmethod
    def open(cls, backup: Backup) -> RecoverySession:
        """Load the RSA recovery key that the backup file carries."""
        if not backup.recovery_key_b64:
            raise S70Error(
                f"{backup.path.name} has no 'recovery_key' field, so there is nothing "
                "to decrypt the wallet keys with. Every CrypDefi backup embeds one -- "
                "this file is truncated or is not a CrypDefi backup."
            )
        return cls(backup, recovery.load_recovery_key_from_b64(backup.recovery_key_b64))

    @property
    def recovery_key_label(self) -> str:
        return recovery.describe_recovery_key(self.recovery_key)

    # -- recovery ---------------------------------------------------------

    def recover(self, record: WalletRecord) -> WalletRecord:
        """Decrypt and identify one wallet. Idempotent."""
        if record.recovered:
            return record

        record.error = None
        record.skipped_reason = None

        try:
            decrypted = recovery.decrypt_share(self.recovery_key, record.share)
        except S70Error as exc:
            record.error = str(exc)
            return record

        record.decrypted = decrypted
        record.integrity_result = decrypted.integrity_verified

        try:
            candidates = parse_candidates(decrypted.plaintext.reveal())
        except S70Error as exc:
            record.error = str(exc)
            return record

        identification = chains.identify(
            record.address,
            candidates,
            declared_chain_id=record.share.declared_chain_id,
            declared_curve=record.entry.declared_curve,
        )
        record.identification = identification
        record.verdict = identification.status
        record.verdict_detail = identification.detail
        record.verdict_chain_id = identification.chain.id if identification.chain else None
        return record

    def recover_all(self, *, forget_keys: bool = False) -> SessionStats:
        """Decrypt everything.

        With ``forget_keys`` the key material is discarded as soon as each
        wallet's verdict is recorded, which is what a bulk verification wants:
        the answer, not 23 private keys sitting in memory.
        """
        stats = SessionStats(total=len(self.records))
        for record in self.records:
            self.recover(record)

            if record.error:
                stats.failed += 1
            elif record.integrity_result is False:
                stats.mismatched += 1
            elif record.verdict is None:
                stats.failed += 1
            elif record.verdict is Status.VERIFIED:
                stats.verified += 1
            elif record.verdict is Status.UNVERIFIABLE:
                stats.unverifiable += 1
            elif record.verdict in (Status.UNSUPPORTED, Status.NO_ADDRESS):
                stats.sha_only += 1
            else:
                stats.mismatched += 1

            if forget_keys:
                self.forget(record)
        return stats

    # -- inventory --------------------------------------------------------

    def inventory(self) -> list[WalletRecord]:
        return self.records

    def unsupported(self) -> list[WalletRecord]:
        return [record for record in self.records if not record.supported]

    def forget(self, record: WalletRecord) -> None:
        """Drop recovered key material for one record, keeping its verdict.

        Python offers no way to reliably erase the immutable bytes the
        cryptography stack returned, so this reduces the window rather than
        closing it. It still means a long-running TUI session is not sitting
        on every key you have ever looked at.

        ``integrity_result``, ``verdict`` and ``verdict_chain_id`` survive, so
        the inventory keeps showing what was established without holding the
        key that established it.
        """
        record.decrypted = None
        record.identification = None


@dataclass
class RevealResult:
    """A recovered key rendered for one target wallet."""

    record: WalletRecord
    guide: object  # s70.wallets.ImportGuide -- imported lazily to avoid a cycle
    notes: list[str] = field(default_factory=list)
