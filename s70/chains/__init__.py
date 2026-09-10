"""Chain registry and identification.

Identification runs in two stages, because the useful information arrives at
two different times:

* **Before decryption** we only have the address, so :func:`shape_candidates`
  narrows by format. This is enough to build the inventory table and to warn
  about entries on chains the tool does not support.
* **After decryption** we have a public key, so :func:`identify` derives
  addresses and finds the one chain (and curve) that reproduces the recorded
  address exactly. This resolves Aptos-vs-Sui and Ed25519-vs-secp256k1
  ambiguity, and doubles as proof that the decryption was correct.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from s70.chains import aptos, canton, evm, polkadot, solana, stellar, sui, xrpl
from s70.chains.base import ChainSpec
from s70.keymaterial import KeyMaterial

#: Every chain this tool supports, in display order.
ALL: tuple[ChainSpec, ...] = (
    evm.SPEC,
    solana.SPEC,
    aptos.SPEC,
    sui.SPEC,
    stellar.SPEC,
    polkadot.SPEC,
    xrpl.SPEC,
    canton.SPEC,
)

_BY_ID: dict[str, ChainSpec] = {}
for _spec in ALL:
    _BY_ID[_spec.id] = _spec
    for _alias in _spec.aliases:
        _BY_ID[_alias] = _spec

#: ``metadata.chain_id`` -> this tool's chain id. The backup writes
#: ``ch-<SLIP-44 coin type>``; SLIP-44 is what makes ``ch-637`` (Aptos) and
#: ``ch-784`` (Sui) distinguishable, since their addresses are not.
SLIP44_CHAIN_IDS: dict[str, str] = {
    "ch-60": "evm",
    "ch-144": "xrpl",
    "ch-148": "stellar",
    "ch-354": "polkadot",
    "ch-501": "solana",
    "ch-637": "aptos",
    "ch-784": "sui",
    "ch-6767": "canton",
}

#: Chains that appear in real backups but that this tool cannot derive an
#: address for. Naming them beats showing "unsupported": the key bytes are
#: still recovered and displayed, and the user knows what they are holding.
KNOWN_UNSUPPORTED: dict[str, str] = {
    "ch-1022": "Radix",
}


def label_for_chain_id(chain_id: str | None) -> str | None:
    """Human-readable name for a ``ch-<n>`` identifier, supported or not."""
    if not chain_id:
        return None
    spec = spec_for_chain_id(chain_id)
    if spec is not None:
        return spec.label
    return KNOWN_UNSUPPORTED.get(chain_id.strip().lower())


def spec_for_chain_id(chain_id: str | None) -> ChainSpec | None:
    """Resolve ``metadata.chain_id`` to a supported :class:`ChainSpec`."""
    if not chain_id:
        return None
    mapped = SLIP44_CHAIN_IDS.get(chain_id.strip().lower())
    return _BY_ID.get(mapped) if mapped else None


class Status(str, Enum):
    """Outcome of trying to tie a key to a chain and address."""

    VERIFIED = "verified"
    """The derived address matches the one in the backup."""

    UNVERIFIABLE = "unverifiable"
    """Chain identified, but its address cannot be recomputed offline."""

    MISMATCH = "mismatch"
    """Chain identified, but the key derives a different address."""

    AMBIGUOUS = "ambiguous"
    """Address shape matched several chains and none of them verified."""

    UNSUPPORTED = "unsupported"
    """The address does not belong to any chain this tool handles."""

    NO_ADDRESS = "no-address"
    """The backup recorded no address, so nothing can be cross-checked."""


@dataclass(frozen=True)
class Identification:
    status: Status
    chain: ChainSpec | None
    key: KeyMaterial | None
    derived_address: str | None
    detail: str

    @property
    def ok(self) -> bool:
        """True when the address check passed, or could not be run at all.

        This gates *signing*, not display. Use :attr:`has_key` to decide
        whether there are key bytes to show -- there usually are, even here.
        """
        return self.status in (Status.VERIFIED, Status.UNVERIFIABLE)

    @property
    def has_key(self) -> bool:
        """True when key material was recovered, whatever the verdict."""
        return self.key is not None

    @property
    def chain_label(self) -> str:
        return self.chain.label if self.chain else "unknown"


def by_id(identifier: str) -> ChainSpec | None:
    return _BY_ID.get(identifier.strip().lower())


def shape_candidates(address: str | None) -> list[ChainSpec]:
    """Chains whose address format matches ``address``.

    May return more than one: Aptos and Sui addresses are indistinguishable
    by shape alone.
    """
    if not address:
        return []
    return [spec for spec in ALL if spec.matches_shape(address)]


def identify(
    address: str | None,
    keys: list[KeyMaterial],
    declared_chain_id: str | None = None,
    declared_curve: str | None = None,
) -> Identification:
    """Tie a decrypted key to a chain by reproducing the recorded address.

    ``key`` is populated on *every* outcome that has key material to offer,
    including ``UNSUPPORTED`` and ``MISMATCH``. The recovered private key is
    the whole point of the tool; the status says how much has been proved
    about it, and callers must not treat a non-``VERIFIED`` status as a reason
    to withhold the bytes.
    """
    if not keys:
        return Identification(
            Status.NO_ADDRESS, None, None, None, "no key material to identify"
        )

    # The backup states the curve in `key_type`. Honour it: a 32-byte scalar
    # is valid on both curves, and deriving the wrong one produces a
    # well-formed address for an account nobody controls.
    if declared_curve:
        preferred = [k for k in keys if k.curve == declared_curve]
        if preferred:
            keys = preferred + [k for k in keys if k.curve != declared_curve]

    # `chain_id` is authoritative for *which* chain to check against -- it is
    # the only way to tell Aptos from Sui. It narrows the derivation; it never
    # replaces the address comparison below.
    specs: list[ChainSpec]
    declared_spec = spec_for_chain_id(declared_chain_id)
    if declared_spec is not None:
        specs = [declared_spec]
    else:
        specs = shape_candidates(address)

    if not address:
        return Identification(
            Status.NO_ADDRESS,
            specs[0] if len(specs) == 1 else None,
            keys[0],
            None,
            "backup recorded no address for this share, so the key cannot be cross-checked",
        )

    if not specs:
        named = KNOWN_UNSUPPORTED.get((declared_chain_id or "").strip().lower())
        detail = (
            f"{named} is not a chain this tool can derive an address for; the raw "
            "private key below is correct but was not cross-checked against the "
            "recorded address"
            if named
            else "address format not recognised by any supported chain; the raw "
            f"private key below was not cross-checked: {address[:24]}..."
        )
        return Identification(Status.UNSUPPORTED, None, keys[0], None, detail)

    # Positive identification: some (chain, curve) pair reproduces the address.
    for spec in specs:
        for key in keys:
            matched, derived = spec.matches_key(address, key)
            if matched:
                return Identification(
                    Status.VERIFIED,
                    spec,
                    key,
                    derived,
                    f"{spec.label} address derived from the recovered key matches the backup",
                )

    # No match. Distinguish "can't check" from "checked and wrong".
    unverifiable = [spec for spec in specs if not spec.address_verifiable]
    if unverifiable:
        spec = unverifiable[0]
        key = next((k for k in keys if k.curve in spec.curves), keys[0])
        return Identification(
            Status.UNVERIFIABLE,
            spec,
            key,
            None,
            f"{spec.label} addresses cannot be recomputed offline; key integrity rests "
            "on the SHA-256 check alone",
        )

    if len(specs) == 1:
        spec = specs[0]
        key = next((k for k in keys if k.curve in spec.curves), keys[0])
        _, derived = spec.matches_key(address, key)
        return Identification(
            Status.MISMATCH,
            spec,
            key,
            derived,
            f"key derives {derived or '<no address>'} but the backup records {address}",
        )

    return Identification(
        Status.AMBIGUOUS,
        None,
        keys[0],
        None,
        "address shape matches "
        + " or ".join(spec.label for spec in specs)
        + ", but the recovered key reproduces neither",
    )


__all__ = [
    "ALL",
    "KNOWN_UNSUPPORTED",
    "SLIP44_CHAIN_IDS",
    "ChainSpec",
    "Identification",
    "Status",
    "by_id",
    "identify",
    "label_for_chain_id",
    "shape_candidates",
    "spec_for_chain_id",
]
