"""The chain abstraction.

A :class:`ChainSpec` answers two questions:

1. *Could this address belong to me?* -- a cheap shape test used to narrow
   candidates before anything is decrypted.
2. *What addresses would this key produce under my rules?* -- used after
   decryption to confirm the chain and prove the key is the right one.

Question 2 is the important one. Several chains share an address shape
(Aptos and Sui are both ``0x`` + 64 hex; Solana and Polkadot are both
base58), and a 32-byte plaintext is a valid key on two different curves.
Deriving the address and comparing it to the one recorded in the backup
resolves all of that at once, and simultaneously proves the decryption was
correct rather than merely well-formed.
"""

from __future__ import annotations

from dataclasses import dataclass

from s70.keymaterial import KeyMaterial


@dataclass(frozen=True)
class ChainSpec:
    """Static description of one supported chain."""

    id: str
    label: str
    #: Curves this chain's keys can use, in order of likelihood.
    curves: tuple[str, ...]

    # -- shape ------------------------------------------------------------

    def matches_shape(self, address: str) -> bool:
        """Cheap test: could ``address`` plausibly belong to this chain?"""
        raise NotImplementedError

    def normalize(self, address: str) -> str:
        """Canonical form used for equality comparison."""
        return address.strip()

    # -- derivation -------------------------------------------------------

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        """Every address this key could produce under this chain's rules.

        Returning several candidates is normal and intentional: chains often
        have more than one live address scheme (Aptos legacy vs unified,
        Polkadot's per-network prefixes), and matching any one of them is a
        positive identification. Return an empty list if the chain's address
        cannot be derived offline.
        """
        raise NotImplementedError

    def matches_key(self, address: str, key: KeyMaterial) -> tuple[bool, str | None]:
        """Does ``key`` produce ``address``?

        Returns ``(matched, derived_address)``. ``derived_address`` is the
        first candidate, for display when the match fails.
        """
        if key.curve not in self.curves:
            return False, None
        try:
            candidates = self.addresses_for(key)
        except Exception:  # noqa: BLE001 - a derivation failure is just a non-match
            return False, None
        if not candidates:
            return False, None

        target = self.normalize(address)
        for candidate in candidates:
            if self.normalize(candidate) == target:
                return True, candidate
        return False, candidates[0]
