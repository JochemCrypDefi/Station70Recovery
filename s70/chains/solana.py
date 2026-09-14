"""Solana."""

from __future__ import annotations

from s70.chains.base import ChainSpec
from s70.codecs import b58
from s70.keymaterial import CURVE_ED25519, KeyMaterial


class SolanaChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        address = address.strip()
        if not 32 <= len(address) <= 44:
            return False
        try:
            # A Solana address is exactly the 32-byte public key in base58,
            # with no version byte and no checksum. The length check is what
            # separates it from an SS58 address, which carries both.
            return len(b58.decode(address)) == 32
        except ValueError:
            return False

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        if key.curve != CURVE_ED25519:
            return []
        return [b58.encode(key.public_key)]


SPEC = SolanaChain(id="solana", label="Solana", curves=(CURVE_ED25519,))
