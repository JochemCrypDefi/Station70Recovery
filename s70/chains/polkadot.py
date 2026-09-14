"""Polkadot / Substrate.

Two things about Polkadot make it the awkward case of the set.

**Import.** Talisman does not support importing a raw private key for
Substrate accounts at all -- its private-key field is limited to Ethereum and
Solana. Substrate accounts arrive only via mnemonic, Ledger, Vault QR, or a
polkadot-js JSON keystore. So the import path here is "write a keystore file",
not "copy a string"; see :mod:`s70.keystore_polkadot`.

**Curve.** Substrate accounts are usually sr25519, but sr25519 has no
implementation in this tool's dependency set, and its keystore format needs
the 64-byte *expanded* key rather than the 32-byte mini-secret. We therefore
only handle Ed25519 Substrate accounts, and we detect that by checking whether
the Ed25519 public key derived from the recovered key reproduces the recorded
SS58 address. If it does not, the account is almost certainly sr25519 and the
UI says so instead of emitting a keystore that would import as the wrong
account.
"""

from __future__ import annotations

from s70.chains.base import ChainSpec
from s70.codecs import ss58
from s70.keymaterial import CURVE_ED25519, KeyMaterial


class PolkadotChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        address = address.strip()
        if not 40 <= len(address) <= 60:
            return False
        try:
            ss58.decode(address)
        except ValueError:
            return False
        return True

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        if key.curve != CURVE_ED25519:
            return []
        return [ss58.encode(key.public_key, prefix) for prefix in ss58.COMMON_PREFIXES]

    def prefix_of(self, address: str) -> int:
        """Network prefix of an existing address, so we can round-trip it."""
        return ss58.decode(address)[1]


SPEC = PolkadotChain(id="polkadot", label="Polkadot", curves=(CURVE_ED25519,))
