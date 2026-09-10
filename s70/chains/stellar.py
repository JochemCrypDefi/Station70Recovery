"""Stellar."""

from __future__ import annotations

import re

from s70.chains.base import ChainSpec
from s70.codecs import strkey
from s70.keymaterial import CURVE_ED25519, KeyMaterial

_RE = re.compile(r"^G[A-Z2-7]{55}$")


class StellarChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        address = address.strip()
        if not _RE.match(address):
            return False
        try:
            # StrKey carries a CRC16 checksum, so this is a real validation
            # rather than a shape guess.
            strkey.decode_ed25519_public_key(address)
        except ValueError:
            return False
        return True

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        if key.curve != CURVE_ED25519:
            return []
        return [strkey.encode_ed25519_public_key(key.public_key)]


SPEC = StellarChain(
    id="stellar",
    label="Stellar",
    curves=(CURVE_ED25519,),
    wallet="Freighter",
    address_verifiable=True,
    supports_signing=True,
    import_note=(
        "Freighter takes the StrKey secret seed ('S' + 55 chars). It cannot recover an "
        "imported secret key from its recovery phrase, and says so during import."
    ),
    aliases=("xlm",),
)
