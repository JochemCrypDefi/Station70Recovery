"""Sui.

Sui addresses are ``blake2b_256(flag || public_key)``. The scheme flag is
*inside* the hash, so one 32-byte key yields a different address under
Ed25519 than under secp256k1 -- which is exactly what lets us tell an Aptos
address from a Sui one even though both are ``0x`` + 64 hex.
"""

from __future__ import annotations

import re

from s70.chains.base import ChainSpec
from s70.codecs.hashes import blake2b_256
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, KeyMaterial

_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

FLAG_ED25519 = 0x00
FLAG_SECP256K1 = 0x01
FLAG_SECP256R1 = 0x02


class SuiChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        return bool(_RE.match(address.strip()))

    def normalize(self, address: str) -> str:
        body = address.strip().lower().removeprefix("0x")
        return "0x" + body.rjust(64, "0")

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        if key.curve == CURVE_ED25519:
            payload = bytes([FLAG_ED25519]) + key.public_key
        elif key.curve == CURVE_SECP256K1:
            payload = bytes([FLAG_SECP256K1]) + key.compressed_public_key
        else:
            return []
        return ["0x" + blake2b_256(payload).hex()]


SPEC = SuiChain(id="sui", label="Sui", curves=(CURVE_ED25519, CURVE_SECP256K1))
