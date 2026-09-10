"""EVM chains (Ethereum and every L2/sidechain that shares its address format)."""

from __future__ import annotations

import re

from s70.chains.base import ChainSpec
from s70.codecs.hashes import keccak256
from s70.keymaterial import CURVE_SECP256K1, KeyMaterial

_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def to_checksum_address(address_bytes: bytes) -> str:
    """EIP-55 mixed-case checksum encoding of a 20-byte address."""
    if len(address_bytes) != 20:
        raise ValueError(f"EVM address must be 20 bytes, got {len(address_bytes)}")
    lowercase = address_bytes.hex()
    digest = keccak256(lowercase.encode("ascii")).hex()
    out = "".join(
        char.upper() if char.isalpha() and int(digest[i], 16) >= 8 else char
        for i, char in enumerate(lowercase)
    )
    return "0x" + out


class EvmChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        return bool(_RE.match(address.strip()))

    def normalize(self, address: str) -> str:
        # EIP-55 casing carries a checksum but is not part of the identity.
        return address.strip().lower()

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        if key.curve != CURVE_SECP256K1:
            return []
        return [to_checksum_address(keccak256(key.public_key)[-20:])]


SPEC = EvmChain(
    id="evm",
    label="EVM",
    curves=(CURVE_SECP256K1,),
    wallet="Rabby or MetaMask",
    address_verifiable=True,
    supports_signing=False,
    signing_note=(
        "Transaction building is deliberately not offered for EVM. There is no "
        "reliable way to enumerate everything of value at an EVM address: ERC-20 has "
        "no reverse index, so a scan can only check tokens it already knows to ask "
        "about, and it would miss LP, staked, vesting, locked and bridged positions "
        "entirely. A partial sweep that looks complete is worse than no sweep. "
        "Import the key into Rabby and use its portfolio view across chains instead."
    ),
    aliases=("ethereum", "eth"),
)
