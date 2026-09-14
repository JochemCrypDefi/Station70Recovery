"""Bech32 (BIP-173), the encoding of a Sui private key.

Sui uses plain **bech32** (checksum constant 1), not bech32m. Encoding a Sui
key with bech32m produces a string that still starts with ``suiprivkey1`` and
then fails checksum validation inside the wallet, so the constant matters.
Only bech32 is implemented here, which is one way to be sure of it.

Encoding only: nothing in this tool reads a bech32 string back.

Adapted from the BIP-173 reference implementation.
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32_CONST = 1


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    """Regroup bits, e.g. 8-bit bytes into 5-bit bech32 groups."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("value out of range for convertbits")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in convertbits")
    return ret


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def encode(hrp: str, data: list[int]) -> str:
    """Encode 5-bit ``data`` groups under human-readable prefix ``hrp``."""
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def encode_bytes(hrp: str, payload: bytes) -> str:
    """Convenience wrapper: 8-bit ``payload`` -> bech32 string."""
    return encode(hrp, convertbits(payload, 8, 5))
