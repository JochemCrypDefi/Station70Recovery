"""Bech32 / Bech32m (BIP-173 / BIP-350).

Sui private keys use plain **bech32** (constant 1), not bech32m. Encoding a
Sui key with bech32m produces a string that starts with ``suiprivkey1`` and
fails checksum validation inside the wallet, so the variant matters.

Adapted from the BIP-173 reference implementation.
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


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


def _create_checksum(hrp: str, data: list[int], const: int) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def encode(hrp: str, data: list[int], *, bech32m: bool = False) -> str:
    """Encode 5-bit ``data`` groups under human-readable prefix ``hrp``."""
    const = BECH32M_CONST if bech32m else BECH32_CONST
    combined = data + _create_checksum(hrp, data, const)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def encode_bytes(hrp: str, payload: bytes, *, bech32m: bool = False) -> str:
    """Convenience wrapper: 8-bit ``payload`` -> bech32 string."""
    return encode(hrp, convertbits(payload, 8, 5), bech32m=bech32m)


def decode(text: str, *, bech32m: bool = False) -> tuple[str, list[int]]:
    """Decode and verify a bech32(m) string, returning (hrp, 5-bit data)."""
    if text != text.lower() and text != text.upper():
        raise ValueError("bech32 string is mixed case")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise ValueError("bech32 string has no valid separator position")
    hrp, data_part = text[:pos], text[pos + 1 :]
    try:
        data = [CHARSET.index(c) for c in data_part]
    except ValueError:
        raise ValueError("bech32 string contains an out-of-charset character") from None
    const = BECH32M_CONST if bech32m else BECH32_CONST
    if _polymod(_hrp_expand(hrp) + data) != const:
        raise ValueError("bech32 checksum mismatch")
    return hrp, data[:-6]


def decode_bytes(text: str, *, bech32m: bool = False) -> tuple[str, bytes]:
    """Decode a bech32(m) string back to (hrp, 8-bit payload)."""
    hrp, data = decode(text, bech32m=bech32m)
    return hrp, bytes(convertbits(data, 5, 8, pad=False))
