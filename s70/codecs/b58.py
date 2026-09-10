"""Base58 and Base58Check, with pluggable alphabets.

Bitcoin/Solana/Polkadot share one alphabet; XRPL uses its own permutation of
the same 58 characters. Passing the wrong alphabet produces a string that
looks perfectly valid and decodes to garbage, so the alphabet is always an
explicit argument.
"""

from __future__ import annotations

from s70.codecs.hashes import double_sha256

#: Bitcoin / Solana / Substrate alphabet.
BITCOIN = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#: XRPL's "dictionary" -- same 58 characters, different order.
XRPL = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def encode(data: bytes, alphabet: str = BITCOIN) -> str:
    """Base58-encode ``data``, preserving leading zero bytes as leading '1's."""
    if not data:
        return ""

    leading_zeros = 0
    for byte in data:
        if byte != 0:
            break
        leading_zeros += 1

    num = int.from_bytes(data, "big")
    out: list[str] = []
    base = len(alphabet)
    while num > 0:
        num, rem = divmod(num, base)
        out.append(alphabet[rem])

    return alphabet[0] * leading_zeros + "".join(reversed(out))


def decode(text: str, alphabet: str = BITCOIN) -> bytes:
    """Base58-decode ``text``. Raises ValueError on an out-of-alphabet char."""
    if text == "":
        return b""

    index = {char: i for i, char in enumerate(alphabet)}
    base = len(alphabet)

    num = 0
    for char in text:
        try:
            num = num * base + index[char]
        except KeyError:
            raise ValueError(f"character {char!r} is not in this base58 alphabet") from None

    leading_zeros = 0
    for char in text:
        if char != alphabet[0]:
            break
        leading_zeros += 1

    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * leading_zeros + body


def encode_check(payload: bytes, alphabet: str = BITCOIN) -> str:
    """Append a 4-byte double-SHA256 checksum, then base58-encode."""
    return encode(payload + double_sha256(payload)[:4], alphabet)


def decode_check(text: str, alphabet: str = BITCOIN) -> bytes:
    """Base58-decode and verify+strip the 4-byte checksum."""
    raw = decode(text, alphabet)
    if len(raw) < 5:
        raise ValueError("base58check payload is too short to contain a checksum")
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("base58check checksum mismatch")
    return payload
