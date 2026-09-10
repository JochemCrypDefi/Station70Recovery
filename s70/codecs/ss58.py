"""SS58 address encoding (Substrate / Polkadot).

Layout::

    base58( prefix_bytes || public_key || blake2b_512(b"SS58PRE" || prefix_bytes || public_key)[:2] )

The same 32-byte public key renders as a *different* string for every
network prefix, so comparisons must be done on public keys -- or by trying
each candidate prefix. Common prefixes:

==============  ======
network         prefix
==============  ======
Polkadot        0
Kusama          2
Substrate/dev   42
==============  ======
"""

from __future__ import annotations

from s70.codecs import b58
from s70.codecs.hashes import blake2b_512

PREFIX_POLKADOT = 0
PREFIX_KUSAMA = 2
PREFIX_SUBSTRATE = 42

#: Prefixes worth trying when identifying an unknown SS58 address.
COMMON_PREFIXES = (PREFIX_POLKADOT, PREFIX_KUSAMA, PREFIX_SUBSTRATE)

_SS58_PRE = b"SS58PRE"


def _prefix_bytes(prefix: int) -> bytes:
    """Encode a network prefix into its 1- or 2-byte SS58 form."""
    if 0 <= prefix <= 63:
        return bytes([prefix])
    if 64 <= prefix <= 16383:
        # Two-byte form, per the SS58 spec's bit-shuffling.
        ident = prefix & 0x3FFF
        first = ((ident & 0xFC) >> 2) | 0x40
        second = (ident >> 8) | ((ident & 0x03) << 6)
        return bytes([first, second])
    raise ValueError(f"SS58 prefix {prefix} out of range (0..16383)")


def _decode_prefix(raw: bytes) -> tuple[int, int]:
    """Return (prefix, number_of_prefix_bytes) from the head of ``raw``."""
    if raw[0] & 0x40:
        if len(raw) < 2:
            raise ValueError("truncated two-byte SS58 prefix")
        lower = (raw[0] & 0x3F) << 2
        upper = raw[1] >> 6
        return (lower | upper) | (raw[1] & 0x3F) << 8, 2
    return raw[0], 1


def encode(public_key: bytes, prefix: int = PREFIX_POLKADOT) -> str:
    """Encode a 32-byte public key as an SS58 address."""
    if len(public_key) != 32:
        raise ValueError(f"SS58 account key must be 32 bytes, got {len(public_key)}")
    head = _prefix_bytes(prefix)
    body = head + public_key
    checksum = blake2b_512(_SS58_PRE + body)[:2]
    return b58.encode(body + checksum)


def decode(address: str) -> tuple[bytes, int]:
    """Decode an SS58 address, returning (public_key, prefix).

    Raises ValueError if the checksum does not verify.
    """
    raw = b58.decode(address.strip())
    if len(raw) < 35:
        raise ValueError(f"SS58 address decodes to only {len(raw)} bytes")

    prefix, prefix_len = _decode_prefix(raw)
    body, checksum = raw[:-2], raw[-2:]
    public_key = body[prefix_len:]

    if len(public_key) != 32:
        raise ValueError(f"SS58 payload is {len(public_key)} bytes, expected 32")
    if blake2b_512(_SS58_PRE + body)[:2] != checksum:
        raise ValueError("SS58 checksum mismatch")
    return public_key, prefix
