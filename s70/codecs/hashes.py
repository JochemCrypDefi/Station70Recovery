"""Hash primitives.

Two of these are not available from hashlib on a normal build:

* keccak256 -- Ethereum uses original Keccak, *not* the NIST SHA3-256 that
  hashlib exposes as ``sha3_256``. They differ in the padding byte and give
  completely different digests. Getting this wrong silently produces
  plausible-looking but wrong EVM addresses.
* ripemd160 -- OpenSSL 3 moved RIPEMD160 to the legacy provider, so
  ``hashlib.new("ripemd160")`` raises on most modern Python builds
  (including the python.org Windows installers).

Both come from pycryptodome instead.
"""

from __future__ import annotations

import hashlib

from Crypto.Hash import RIPEMD160 as _RIPEMD160
from Crypto.Hash import keccak as _keccak


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (Ethereum), not NIST SHA3-256."""
    return _keccak.new(digest_bits=256, data=data).digest()


def sha3_256(data: bytes) -> bytes:
    """NIST SHA3-256 (used by Aptos authentication keys)."""
    return hashlib.sha3_256(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def ripemd160(data: bytes) -> bytes:
    return _RIPEMD160.new(data).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(x)) -- the XRPL/Bitcoin AccountID construction."""
    return ripemd160(sha256(data))


def blake2b_256(data: bytes) -> bytes:
    """32-byte BLAKE2b (Sui addresses)."""
    return hashlib.blake2b(data, digest_size=32).digest()


def blake2b_512(data: bytes) -> bytes:
    """64-byte BLAKE2b (SS58 checksums)."""
    return hashlib.blake2b(data, digest_size=64).digest()


def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM: poly 0x1021, init 0x0000, no reflection, no final xor.

    Used by Stellar's StrKey checksum.
    """
    crc = 0x0000
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc
