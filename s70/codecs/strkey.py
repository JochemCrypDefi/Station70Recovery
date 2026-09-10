"""Stellar StrKey (SEP-23).

Layout::

    base32_no_padding( version_byte || payload || crc16_xmodem_le )

The version byte is ``(key_type << 3) | algorithm``, where algorithm 0 is
Ed25519. Two matter here:

===================  ==========  =========  ============  ======
kind                 key_type    version    leading char  length
===================  ==========  =========  ============  ======
ed25519 public key   6           0x30       ``G``         56
ed25519 secret seed  18          0x90       ``S``         56
===================  ==========  =========  ============  ======

35 bytes is exactly 280 bits = 56 base32 characters, so a correct StrKey
never carries ``=`` padding.

The checksum is appended **little-endian** (low byte first). Appending it
big-endian yields a 56-character string that Freighter rejects with a
generic error, which is a miserable thing to debug -- hence the round-trip
assertion in :func:`encode`.
"""

from __future__ import annotations

import base64

from s70.codecs.hashes import crc16_xmodem

VERSION_ED25519_PUBLIC_KEY = 0x30  # 'G'
VERSION_ED25519_SECRET_SEED = 0x90  # 'S'


def _checksum(payload: bytes) -> bytes:
    return crc16_xmodem(payload).to_bytes(2, "little")


def encode(version_byte: int, payload: bytes) -> str:
    """StrKey-encode ``payload`` under ``version_byte``."""
    body = bytes([version_byte]) + payload
    raw = body + _checksum(body)
    text = base64.b32encode(raw).decode("ascii").rstrip("=")

    # Cheap insurance against a silent encoding bug producing a string that
    # looks right but decodes to something else.
    if decode(version_byte, text) != payload:
        raise RuntimeError("StrKey round-trip failed -- refusing to emit a suspect key")
    return text


def decode(version_byte: int, text: str) -> bytes:
    """Decode a StrKey and verify its version byte and checksum."""
    text = text.strip()
    padded = text + "=" * (-len(text) % 8)
    try:
        raw = base64.b32decode(padded.encode("ascii"), casefold=False)
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean ValueError
        raise ValueError(f"not valid base32: {exc}") from exc

    if len(raw) < 3:
        raise ValueError("StrKey is too short")

    body, checksum = raw[:-2], raw[-2:]
    if body[0] != version_byte:
        raise ValueError(
            f"unexpected StrKey version byte 0x{body[0]:02x} (wanted 0x{version_byte:02x})"
        )
    if _checksum(body) != checksum:
        raise ValueError("StrKey checksum mismatch")
    return body[1:]


def encode_ed25519_public_key(public_key: bytes) -> str:
    """32-byte Ed25519 public key -> ``G...`` account id."""
    if len(public_key) != 32:
        raise ValueError(f"Stellar public key must be 32 bytes, got {len(public_key)}")
    return encode(VERSION_ED25519_PUBLIC_KEY, public_key)


def encode_ed25519_secret_seed(seed: bytes) -> str:
    """32-byte Ed25519 seed -> ``S...`` secret key (what Freighter wants)."""
    if len(seed) != 32:
        raise ValueError(f"Stellar secret seed must be 32 bytes, got {len(seed)}")
    return encode(VERSION_ED25519_SECRET_SEED, seed)


def decode_ed25519_public_key(text: str) -> bytes:
    return decode(VERSION_ED25519_PUBLIC_KEY, text)


def decode_ed25519_secret_seed(text: str) -> bytes:
    return decode(VERSION_ED25519_SECRET_SEED, text)
