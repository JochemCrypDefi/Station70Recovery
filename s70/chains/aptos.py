"""Aptos.

Aptos has had several authentication-key schemes. An address is the account's
authentication key at creation time, so which scheme produced it depends on
when and how the account was made:

* legacy Ed25519 -- ``sha3_256(public_key || 0x00)``
* unified SingleKey -- ``sha3_256(bcs(AnyPublicKey) || 0x02)``

We compute every variant and accept a match on any of them. Extra candidates
cost microseconds and buy robustness against my reading of the BCS layout
being slightly off.

Important caveat: an Aptos account's address equals its authentication key
only if the key has **never been rotated**. After a rotation the address stays
put while the key changes, so a recovered key that fails the address check may
still be the current signing key for that account. The UI says so rather than
declaring the key wrong.
"""

from __future__ import annotations

import re

from s70.chains.base import ChainSpec
from s70.codecs.hashes import sha3_256
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, KeyMaterial

# Full-length addresses, plus the short special addresses (0x1, 0xa, ...) that
# Aptos tooling prints with leading zeros stripped.
#
# The upper bound on the short form is 32 digits rather than 63 on purpose: a
# 40-hex-digit string is an EVM address, and matching it here would make every
# EVM wallet in a backup show up as "EVM/Aptos" before decryption.
_RE = re.compile(r"^0x(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{1,32})$")

SCHEME_ED25519 = 0x00
SCHEME_SINGLE_KEY = 0x02

ANY_PUBLIC_KEY_ED25519 = 0x00
ANY_PUBLIC_KEY_SECP256K1 = 0x01


class AptosChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        return bool(_RE.match(address.strip()))

    def normalize(self, address: str) -> str:
        # Aptos tooling variously prints addresses zero-padded to 64 hex
        # digits or with leading zeros stripped. Both name the same account.
        body = address.strip().lower().removeprefix("0x")
        return "0x" + body.rjust(64, "0")

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        candidates: list[bytes] = []

        if key.curve == CURVE_ED25519:
            public = key.public_key
            # Legacy Ed25519 authentication key.
            candidates.append(sha3_256(public + bytes([SCHEME_ED25519])))
            # Unified SingleKey. BCS encodes the enum variant, then the key as
            # a length-prefixed byte vector (0x20 = 32).
            candidates.append(
                sha3_256(
                    bytes([ANY_PUBLIC_KEY_ED25519, 0x20]) + public + bytes([SCHEME_SINGLE_KEY])
                )
            )
            # Same, without the ULEB128 length prefix.
            candidates.append(
                sha3_256(bytes([ANY_PUBLIC_KEY_ED25519]) + public + bytes([SCHEME_SINGLE_KEY]))
            )

        elif key.curve == CURVE_SECP256K1:
            uncompressed = b"\x04" + key.public_key  # 65-byte SEC1 point
            candidates.append(
                sha3_256(
                    bytes([ANY_PUBLIC_KEY_SECP256K1, 0x41])
                    + uncompressed
                    + bytes([SCHEME_SINGLE_KEY])
                )
            )
            candidates.append(
                sha3_256(
                    bytes([ANY_PUBLIC_KEY_SECP256K1]) + uncompressed + bytes([SCHEME_SINGLE_KEY])
                )
            )

        return ["0x" + digest.hex() for digest in candidates]


SPEC = AptosChain(
    id="aptos",
    label="Aptos",
    curves=(CURVE_ED25519, CURVE_SECP256K1),
    wallet="Petra",
    address_verifiable=True,
    supports_signing=True,
    import_note=(
        "Petra accepts a plain '0x' + 64 hex private key. The AIP-80 prefixed form "
        "('ed25519-priv-0x...') is the standardised Aptos encoding and is offered as "
        "a fallback."
    ),
    aliases=("apt",),
)
