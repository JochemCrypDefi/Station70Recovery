"""XRP Ledger.

The XRPL import story has a hard structural limit that the UI has to be
honest about.

Every XRPL wallet -- Gem Wallet, Xaman/Xumm, Crossmark -- imports a **family
seed** (``s...`` for secp256k1, ``sEd...`` for Ed25519), a mnemonic, or secret
numbers. All three encode the same **16 bytes of entropy**. The account's
32-byte private key is *derived* from that entropy by a one-way function.

So if the backup stores 16 bytes we can produce an importable family seed. If
it stores a 32-byte derived private key -- which is the more likely case --
then **no XRPL wallet can import it**, and the only routes to the funds are

* sign transactions offline with the raw key (phase 2 of this tool does this,
  because xrpl-py's low-level signing accepts a private key directly), or
* use the key as a regular key via ``SetRegularKey`` on an account you still
  control.

Address derivation works either way, so chain detection and key verification
are unaffected.
"""

from __future__ import annotations

import re

from s70.chains.base import ChainSpec
from s70.codecs import b58
from s70.codecs.hashes import hash160
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, KeyMaterial

_RE = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{23,34}$")

#: base58check version byte for a classic AccountID.
VERSION_ACCOUNT_ID = 0x00

#: XRPL marks an Ed25519 public key with a 0xED prefix byte.
ED25519_PUBLIC_KEY_PREFIX = 0xED


def account_id_to_address(account_id: bytes) -> str:
    """20-byte AccountID -> ``r...`` classic address."""
    if len(account_id) != 20:
        raise ValueError(f"XRPL AccountID must be 20 bytes, got {len(account_id)}")
    return b58.encode_check(bytes([VERSION_ACCOUNT_ID]) + account_id, b58.XRPL)


class XrplChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        address = address.strip()
        if not _RE.match(address):
            return False
        try:
            payload = b58.decode_check(address, b58.XRPL)
        except ValueError:
            return False
        return len(payload) == 21 and payload[0] == VERSION_ACCOUNT_ID

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        if key.curve == CURVE_ED25519:
            public = bytes([ED25519_PUBLIC_KEY_PREFIX]) + key.public_key
        elif key.curve == CURVE_SECP256K1:
            public = key.compressed_public_key
        else:
            return []
        return [account_id_to_address(hash160(public))]


SPEC = XrplChain(
    id="xrpl",
    label="XRPL",
    curves=(CURVE_SECP256K1, CURVE_ED25519),
    # No extension can take this key: they all import a 16-byte family seed,
    # and the seed-to-key derivation is one-way. Offline signing is the route.
    wallet="(offline signing only)",
    address_verifiable=True,
    supports_signing=True,
    import_note=(
        "XRPL wallet extensions import a 16-byte family seed, not the 32-byte private "
        "key this backup holds. No extension can import it -- use the offline signing "
        "flow instead."
    ),
    aliases=("xrp", "ripple"),
)
