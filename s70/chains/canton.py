"""Canton Network.

**Address.** A Canton party id is ``<hint>::<fingerprint>``. The fingerprint is
``multihash(sha256(hash_purpose || public_key))`` -- a 4-byte big-endian domain
separator in front of the raw 32-byte Ed25519 public key, the digest rendered
with the multihash prefix ``1220`` (0x12 = SHA-256, 0x20 = 32 bytes).

The domain separator for a public-key fingerprint is
:data:`HASH_PURPOSE_PUBLIC_KEY_FINGERPRINT` = 12. That value is not published;
it was recovered by matching a real Canton party id in a Station70 backup
against a sweep of candidate purposes, and it is pinned here rather than
re-swept, because a sweep turns "we do not know the construction" into
"something matched" and hides which one.

One observed account is thin evidence for a constant. It is enough to *prove* a
key when it matches -- a SHA-256 pre-image match is not a coincidence -- but it
is not enough to condemn one when it does not. A Canton mismatch is therefore
reported with a caveat saying so; see ``_UNVERIFIED_CAVEATS`` in
:mod:`s70.wallets`.

**Import.** Console Wallet's documented import path is "party id + seed
phrase". It advertises key import/export but publishes no key encoding, and
the extension is closed source. We emit the raw key in the three encodings
Canton tooling actually uses (base64 of the raw 32 bytes, PKCS#8 PEM, and
hex) and state plainly that no confirmed extension import path is known.
"""

from __future__ import annotations

import re

from s70.chains.base import ChainSpec
from s70.codecs.hashes import sha256
from s70.keymaterial import CURVE_ED25519, KeyMaterial

_RE = re.compile(r"^[0-9a-zA-Z_\-]{1,64}::[0-9a-fA-F]{4,132}$")

#: Canton renders fingerprints with a multihash-style prefix: 0x12 = SHA-256,
#: 0x20 = 32 bytes of digest.
FINGERPRINT_PREFIX = "1220"

#: The 4-byte big-endian domain separator Canton hashes in front of a public
#: key to make its fingerprint. See the module docstring for where 12 comes
#: from and how far it can be trusted.
HASH_PURPOSE_PUBLIC_KEY_FINGERPRINT = 12


class CantonChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        return bool(_RE.match(address.strip()))

    def fingerprint_of(self, address: str) -> str:
        parts = address.strip().split("::", 1)
        return parts[1] if len(parts) == 2 else ""

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        """The fingerprint half of the party id this key would produce."""
        if key.curve != CURVE_ED25519:
            return []
        payload = (
            HASH_PURPOSE_PUBLIC_KEY_FINGERPRINT.to_bytes(4, "big") + key.public_key
        )
        return [FINGERPRINT_PREFIX + sha256(payload).hex()]

    def matches_key(self, address: str, key: KeyMaterial) -> tuple[bool, str | None]:
        """Compare only the fingerprint half, ignoring the party hint."""
        if key.curve not in self.curves:
            return False, None
        target = self.fingerprint_of(address).lower()
        if not target:
            return False, None
        candidates = self.addresses_for(key)
        for candidate in candidates:
            if candidate.lower() == target:
                return True, candidate
        return False, candidates[0] if candidates else None


SPEC = CantonChain(id="canton", label="Canton", curves=(CURVE_ED25519,))
