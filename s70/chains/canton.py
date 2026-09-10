"""Canton Network.

Canton is the weakest-supported chain here, and the tool says so rather than
implying otherwise.

**Address.** A Canton party id is ``<hint>::<fingerprint>``, where the
fingerprint is a hash of the signing public key computed inside Canton with a
"hash purpose" domain separator and a protobuf serialisation of the key. That
construction is not published in a form I could reproduce and verify offline,
so :attr:`address_verifiable` is False: we compute candidate fingerprints, and
a match is reported as a bonus, but a mismatch proves nothing. Key
verification for Canton therefore rests on ``original_sha256`` and on the
plaintext being a well-formed Ed25519 key.

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

#: DER SubjectPublicKeyInfo header for an Ed25519 public key.
_ED25519_SPKI_HEADER = bytes.fromhex("302a300506032b6570032100")


class CantonChain(ChainSpec):
    def matches_shape(self, address: str) -> bool:
        return bool(_RE.match(address.strip()))

    def hint_of(self, address: str) -> str:
        return address.strip().split("::", 1)[0]

    def fingerprint_of(self, address: str) -> str:
        parts = address.strip().split("::", 1)
        return parts[1] if len(parts) == 2 else ""

    def addresses_for(self, key: KeyMaterial) -> list[str]:
        """Candidate party ids. Speculative -- see the module docstring."""
        if key.curve != CURVE_ED25519:
            return []
        public = key.public_key
        payloads = [
            public,
            _ED25519_SPKI_HEADER + public,
        ]
        # Canton prefixes a 4-byte big-endian "hash purpose" before hashing.
        # The value for a public-key fingerprint is not published; try a small
        # range so a match is at least possible.
        for purpose in range(0, 16):
            payloads.append(purpose.to_bytes(4, "big") + public)

        return [FINGERPRINT_PREFIX + sha256(payload).hex() for payload in payloads]

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


SPEC = CantonChain(
    id="canton",
    label="Canton",
    curves=(CURVE_ED25519,),
    wallet="Console Wallet",
    address_verifiable=False,
    supports_signing=False,
    signing_note=(
        "Transaction building is not offered for Canton. Moving assets requires a "
        "Canton participant node and the counterparty's cooperation; there is no "
        "self-service sweep."
    ),
    import_note=(
        "No confirmed raw-key import path exists for any Canton extension. Console "
        "Wallet documents 'party id + seed phrase' only. Treat the exported encodings "
        "as material for a Canton participant node operator, not as something you can "
        "paste into a browser extension."
    ),
)
