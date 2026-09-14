"""Interpreting decrypted plaintext as a private key.

The backup format stores the wallet private key as opaque bytes -- the
ciphersuite tells you how it was *encrypted*, not how it was *encoded*. In
practice a few shapes turn up, because different chains' key types get
marshalled differently by whatever produced the backup:

=========  =========================================  ==================
length     shape                                      curve
=========  =========================================  ==================
32         raw scalar / Ed25519 seed                  ambiguous
33         the above, with a leading zero pad         ambiguous
48         PKCS#8 Ed25519 (``302e...04220420`` + 32)  ed25519
64         Ed25519 seed || public key (libsodium/Go)  ed25519
varies     DER PKCS#8 / SEC1 EC private key           from the OID
=========  =========================================  ==================

Any of those may also arrive ASCII-armoured as hex or base64.

A bare 32-byte plaintext is genuinely ambiguous: the same bytes are a valid
Ed25519 seed *and* a valid secp256k1 scalar. Rather than guess, we produce a
candidate per curve and let address matching in :mod:`s70.chains` decide.
That makes the address check load-bearing rather than decorative.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from s70.errors import KeyMaterialError
from s70.security import Secret

CURVE_ED25519: Final = "ed25519"
CURVE_SECP256K1: Final = "secp256k1"

#: 16-byte header of a PKCS#8-wrapped Ed25519 private key.
PKCS8_ED25519_HEADER: Final = bytes.fromhex("302e020100300506032b657004220420")

#: secp256k1 group order, for scalar range validation.
SECP256K1_N: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass(frozen=True)
class KeyMaterial:
    """A private key recovered from a backup, plus its derived public half."""

    curve: str
    #: 32-byte Ed25519 seed, or 32-byte secp256k1 private scalar.
    scalar: Secret
    #: Raw 32-byte Ed25519 public key, or uncompressed secp256k1 X||Y (64 bytes).
    public_key: bytes
    #: How the plaintext was interpreted, for display and audit.
    encoding: str
    plaintext_len: int

    @property
    def compressed_public_key(self) -> bytes:
        """33-byte compressed form. secp256k1 only."""
        if self.curve != CURVE_SECP256K1:
            raise KeyMaterialError("compressed public keys apply to secp256k1 only")
        return compress_secp256k1(self.public_key)

    def describe(self) -> str:
        return f"{self.curve}, {self.plaintext_len}-byte plaintext ({self.encoding})"


# --------------------------------------------------------------------------
# public key derivation
# --------------------------------------------------------------------------


def ed25519_public_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise KeyMaterialError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def secp256k1_public_from_scalar(scalar: bytes) -> bytes:
    """Return the uncompressed public key as X||Y (64 bytes, no 0x04 prefix)."""
    if len(scalar) != 32:
        raise KeyMaterialError(f"secp256k1 scalar must be 32 bytes, got {len(scalar)}")
    value = int.from_bytes(scalar, "big")
    if not 0 < value < SECP256K1_N:
        raise KeyMaterialError("secp256k1 scalar is zero or >= group order")
    private = ec.derive_private_key(value, ec.SECP256K1())
    numbers = private.public_key().public_numbers()
    return numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")


def compress_secp256k1(public_key: bytes) -> bytes:
    """X||Y (64 bytes) -> compressed 33-byte SEC1 point."""
    if len(public_key) == 65 and public_key[0] == 0x04:
        public_key = public_key[1:]
    if len(public_key) != 64:
        raise KeyMaterialError(f"expected 64-byte X||Y public key, got {len(public_key)}")
    x, y = public_key[:32], public_key[32:]
    prefix = 0x02 if y[-1] % 2 == 0 else 0x03
    return bytes([prefix]) + x


def _material(curve: str, scalar: bytes, encoding: str, plaintext_len: int) -> KeyMaterial:
    if curve == CURVE_ED25519:
        public = ed25519_public_from_seed(scalar)
    elif curve == CURVE_SECP256K1:
        public = secp256k1_public_from_scalar(scalar)
    else:  # pragma: no cover - guarded by callers
        raise KeyMaterialError(f"unknown curve {curve!r}")
    return KeyMaterial(
        curve=curve,
        scalar=Secret(scalar, "scalar"),
        public_key=public,
        encoding=encoding,
        plaintext_len=plaintext_len,
    )


# --------------------------------------------------------------------------
# plaintext interpretation
# --------------------------------------------------------------------------


def _unwrap_text_armor(plaintext: bytes) -> bytes | None:
    """If the plaintext is an ASCII hex or base64 string, decode it.

    Some backends store the key as text rather than bytes. Detect that rather
    than reporting a bogus 64-byte "Ed25519 seed||pub" for what is actually
    the ASCII of a 32-byte hex string.
    """
    try:
        text = plaintext.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if not text:
        return None

    candidate = text[2:] if text.lower().startswith("0x") else text
    if len(candidate) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in candidate):
        try:
            decoded = bytes.fromhex(candidate)
        except ValueError:
            return None
        if len(decoded) in (16, 32, 48, 64):
            return decoded

    if all(c.isalnum() or c in "+/=_-" for c in text):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(text + "=" * (-len(text) % 4))
            except Exception:  # noqa: BLE001 - just a probe
                continue
            if len(decoded) in (16, 32, 48, 64):
                return decoded
    return None


def _try_der_or_pem(plaintext: bytes) -> KeyMaterial | None:
    """Interpret the plaintext as a serialised private key, if it is one."""
    loaders = (
        serialization.load_der_private_key,
        serialization.load_pem_private_key,
    )
    for loader in loaders:
        try:
            key = loader(plaintext, password=None)
        except Exception:  # noqa: BLE001 - probing formats in turn
            continue

        if isinstance(key, ed25519.Ed25519PrivateKey):
            seed = key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            label = "PKCS#8 Ed25519" if loader is serialization.load_der_private_key else "PEM Ed25519"
            return _material(CURVE_ED25519, seed, label, len(plaintext))

        if isinstance(key, ec.EllipticCurvePrivateKey):
            if not isinstance(key.curve, ec.SECP256K1):
                raise KeyMaterialError(
                    f"decrypted an EC key on curve {key.curve.name!r}; this tool "
                    "supports secp256k1 and Ed25519 only"
                )
            scalar = key.private_numbers().private_value.to_bytes(32, "big")
            label = "DER EC (secp256k1)" if loader is serialization.load_der_private_key else "PEM EC (secp256k1)"
            return _material(CURVE_SECP256K1, scalar, label, len(plaintext))
    return None


def parse_candidates(plaintext: bytes) -> list[KeyMaterial]:
    """Interpret decrypted plaintext, returning one candidate per plausible curve.

    Ordering is not meaningful. Callers should disambiguate by checking the
    derived address against the address recorded in the backup.
    """
    if not plaintext:
        raise KeyMaterialError("decrypted plaintext is empty")

    original_len = len(plaintext)

    # Text-armoured key material.
    unwrapped = _unwrap_text_armor(plaintext)
    if unwrapped is not None and unwrapped != plaintext:
        candidates = parse_candidates(unwrapped)
        return [
            KeyMaterial(
                curve=c.curve,
                scalar=c.scalar,
                public_key=c.public_key,
                encoding=f"ASCII-armoured {c.encoding}",
                plaintext_len=original_len,
            )
            for c in candidates
        ]

    # Structured key formats first -- these are unambiguous about the curve.
    structured = _try_der_or_pem(plaintext)
    if structured is not None:
        return [structured]

    if len(plaintext) == 48 and plaintext.startswith(PKCS8_ED25519_HEADER):
        return [_material(CURVE_ED25519, plaintext[16:48], "PKCS#8 Ed25519", original_len)]

    if len(plaintext) == 64:
        seed, embedded_public = plaintext[:32], plaintext[32:]
        derived = ed25519_public_from_seed(seed)
        if derived != embedded_public:
            raise KeyMaterialError(
                "64-byte plaintext looks like an Ed25519 seed||public key pair, but the "
                "embedded public key does not match the one derived from the seed"
            )
        return [_material(CURVE_ED25519, seed, "Ed25519 seed||public (64 bytes)", original_len)]

    if len(plaintext) == 32:
        # Genuinely ambiguous. Offer both; address matching decides.
        results: list[KeyMaterial] = []
        for curve in (CURVE_ED25519, CURVE_SECP256K1):
            try:
                results.append(_material(curve, plaintext, "raw 32-byte scalar", original_len))
            except KeyMaterialError:
                continue
        if not results:
            raise KeyMaterialError("32-byte plaintext is not a valid key on either curve")
        return results

    if len(plaintext) == 33 and plaintext[0] == 0x00:
        # Leading zero pad, occasionally produced by big-integer serialisation.
        return parse_candidates(plaintext[1:])

    raise KeyMaterialError(
        f"decrypted {original_len} bytes, which does not match any known private-key "
        "encoding (expected 32, 48 or 64 raw bytes, or a DER/PEM private key). "
        "The decryption may have succeeded with the wrong key, or this backup uses "
        "an encoding this tool does not know about."
    )
