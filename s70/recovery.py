"""Recovery-key loading and share decryption.

Load the RSA recovery key the backup carries, RSA-OAEP-decrypt each share, and
check the plaintext against the ``original_sha256`` recorded beside it.

``ciphersuite`` names the OAEP hash, but it is treated as a hint: the
plausible hash combinations are all tried, starting with the declared one. That
is safe because OAEP decoding is itself an integrity check -- a wrong hash
fails the padding check and raises, so it cannot return plausible-but-wrong
plaintext. ``original_sha256`` then confirms the result independently.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from s70.backup import Share
from s70.errors import DecryptionError, RecoveryKeyError
from s70.security import Secret

class _Attempt(NamedTuple):
    """One OAEP parameter set to try."""

    label: str
    #: Canonical digest name, for comparing against the declared ciphersuite.
    digest_name: str
    algorithm: type[_hashes.HashAlgorithm]
    mgf_algorithm: type[_hashes.HashAlgorithm]


#: OAEP combinations to try, most likely first.
_OAEP_ATTEMPTS: tuple[_Attempt, ...] = (
    _Attempt("OAEP-SHA256", "SHA256", _hashes.SHA256, _hashes.SHA256),
    _Attempt("OAEP-SHA1", "SHA1", _hashes.SHA1, _hashes.SHA1),
    _Attempt("OAEP-SHA384", "SHA384", _hashes.SHA384, _hashes.SHA384),
    _Attempt("OAEP-SHA512", "SHA512", _hashes.SHA512, _hashes.SHA512),
    _Attempt("OAEP-SHA256-MGF1-SHA1", "SHA256", _hashes.SHA256, _hashes.SHA1),
)


def _declared_digest(ciphersuite: str) -> str | None:
    """Extract the digest name from a ciphersuite string, if it names one.

    ``"RSA-4096-OAEP-SHA256"`` -> ``"SHA256"``. Returns None when the string
    does not mention a digest we know, in which case nothing can be called a
    mismatch.
    """
    normalized = ciphersuite.upper().replace("-", "").replace("_", "")
    for name in ("SHA256", "SHA384", "SHA512", "SHA1"):
        if name in normalized:
            return name
    return None


@dataclass(frozen=True)
class DecryptedShare:
    """The result of decrypting one share."""

    plaintext: Secret
    #: True/False when ``original_sha256`` was present, None when it was not.
    integrity_verified: bool | None
    #: Which OAEP variant actually worked.
    scheme_used: str
    #: True when the ciphersuite string did not match what worked.
    scheme_mismatch: bool

    @property
    def scheme_warning(self) -> str:
        """Said out loud when the file's declared ciphersuite was wrong.

        Trying several OAEP digests is safe -- padding is self-validating -- but
        a file whose ``ciphersuite`` does not describe its own ciphertext is a
        file that has been through something, and that is worth one line rather
        than being noticed and dropped.
        """
        if not self.scheme_mismatch:
            return ""
        return (
            f"the backup declares its ciphersuite but decryption only succeeded with "
            f"{self.scheme_used}. The key is intact -- OAEP padding is self-validating, "
            "so a wrong digest cannot return wrong bytes -- but the file's own label is "
            "inaccurate."
        )


# --------------------------------------------------------------------------
# recovery key
# --------------------------------------------------------------------------


def _load_private_key(data: bytes):
    """Load a private key from DER or PEM bytes."""
    errors: list[str] = []
    for loader in (serialization.load_der_private_key, serialization.load_pem_private_key):
        try:
            return loader(data, password=None)
        except Exception as exc:  # noqa: BLE001 - probing both encodings
            errors.append(f"{loader.__name__}: {exc}")
    raise RecoveryKeyError(
        "could not parse the recovery key as a DER or PEM private key.\n  " + "\n  ".join(errors)
    )


def load_recovery_key_from_b64(value: str) -> rsa.RSAPrivateKey:
    """Load the RSA recovery key from the backup's base64 ``recovery_key``.

    The key is always embedded in the backup file and always unencrypted --
    that is what makes the file self-sufficient, and it is why there is no
    separate key file or passphrase to supply.
    """
    text = value.strip()

    # The field is documented as base64 DER, but a PEM block pasted in
    # directly is a common accident and costs nothing to accept.
    if "-----BEGIN" in text:
        data = text.encode("ascii")
    else:
        try:
            data = base64.b64decode("".join(text.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RecoveryKeyError(f"recovery_key is not valid base64: {exc}") from exc

    key = _load_private_key(data)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RecoveryKeyError(
            f"recovery_key parsed as a {type(key).__name__}, but an RSA private key is required"
        )
    return key


def describe_recovery_key(key: rsa.RSAPrivateKey) -> str:
    return f"RSA-{key.key_size}"


def public_key_b64(key: rsa.RSAPrivateKey) -> str:
    """The public half as base64 DER SubjectPublicKeyInfo.

    Exactly the form the backup records in ``encryption.public_key``, so the
    two can be compared as strings.
    """
    return base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")


# --------------------------------------------------------------------------
# share decryption
# --------------------------------------------------------------------------


def _attempts_for(ciphersuite: str) -> list[_Attempt]:
    """Order the OAEP attempts so the declared digest is tried first."""
    declared = _declared_digest(ciphersuite)
    if declared is None:
        return list(_OAEP_ATTEMPTS)
    preferred = [a for a in _OAEP_ATTEMPTS if a.digest_name == declared]
    rest = [a for a in _OAEP_ATTEMPTS if a.digest_name != declared]
    return preferred + rest


def verify_integrity(plaintext: bytes, original_sha256: str | None) -> bool | None:
    """Compare SHA-256 of the plaintext against the recorded digest.

    Returns None when the backup recorded no digest. Accepts the digest in
    base64 (as written by the backup format) or hex.
    """
    if not original_sha256:
        return None

    digest = hashlib.sha256(plaintext).digest()
    expected = original_sha256.strip()

    if len(expected) == 64 and all(c in "0123456789abcdefABCDEF" for c in expected):
        return digest.hex() == expected.lower()

    return base64.b64encode(digest).decode("ascii") == expected


def decrypt_share(private_key: rsa.RSAPrivateKey, share: Share) -> DecryptedShare:
    """RSA-OAEP-decrypt one share and check its integrity."""
    ciphertext_b64 = share.ciphertext_b64
    if not ciphertext_b64:
        raise DecryptionError("share has no 'ciphertext' field")

    try:
        ciphertext = base64.b64decode("".join(ciphertext_b64.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError(f"ciphertext is not valid base64: {exc}") from exc

    expected_size = private_key.key_size // 8
    if len(ciphertext) != expected_size:
        raise DecryptionError(
            f"ciphertext is {len(ciphertext)} bytes but the recovery key is "
            f"RSA-{private_key.key_size}, which produces {expected_size}-byte ciphertexts. "
            "This share was probably encrypted to a different backup key."
        )

    declared = _declared_digest(share.ciphersuite)
    failures: list[str] = []

    for attempt in _attempts_for(share.ciphersuite):
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=attempt.mgf_algorithm()),
                    algorithm=attempt.algorithm(),
                    label=None,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - OAEP failure is expected while probing
            failures.append(f"{attempt.label}: {type(exc).__name__}")
            continue

        return DecryptedShare(
            plaintext=Secret(plaintext, "plaintext"),
            integrity_verified=verify_integrity(plaintext, share.original_sha256),
            scheme_used=attempt.label,
            # Only a mismatch if the backup actually named a digest and it is
            # not the one that worked.
            scheme_mismatch=declared is not None and declared != attempt.digest_name,
        )

    raise DecryptionError(
        "RSA-OAEP decryption failed for every hash combination tried. Either this "
        "share was encrypted to a different backup public key, or the ciphertext is "
        "corrupt.\n  Tried: " + ", ".join(failures)
    )
