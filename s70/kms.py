"""Wrapping a recovered key as AWS KMS importable key material.

Produces the single binary ``EncryptedKeyMaterial.bin`` that
``aws kms import-key-material`` accepts for a KMS key created with
``Origin=EXTERNAL``. Once the key is in KMS, signing with it happens there.

**Nothing here touches the network.** ``boto3`` is not imported and is not a
dependency. The user carries the wrapping public key and import token in from
an online machine, and carries the wrapped blob back out.

Two things in this file are easy to get subtly wrong, and both fail as an
opaque ``InvalidCiphertextException`` from AWS hours later rather than as an
error here:

**The AES key goes first.** For the ``RSA_AES_KEY_WRAP_*`` algorithms the blob
is ``RSA-OAEP(aes_key) || AES-KWP(key_material)``. The RSA block is always
exactly ``key_size / 8`` bytes, which is how KMS finds the split. Reverse the
two halves and the padding check fails with no hint as to why.

**AES-KWP is RFC 5649, not RFC 3394.** It is ``aes_key_wrap_with_padding``,
which prepends the ``A65959A6`` alternative IV and pads to a multiple of 8.
The unpadded RFC 3394 variant happens to accept the 48-byte Ed25519 key -- 48
is already a multiple of 8 -- and then rejects the 135-byte secp256k1 key. A
test that only covers Ed25519 would not catch it, so
``tests/test_kms.py`` pins the AIV directly.

Byte layout, for an RSA-4096 wrapping key::

    RSA_AES_KEY_WRAP_SHA_256, Ed25519    512 + 56  = 568 bytes
    RSA_AES_KEY_WRAP_SHA_256, secp256k1  512 + 144 = 656 bytes
    RSAES_OAEP_SHA_256, either                 512 bytes

The plaintext KMS wants is the private key alone as *unencrypted* PKCS#8 DER --
``openssl pkcs8 -topk8 -outform der -nocrypt``. KMS derives the public half
itself, which is what makes the verification step in :func:`build_guide` worth
running: the public key this tool derived from the private key must equal the
one KMS reports afterwards, or the material landed on the wrong key.

Nothing here writes that PKCS#8 DER to disk, and nothing should be added that
does: it is the key in plaintext, and the only thing this module is meant to
emit is ciphertext.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import textwrap
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from s70 import security
from s70.errors import (
    KmsKeySpecError,
    KmsParametersError,
    KmsWrapError,
    S70Error,
)
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, KeyMaterial
from s70.security import Secret

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

WRAP_RSA_AES_SHA256: Final = "RSA_AES_KEY_WRAP_SHA_256"
WRAP_RSA_AES_SHA1: Final = "RSA_AES_KEY_WRAP_SHA_1"
WRAP_OAEP_SHA256: Final = "RSAES_OAEP_SHA_256"
WRAP_OAEP_SHA1: Final = "RSAES_OAEP_SHA_1"

#: Permitted for elliptic-curve key material, in AWS's own preference order.
#: The first entry is the default.
WRAPPING_ALGORITHMS: Final = (
    WRAP_RSA_AES_SHA256,
    WRAP_RSA_AES_SHA1,
    WRAP_OAEP_SHA256,
    WRAP_OAEP_SHA1,
)
DEFAULT_WRAPPING_ALGORITHM: Final = WRAP_RSA_AES_SHA256

_TWO_STEP: Final = frozenset({WRAP_RSA_AES_SHA256, WRAP_RSA_AES_SHA1})

_OAEP_HASHES: Final = {
    WRAP_RSA_AES_SHA256: hashes.SHA256,
    WRAP_RSA_AES_SHA1: hashes.SHA1,
    WRAP_OAEP_SHA256: hashes.SHA256,
    WRAP_OAEP_SHA1: hashes.SHA1,
}

#: KMS generates wrapping keys at these sizes only.
RSA_KEY_SIZES: Final = (2048, 3072, 4096)
AES_KEY_BYTES: Final = 32

#: KMS gives a wrapping public key and import token 24 hours together.
MAX_PARAMETER_AGE: Final = timedelta(hours=24)

KEYSPEC_SECP256K1: Final = "ECC_SECG_P256K1"
KEYSPEC_ED25519: Final = "ECC_NIST_EDWARDS25519"

CONSOLE_PUBLIC_KEY_NAME: Final = "WrappingPublicKey.bin"
CONSOLE_TOKEN_NAME: Final = "ImportToken.bin"
CONSOLE_README_NAME: Final = "README.txt"

#: Cap on any single member read out of a console zip, against a zip bomb. A
#: real wrapping key is 550 bytes and a real import token a few kilobytes.
_MAX_MEMBER_BYTES: Final = 1 << 20


# --------------------------------------------------------------------------
# curve -> key spec
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SigningAlgorithm:
    """One ``aws kms sign --signing-algorithm`` value and its message type.

    The pairing is not free choice: KMS rejects ``ED25519_SHA_512`` with
    ``MessageType:DIGEST`` and ``ED25519_PH_SHA_512`` with ``MessageType:RAW``.
    """

    name: str
    message_type: str
    note: str = ""


@dataclass(frozen=True)
class KeySpecProfile:
    """Everything KMS-shaped that follows from the recovered key's curve."""

    key_spec: str
    curve: str
    #: Both curves here are signing-only in KMS; neither can encrypt.
    key_usage: str = "SIGN_VERIFY"
    signing_algorithms: tuple[SigningAlgorithm, ...] = ()
    #: Caveats about creating the key -- shown on the `create-key` step.
    create_notes: tuple[str, ...] = ()
    #: Caveats about using it afterwards -- shown on the `sign` step.
    signing_notes: tuple[str, ...] = ()


_ECDSA_LOW_S_NOTE: Final = (
    "KMS returns a DER-encoded ECDSA signature with no recovery id, and does not "
    "guarantee low-S. Chains that require a compact 64-byte signature (EVM, "
    "Bitcoin, XRPL secp256k1) need you to parse the DER, normalise S into the "
    "lower half of the curve order, and recover v by trying both values. Signing "
    "libraries do this for you; a raw `aws kms sign` call does not."
)

PROFILES: Final[dict[str, KeySpecProfile]] = {
    KEYSPEC_SECP256K1: KeySpecProfile(
        key_spec=KEYSPEC_SECP256K1,
        curve=CURVE_SECP256K1,
        signing_algorithms=(
            SigningAlgorithm(
                "ECDSA_SHA_256",
                "DIGEST",
                "Pass a 32-byte SHA-256 digest. Use this for a transaction hash "
                "you have already computed.",
            ),
            SigningAlgorithm(
                "ECDSA_SHA_256",
                "RAW",
                "Pass the message itself, up to 4 KB, and let KMS hash it.",
            ),
        ),
        signing_notes=(_ECDSA_LOW_S_NOTE,),
    ),
    KEYSPEC_ED25519: KeySpecProfile(
        key_spec=KEYSPEC_ED25519,
        curve=CURVE_ED25519,
        signing_algorithms=(
            SigningAlgorithm(
                "ED25519_SHA_512",
                "RAW",
                "This is PureEdDSA -- the signature Solana, Stellar, Aptos and Sui "
                "verify. This is the one you want. Messages are limited to 4 KB, "
                "which every transaction on those chains is comfortably under.",
            ),
            SigningAlgorithm(
                "ED25519_PH_SHA_512",
                "DIGEST",
                "HashEdDSA. KMS re-hashes what you send, so the message is hashed "
                "twice. No chain above accepts this -- do not use it unless you "
                "specifically know you want prehashed EdDSA.",
            ),
        ),
        create_notes=(
            "Ed25519 KMS keys are a recent addition. If `create-key` rejects "
            f"--key-spec {KEYSPEC_ED25519}, the region does not offer them yet; the "
            "blob this tool writes stays valid for whenever it does.",
        ),
    ),
}

_BY_CURVE: Final = {profile.curve: profile for profile in PROFILES.values()}


def profile_for_curve(curve: str) -> KeySpecProfile:
    """The one KMS key spec a key on this curve can be imported as."""
    profile = _BY_CURVE.get(curve)
    if profile is None:
        raise KmsKeySpecError(
            f"no KMS key spec covers the curve {curve!r}. KMS imports secp256k1 as "
            f"{KEYSPEC_SECP256K1} and Ed25519 as {KEYSPEC_ED25519}, and this backup "
            "format holds no other curve."
        )
    return profile


def profile_for_key_spec(key_spec: str) -> KeySpecProfile:
    """Resolve a user-supplied key spec, case-insensitively."""
    profile = PROFILES.get(key_spec.strip().upper())
    if profile is None:
        raise KmsKeySpecError(
            f"{key_spec!r} is not a KMS key spec this tool can produce material for. "
            f"Use {KEYSPEC_SECP256K1} (secp256k1) or {KEYSPEC_ED25519} (Ed25519), or "
            "omit the option and let the key's curve decide."
        )
    return profile


def resolve_key_spec(key: KeyMaterial, requested: str | None = None) -> KeySpecProfile:
    """Pick the key spec, refusing a request that contradicts the key's curve.

    A secp256k1 scalar is also a valid Ed25519 seed, so wrapping one as the
    other succeeds and produces a KMS key controlling a *different* account.
    That is precisely the class of silent wrong answer the rest of this tool
    exists to prevent, so a contradiction is an error, not a preference.
    """
    from_curve = profile_for_curve(key.curve)
    if requested is None:
        return from_curve

    asked = profile_for_key_spec(requested)
    if asked.key_spec != from_curve.key_spec:
        raise KmsKeySpecError(
            f"this key is on {key.curve}, which imports as {from_curve.key_spec}, but "
            f"--key-spec asked for {asked.key_spec} ({asked.curve}). Those are "
            "different accounts: the same 32 bytes are a valid key on both curves and "
            "derive unrelated addresses. Drop --key-spec and let the curve decide."
        )
    return from_curve


# --------------------------------------------------------------------------
# import parameters
# --------------------------------------------------------------------------


def _parse_aws_timestamp(value: object) -> datetime | None:
    """Parse a ``ParametersValidTo`` in any of the shapes AWS emits.

    The CLI renders it as a float epoch by default and as an ISO-8601 string
    with a trailing ``Z`` under some output settings. ``fromisoformat`` only
    learned to accept that ``Z`` in Python 3.11, and this package supports
    3.10, so normalise it rather than relying on the interpreter version -- a
    dev machine on 3.13 would never see the failure.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


_ARN_RE: Final = re.compile(r"^arn:aws[\w-]*:kms:([a-z0-9-]+):", re.IGNORECASE)


def _region_from_key_id(key_id: str | None) -> str | None:
    if not key_id:
        return None
    match = _ARN_RE.match(key_id.strip())
    return match.group(1) if match else None


@dataclass(frozen=True)
class ImportParameters:
    """The wrapping public key and import token, from whichever form we got.

    Everything on this object is public: it is safe to print, and safe to carry
    on the same USB stick as the wrapped blob. The import token is opaque bytes
    that this tool never interprets, only copies.
    """

    wrapping_public_key: rsa.RSAPublicKey
    wrapping_algorithm: str
    #: ``None`` only when the user pointed at a bare public key with no token
    #: alongside it. The guide then tells them to supply it at import time.
    import_token: bytes | None
    key_id: str | None
    region: str | None
    parameters_valid_to: datetime | None
    #: Best effort: the README's stated date, or the file's mtime.
    created_at: datetime | None
    #: Human label for where this came from, shown in the CLI summary.
    source: str
    source_path: Path | None
    #: The exact token file the generated import command should reference.
    import_token_path: Path | None
    #: "README.txt", "--wrapping-algorithm", or "default (assumed)".
    algorithm_source: str
    notes: tuple[str, ...] = ()

    @property
    def rsa_key_size(self) -> int:
        return self.wrapping_public_key.key_size

    def __repr__(self) -> str:
        return (
            f"<ImportParameters {self.source} RSA-{self.rsa_key_size} "
            f"{self.wrapping_algorithm} token={len(self.import_token or b'')}B>"
        )


def _load_wrapping_public_key(data: bytes) -> rsa.RSAPublicKey:
    """DER-then-PEM SubjectPublicKeyInfo, which must be RSA at a KMS size."""
    key = None
    for loader in (serialization.load_der_public_key, serialization.load_pem_public_key):
        try:
            key = loader(data)
            break
        except Exception:  # noqa: BLE001 - probing the two encodings in turn
            continue
    if key is None:
        raise KmsParametersError(
            "the wrapping public key is not a readable DER or PEM public key. "
            "`get-parameters-for-import` returns it base64-encoded; the console "
            f"ships it as raw DER in {CONSOLE_PUBLIC_KEY_NAME}."
        )

    if not isinstance(key, rsa.RSAPublicKey):
        kind = type(key).__name__.replace("PublicKey", "")
        raise KmsParametersError(
            f"the wrapping key is a {kind} public key, but KMS wrapping keys are RSA "
            f"({', '.join('RSA_%d' % size for size in RSA_KEY_SIZES)}). This looks "
            "like the wrong file -- check you did not pass a chain public key."
        )
    if key.key_size not in RSA_KEY_SIZES:
        raise KmsParametersError(
            f"the wrapping key is RSA-{key.key_size}, which KMS does not issue. "
            f"Expected one of {', '.join(str(size) for size in RSA_KEY_SIZES)}."
        )
    return key


_ALGORITHM_RE: Final = re.compile(
    r"\b(RSA_AES_KEY_WRAP_SHA_256|RSA_AES_KEY_WRAP_SHA_1|"
    r"RSAES_OAEP_SHA_256|RSAES_OAEP_SHA_1|RSAES_PKCS1_V1_5)\b"
)


def parse_wrapping_algorithm(readme_text: str) -> str | None:
    """The single algorithm the console README names, or ``None`` if it names none.

    Raises if the text names more than one. Guessing which of them the user
    actually chose when they downloaded the parameters is exactly the mistake
    that produces a blob KMS rejects a day later.
    """
    found = []
    for name in _ALGORITHM_RE.findall(readme_text or ""):
        if name not in found:
            found.append(name)

    if not found:
        return None
    if len(found) > 1:
        raise KmsParametersError(
            f"{CONSOLE_README_NAME} names more than one wrapping algorithm "
            f"({', '.join(found)}), so it cannot say which one these parameters were "
            "downloaded with. Pass --wrapping-algorithm explicitly."
        )

    only = found[0]
    if only == "RSAES_PKCS1_V1_5":
        raise KmsParametersError(
            "these parameters name the RSAES_PKCS1_V1_5 wrapping algorithm, which AWS "
            "withdrew in October 2023. Download a fresh set with "
            f"--wrapping-algorithm {DEFAULT_WRAPPING_ALGORITHM}."
        )
    return only


def _validate_algorithm(name: str) -> str:
    upper = name.strip().upper()
    if upper not in _OAEP_HASHES:
        raise KmsParametersError(
            f"{name!r} is not a wrapping algorithm KMS accepts for elliptic-curve key "
            f"material. Choose one of: {', '.join(WRAPPING_ALGORITHMS)}."
        )
    return upper


def _read_capped(handle, name: str) -> bytes:
    data = handle.read(_MAX_MEMBER_BYTES + 1)
    if len(data) > _MAX_MEMBER_BYTES:
        raise KmsParametersError(
            f"{name} is larger than {_MAX_MEMBER_BYTES} bytes, which no real KMS "
            "import parameter file is. Refusing to read it."
        )
    return data


def _bundle_from_zip(path: Path) -> dict[str, tuple[bytes, Path | None]]:
    """Read the three known basenames out of a console zip.

    Members are read by name via :meth:`ZipFile.read`; nothing is extracted, so
    a crafted path in the archive cannot write outside a directory.
    """
    wanted = {
        CONSOLE_PUBLIC_KEY_NAME.lower(): CONSOLE_PUBLIC_KEY_NAME,
        CONSOLE_TOKEN_NAME.lower(): CONSOLE_TOKEN_NAME,
        CONSOLE_README_NAME.lower(): CONSOLE_README_NAME,
    }
    found: dict[str, tuple[bytes, str]] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                key = wanted.get(Path(info.filename).name.lower())
                if key is None:
                    continue
                if key in found:
                    raise KmsParametersError(
                        f"{path} contains more than one {key}. The wrapping public key "
                        "and import token are an indivisible pair, and picking one of "
                        "two would silently mismatch them -- unzip the bundle you mean "
                        "and point at that directory."
                    )
                if info.file_size > _MAX_MEMBER_BYTES:
                    raise KmsParametersError(
                        f"{key} in {path} claims to be {info.file_size} bytes, which no "
                        "real KMS import parameter file is. Refusing to read it."
                    )
                with archive.open(info) as member:
                    # No path: a member inside a zip is not something the
                    # generated `fileb://` command could point at.
                    found[key] = (_read_capped(member, key), None)
    except zipfile.BadZipFile as exc:
        raise KmsParametersError(f"{path} is not a readable zip: {exc}") from exc
    return found


def _bundle_from_dir(path: Path) -> dict[str, tuple[bytes, Path | None]]:
    """Find the three known basenames at depth <= 2 under a directory.

    Unzipping a console download usually nests an ``Import_Parameters_.../``
    folder, so pointing at the directory you unzipped into has to work too.
    """
    wanted = {
        CONSOLE_PUBLIC_KEY_NAME.lower(): CONSOLE_PUBLIC_KEY_NAME,
        CONSOLE_TOKEN_NAME.lower(): CONSOLE_TOKEN_NAME,
        CONSOLE_README_NAME.lower(): CONSOLE_README_NAME,
    }
    found: dict[str, tuple[bytes, Path]] = {}
    candidates: list[Path] = []
    try:
        candidates += sorted(p for p in path.iterdir() if p.is_file())
        for child in sorted(p for p in path.iterdir() if p.is_dir()):
            candidates += sorted(p for p in child.iterdir() if p.is_file())
    except OSError as exc:
        raise KmsParametersError(f"could not read {path}: {exc}") from exc

    for candidate in candidates:
        key = wanted.get(candidate.name.lower())
        if key is None:
            continue
        if key in found:
            raise KmsParametersError(
                f"found more than one {key} under {path}. The wrapping public key and "
                "import token are an indivisible pair, and mixing two downloads "
                "produces a blob KMS rejects -- point at a single bundle directory."
            )
        try:
            with candidate.open("rb") as handle:
                found[key] = (_read_capped(handle, candidate.name), candidate)
        except OSError as exc:
            raise KmsParametersError(f"could not read {candidate}: {exc}") from exc
    return found


def _mtime(path: Path | None) -> datetime | None:
    if path is None:
        return None
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def _resolve_algorithm(
    from_readme: str | None, requested: str | None
) -> tuple[str, str, tuple[str, ...]]:
    """Settle the wrapping algorithm, returning ``(name, source, notes)``.

    Precedence is deliberate and lives here alone so it can be audited in one
    place: an explicit request beats nothing, a README beats the default, and a
    request that *disagrees* with a README is an error rather than a winner --
    one of the two is a mistake, and silently honouring either loses the user a
    24-hour token.
    """
    if from_readme and requested:
        if from_readme != requested:
            raise KmsParametersError(
                f"--wrapping-algorithm says {requested}, but {CONSOLE_README_NAME} in "
                f"this bundle says these parameters were downloaded with {from_readme}. "
                "The wrapping algorithm has to match what `get-parameters-for-import` "
                "was called with. Drop the option to use the bundle's own value."
            )
        return from_readme, CONSOLE_README_NAME, ()

    if from_readme:
        return from_readme, CONSOLE_README_NAME, ()
    if requested:
        return requested, "--wrapping-algorithm", ()

    return (
        DEFAULT_WRAPPING_ALGORITHM,
        "default (assumed)",
        (
            f"No wrapping algorithm was given, so {DEFAULT_WRAPPING_ALGORITHM} was "
            "assumed. `get-parameters-for-import` does not echo the algorithm back, so "
            "this cannot be checked offline -- it MUST match what you passed to that "
            "call, or the import fails. Pass --wrapping-algorithm to be sure.",
        ),
    )


def _from_console_bundle(
    found: dict[str, tuple[bytes, Path | None]],
    path: Path,
    requested: str | None,
    *,
    from_zip: bool,
) -> ImportParameters:
    """Build parameters from an AWS console import-parameters download.

    Shared by the directory and zip forms, which differ only in whether the
    import token is a path the generated command can reference.
    """
    if CONSOLE_PUBLIC_KEY_NAME not in found:
        where = (
            f"a zip with no {CONSOLE_PUBLIC_KEY_NAME} in it"
            if from_zip
            else (
                f"a directory with no {CONSOLE_PUBLIC_KEY_NAME} in it, or in any "
                "immediate subdirectory"
            )
        )
        raise KmsParametersError(
            f"{path} is {where}. Point at the AWS console's import-parameters "
            "download, or at the JSON from `aws kms get-parameters-for-import`."
        )

    key_bytes, key_path = found[CONSOLE_PUBLIC_KEY_NAME]
    token_bytes, token_path = found.get(CONSOLE_TOKEN_NAME, (None, None))
    readme_text = ""
    if CONSOLE_README_NAME in found:
        readme_text = found[CONSOLE_README_NAME][0].decode("utf-8", "replace")

    algorithm, algorithm_source, notes = _resolve_algorithm(
        parse_wrapping_algorithm(readme_text), requested
    )
    if token_bytes is None:
        notes += (
            f"No {CONSOLE_TOKEN_NAME} was found alongside the wrapping key. The "
            "import needs it, and it must come from this same download.",
        )
    elif from_zip:
        notes += (
            "The import token is inside the zip. Unzip it so "
            f"`--import-token fileb://{CONSOLE_TOKEN_NAME}` can reach it.",
        )

    return ImportParameters(
        wrapping_public_key=_load_wrapping_public_key(key_bytes),
        wrapping_algorithm=algorithm,
        import_token=token_bytes,
        key_id=None,
        region=None,
        parameters_valid_to=None,
        # A zip's members share its mtime; a directory's key file has its own.
        created_at=_mtime(path if from_zip else key_path),
        source=f"console download ({'zip' if from_zip else 'directory'})",
        source_path=path,
        # Only the unzipped form gives a path the import command can name.
        import_token_path=None if from_zip else token_path,
        algorithm_source=algorithm_source,
        notes=notes,
    )


def load_import_parameters(
    path: str | Path,
    *,
    wrapping_algorithm: str | None = None,
) -> ImportParameters:
    """Load KMS import parameters, auto-detecting the form they arrived in.

    Four shapes are accepted, in this order: a console bundle directory, a
    console bundle zip, the JSON that ``aws kms get-parameters-for-import``
    prints, and a bare DER/PEM wrapping public key.

    ``wrapping_algorithm`` is the *explicitly requested* one or ``None``; the
    default is applied inside :func:`_resolve_algorithm` rather than by the
    caller, so that a bundle's ``README.txt`` can win over the default without
    being pre-empted by it.
    """
    path = Path(path).expanduser()
    requested = _validate_algorithm(wrapping_algorithm) if wrapping_algorithm else None

    if not path.exists():
        raise KmsParametersError(f"no such path: {path}")

    # 1 and 2. the console download, as a directory or as the zip itself
    if path.is_dir():
        return _from_console_bundle(
            _bundle_from_dir(path), path, requested, from_zip=False
        )
    if zipfile.is_zipfile(path):
        return _from_console_bundle(
            _bundle_from_zip(path), path, requested, from_zip=True
        )

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise KmsParametersError(f"could not read {path}: {exc}") from exc
    if len(raw) > _MAX_MEMBER_BYTES:
        raise KmsParametersError(
            f"{path} is larger than {_MAX_MEMBER_BYTES} bytes, which no KMS import "
            "parameter file is."
        )

    # 3. get-parameters-for-import JSON
    if raw.lstrip()[:1] == b"{":
        return _from_json(raw, path, requested)

    # 4. bare wrapping public key
    public_key = _load_wrapping_public_key(raw)
    algorithm, algorithm_source, notes = _resolve_algorithm(None, requested)
    notes += (
        "This is a bare wrapping public key with no import token beside it. The "
        "import needs the ImportToken from the same download -- supply it yourself.",
    )
    return ImportParameters(
        wrapping_public_key=public_key,
        wrapping_algorithm=algorithm,
        import_token=None,
        key_id=None,
        region=None,
        parameters_valid_to=None,
        created_at=_mtime(path),
        source="bare wrapping public key",
        source_path=path,
        import_token_path=None,
        algorithm_source=algorithm_source,
        notes=notes,
    )


def _b64(value: object, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise KmsParametersError(
            f"the JSON has no usable {field_name!r}. Save the whole output of "
            "`aws kms get-parameters-for-import` without editing it."
        )
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KmsParametersError(
            f"{field_name!r} in the JSON is not valid base64: {exc}"
        ) from exc


def _from_json(raw: bytes, path: Path, requested: str | None) -> ImportParameters:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KmsParametersError(f"{path} is not readable JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise KmsParametersError(
            f"{path} holds a JSON {type(document).__name__}, not the object "
            "`aws kms get-parameters-for-import` prints."
        )

    public_key = _load_wrapping_public_key(_b64(document.get("PublicKey"), "PublicKey"))
    token = _b64(document.get("ImportToken"), "ImportToken")
    key_id = document.get("KeyId") if isinstance(document.get("KeyId"), str) else None
    valid_to = _parse_aws_timestamp(document.get("ParametersValidTo"))

    algorithm, algorithm_source, notes = _resolve_algorithm(None, requested)
    return ImportParameters(
        wrapping_public_key=public_key,
        wrapping_algorithm=algorithm,
        import_token=token,
        key_id=key_id,
        region=_region_from_key_id(key_id),
        parameters_valid_to=valid_to,
        # ParametersValidTo is issue time + 24h, so it dates the download.
        created_at=(valid_to - MAX_PARAMETER_AGE) if valid_to else _mtime(path),
        source="get-parameters-for-import JSON",
        source_path=path,
        import_token_path=None,
        algorithm_source=algorithm_source,
        notes=notes,
    )


def check_import_token_destination(path: str | Path, params: ImportParameters) -> None:
    """Fail now if :func:`write_import_token` would fail later.

    Called before the key is wrapped. The alternative is discovering the
    collision after the blob is on disk, which leaves the user to clean up two
    files and re-run, having burned part of a 24-hour token on it.
    """
    if params.import_token is None:
        return
    path = Path(path).expanduser()
    if path.exists() and path.read_bytes() != params.import_token:
        raise KmsParametersError(
            f"{path} already exists and holds a different import token. It is almost "
            "certainly from an earlier download, and pairing it with this wrapping key "
            "produces a blob KMS rejects. Move it aside and run this again."
        )


def write_import_token(path: str | Path, params: ImportParameters) -> Path:
    """Decode the base64 import token into the raw file ``fileb://`` needs.

    Written next to the wrapped blob on every run, because the
    ``import-key-material`` command needs it and telling the user to produce it
    themselves with ``base64 -d`` -- on the online machine, where they may not
    have the JSON -- is a step that reliably fails.

    Not secret: the token is public, and pairing it with the blob is what the
    import is. Same owner-only discipline as everything else this tool writes;
    re-writing the identical token is a no-op rather than an error, so a
    re-run after a failed wrap does not need cleaning up first.
    """
    if params.import_token is None:
        raise KmsParametersError(
            "these import parameters carry no import token, so there is nothing to "
            "write. Supply the ImportToken from the same download you took the "
            "wrapping public key from."
        )
    path = Path(path).expanduser()
    if path.exists() and path.read_bytes() == params.import_token:
        return path
    return _write_exclusive(path, params.import_token)


# --------------------------------------------------------------------------
# freshness
# --------------------------------------------------------------------------


def age_warnings(
    params: ImportParameters, *, now: datetime | None = None
) -> list[str]:
    """Warnings about how old the import parameters look. Never blocks.

    The machine running this is offline, and an offline machine's clock is
    routinely wrong -- sometimes by years, if its battery is flat. An
    apparently-expired parameter set is therefore at least as likely to be a
    bad clock as a stale USB stick, so this reports and carries on. AWS will
    reject a genuinely expired token at import time, which costs one re-run of
    ``get-parameters-for-import`` and nothing else.
    """
    now = now or datetime.now(timezone.utc)
    warnings: list[str] = []

    clock_is_wrong = params.created_at is not None and now < params.created_at

    if params.parameters_valid_to is not None and now > params.parameters_valid_to:
        hours = (now - params.parameters_valid_to).total_seconds() / 3600
        warnings.append(
            f"these import parameters expired about {hours:.0f}h ago according to this "
            "machine's clock."
        )
    elif params.created_at is not None and not clock_is_wrong:
        age = now - params.created_at
        if age > MAX_PARAMETER_AGE:
            hours = age.total_seconds() / 3600
            warnings.append(
                f"these import parameters look about {hours:.0f}h old, and KMS only "
                "gives them 24h."
            )

    if clock_is_wrong:
        warnings.append(
            "this machine's clock reads earlier than these parameters were created, so "
            "the clock is wrong -- treat any age warning here as unreliable."
        )

    if warnings:
        warnings.append(
            "The blob will still be written, and it will still be correct. If "
            "`import-key-material` fails with an expired-token error, re-run "
            "`get-parameters-for-import`, bring the new bundle across and run this "
            "again. Nothing is lost by trying."
        )
    return warnings


# --------------------------------------------------------------------------
# the wrap
# --------------------------------------------------------------------------


def pkcs8_der(key: KeyMaterial, profile: KeySpecProfile | None = None) -> Secret:
    """The plaintext KMS wants: the private key alone, unencrypted PKCS#8 DER.

    Equivalent to ``openssl pkcs8 -topk8 -outform der -nocrypt``. 48 bytes for
    Ed25519, 135 for secp256k1 (whose inner SEC1 structure carries the optional
    public key, as openssl's output does).

    The public key rebuilt here is compared against
    :attr:`KeyMaterial.public_key` before returning. That is not paranoia about
    ``cryptography``: it is a guard against a mislabelled curve producing a
    perfectly valid blob for an account nobody controls.
    """
    profile = profile or profile_for_curve(key.curve)
    scalar = key.scalar.reveal()

    if profile.curve == CURVE_ED25519:
        private = ed25519.Ed25519PrivateKey.from_private_bytes(scalar)
        derived = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    elif profile.curve == CURVE_SECP256K1:
        private = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256K1())
        numbers = private.public_key().public_numbers()
        derived = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    else:  # pragma: no cover - profile_for_curve already rejected anything else
        raise KmsKeySpecError(f"cannot serialise a {profile.curve} key for KMS")

    if derived != key.public_key:
        raise KmsKeySpecError(
            "the public key rebuilt from this private key does not match the one "
            "recovered alongside it, so the curve is mislabelled. Wrapping it would "
            "create a KMS key for a different account. Re-run `s70 verify` on this "
            "backup and do not import this key."
        )

    return Secret(
        private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "pkcs8",
    )


def max_oaep_plaintext(rsa_key_size_bits: int, hash_len: int) -> int:
    """Largest plaintext a single RSA-OAEP block can hold, in bytes.

    ``keysize/8 - 2*hashlen - 2``. RSA-2048 with SHA-256 gives 190.
    """
    return rsa_key_size_bits // 8 - 2 * hash_len - 2


def _oaep(algorithm: str) -> padding.OAEP:
    """OAEP as KMS specifies it: one hash for both digest and MGF1, empty label."""
    digest = _OAEP_HASHES[algorithm]()
    return padding.OAEP(mgf=padding.MGF1(algorithm=digest), algorithm=digest, label=None)


def wrap_plaintext(
    plaintext: bytes,
    public_key: rsa.RSAPublicKey,
    algorithm: str,
    *,
    aes_key: bytes | None = None,
) -> bytes:
    """Wrap raw bytes for KMS import.

    Split out from :func:`wrap_key_material` so the byte layout can be tested
    directly against a locally generated RSA key, with no ``KeyMaterial`` and no
    AWS. ``aes_key`` exists for that test and should be left alone otherwise.
    """
    algorithm = _validate_algorithm(algorithm)

    if algorithm not in _TWO_STEP:
        limit = max_oaep_plaintext(
            public_key.key_size, _OAEP_HASHES[algorithm].digest_size
        )
        if len(plaintext) > limit:
            raise KmsWrapError(
                f"{algorithm} with an RSA-{public_key.key_size} wrapping key can "
                f"encrypt at most {limit} bytes, and this key's PKCS#8 DER is "
                f"{len(plaintext)}. Use --wrapping-algorithm "
                f"{WRAP_RSA_AES_SHA256} instead (it has no size limit), or ask for a "
                "larger --wrapping-key-spec when you fetch the import parameters."
            )
        try:
            return public_key.encrypt(plaintext, _oaep(algorithm))
        except Exception as exc:  # noqa: BLE001 - surfaced as a clean error
            raise KmsWrapError(f"RSA-OAEP encryption failed: {exc}") from exc

    # Two-step RSA_AES_KEY_WRAP_*:
    #   1. a fresh 32-byte AES key, used once and thrown away
    #   2. AES-KWP (RFC 5649) over the key material
    #   3. RSA-OAEP over the AES key
    #   4. aes_wrapped || material_wrapped  -- AES KEY FIRST. See the module
    #      docstring; reversing these is the failure that costs a day.
    ephemeral = bytearray(aes_key if aes_key is not None else os.urandom(AES_KEY_BYTES))
    if len(ephemeral) != AES_KEY_BYTES:
        raise KmsWrapError(
            f"the ephemeral AES key must be {AES_KEY_BYTES} bytes, got {len(ephemeral)}"
        )
    try:
        material_wrapped = keywrap.aes_key_wrap_with_padding(
            bytes(ephemeral), plaintext
        )
        aes_wrapped = public_key.encrypt(bytes(ephemeral), _oaep(algorithm))
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean error
        raise KmsWrapError(f"could not wrap the key material: {exc}") from exc
    finally:
        security.zeroize(ephemeral)

    return aes_wrapped + material_wrapped


def wrap_key_material(
    key: KeyMaterial,
    params: ImportParameters,
    *,
    key_spec: str | None = None,
    aes_key: bytes | None = None,
) -> tuple[bytes, KeySpecProfile, int]:
    """Resolve the key spec, build the PKCS#8 DER, and wrap it.

    Returns ``(blob, profile, plaintext_len)``. The plaintext is revealed at
    this single point of use and not bound to anything that outlives the call.
    """
    profile = resolve_key_spec(key, key_spec)
    plaintext = pkcs8_der(key, profile)
    blob = wrap_plaintext(
        plaintext.reveal(),
        params.wrapping_public_key,
        params.wrapping_algorithm,
        aes_key=aes_key,
    )
    return blob, profile, len(plaintext)


# --------------------------------------------------------------------------
# writing the blob
# --------------------------------------------------------------------------


def _write_exclusive(path: str | Path, payload: bytes) -> Path:
    """Create a file at mode 0600, refusing to overwrite or follow a symlink.

    Same contract and wording as :func:`s70.keystore_polkadot.write_keystore`.
    """
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise S70Error(f"refusing to overwrite an existing file: {path}") from None
    except OSError as exc:
        raise S70Error(f"could not create {path}: {exc}") from exc

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
    except OSError as exc:
        raise S70Error(f"could not write {path}: {exc}") from exc
    return path


def permission_warning(path: Path) -> str | None:
    """Warn when a written file is group- or world-readable after all.

    ``O_CREAT`` with mode 0600 is honoured by every real filesystem and by none
    of the ones people carry recovery material on: a FAT32 or exFAT USB stick
    has no permission bits and mounts everything 0777. The blob is ciphertext
    so this is not urgent, but this tool says what it did and did not manage.
    """
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return None
    if mode & 0o077:
        return (
            f"{path} ended up mode {mode:04o}, not 0600 -- this filesystem has no "
            "permission bits (a FAT32/exFAT USB stick does not). The file is "
            "ciphertext, so this is not a key leak, but anyone with the disk can read "
            "it."
        )
    return None


@dataclass
class WrapResult:
    """What was written, and everything needed to talk about it.

    Deliberately holds **no key material** -- no :class:`Secret`, no scalar, no
    PKCS#8 DER. It has to survive ``session.forget()``, because the guide is
    printed after the key it describes has been dropped.
    """

    path: Path
    profile: KeySpecProfile
    wrapping_algorithm: str
    rsa_key_size: int
    blob_len: int
    plaintext_len: int
    #: SubjectPublicKeyInfo DER of the public half, derived by this tool from
    #: the private key. The verification step compares it against KMS's own.
    public_key_der: bytes
    public_key_sha256: str
    warnings: list[str] = field(default_factory=list)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_der).decode("ascii")


def _spki_der(key: KeyMaterial, profile: KeySpecProfile) -> bytes:
    """The public half as SubjectPublicKeyInfo DER, as ``get-public-key`` returns it."""
    if profile.curve == CURVE_ED25519:
        public = ed25519.Ed25519PublicKey.from_public_bytes(key.public_key)
    else:
        raw = key.public_key
        point = raw if len(raw) == 65 and raw[0] == 0x04 else b"\x04" + raw
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), point)
    return public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def write_encrypted_key_material(
    path: str | Path,
    key: KeyMaterial,
    params: ImportParameters,
    *,
    key_spec: str | None = None,
    aes_key: bytes | None = None,
) -> WrapResult:
    """Wrap the key and write the blob, owner-only and refusing to overwrite.

    Wrapping happens *before* the file is opened, deliberately: a wrap that
    fails must leave nothing behind, or the user's second attempt hits
    "refusing to overwrite" against a zero-byte file they never wanted.
    """
    blob, profile, plaintext_len = wrap_key_material(
        key, params, key_spec=key_spec, aes_key=aes_key
    )
    written = _write_exclusive(path, blob)

    spki = _spki_der(key, profile)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(spki)

    warnings: list[str] = []
    mode_warning = permission_warning(written)
    if mode_warning:
        warnings.append(mode_warning)

    return WrapResult(
        path=written,
        profile=profile,
        wrapping_algorithm=params.wrapping_algorithm,
        rsa_key_size=params.rsa_key_size,
        blob_len=len(blob),
        plaintext_len=plaintext_len,
        public_key_der=spki,
        public_key_sha256=digest.finalize().hex(),
        warnings=warnings,
    )


# --------------------------------------------------------------------------
# the guide
# --------------------------------------------------------------------------


def _wrap_note(note: str, width: int) -> list[str]:
    """Wrap one bullet, keeping any single over-long token on its own line."""
    wrapped = textwrap.wrap(
        note,
        width=width,
        initial_indent="     - ",
        subsequent_indent="       ",
        break_long_words=False,
        break_on_hyphens=False,
    )
    return wrapped or [f"     - {note}"]


@dataclass
class KmsStep:
    title: str
    commands: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class KmsGuide:
    """A numbered list of what to do next, and only what is left to do.

    ``preamble`` is a receipt -- what this run produced -- and is printed
    unnumbered, above the steps. The numbered steps are strictly things the
    user has still to do, because a numbered list whose first entries are
    already behind them is a list they have to read twice to find their place
    in.

    Same shape as :class:`s70.wallets.ImportGuide` so both front ends already
    know how to render it. Everything on it is public.
    """

    steps: list[KmsStep] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    preamble: list[str] = field(default_factory=list)

    def render(self, width: int = 84) -> str:
        """Plain text, no markup -- ARNs and JSON braces have to survive rich.

        Prose is wrapped here so the caller can print with wrapping disabled:
        a command broken mid-token by a terminal is a command nobody can copy,
        and these commands are the entire deliverable. Long single tokens (a
        base64 public key) are left over-long for the same reason.
        """
        lines: list[str] = list(self.preamble)
        if lines and self.steps:
            lines.append("")
        for index, step in enumerate(self.steps, start=1):
            if index > 1:
                lines.append("")
            lines.append(f"{index}. {step.title}")
            for command in step.commands:
                lines.append(f"     {command}")
            for note in step.notes:
                lines.extend(_wrap_note(note, width))
        if self.warnings:
            lines.append("")
            lines.append("Warnings")
            for warning in self.warnings:
                lines.extend(_wrap_note(warning, width))
        return "\n".join(lines)


_CUSTODY_NOTE: Final = (
    "Importing to KMS is a custody move, not a copy you can undo: KMS will never "
    "export the private key again. Keep this backup file until the funds have "
    "actually moved."
)


def _region_flag(region: str | None) -> str:
    return f" --region {region}" if region else " --region <region>"


def key_spec_steps(
    profile: KeySpecProfile,
    *,
    wrapping_algorithm: str = DEFAULT_WRAPPING_ALGORITHM,
    region: str | None = None,
    wallet_name: str = "",
) -> list[KmsStep]:
    """The two online steps that must happen before this tool can do anything.

    Split out so ``s70 kms-prepare`` can print them without decrypting a key --
    the curve, and therefore the key spec, is already stated in the backup's
    ``key_type`` field.
    """
    described = f"s70 recovered {wallet_name}".strip() if wallet_name else "s70 recovered key"
    return [
        KmsStep(
            title=f"ONLINE -- create an empty KMS key for {profile.key_spec}",
            commands=[
                "aws kms create-key"
                f" --key-spec {profile.key_spec}"
                f" --key-usage {profile.key_usage}"
                " --origin EXTERNAL"
                f' --description "{described}"'
                f"{_region_flag(region)}",
            ],
            notes=[
                "Origin EXTERNAL means the key starts with no key material and cannot "
                "be changed to generate its own later.",
                "Note the KeyId it prints; every later command needs it.",
                "An older AWS CLI spells --key-spec as --customer-master-key-spec.",
                *profile.create_notes,
            ],
        ),
        KmsStep(
            title="ONLINE -- download the wrapping public key and import token",
            commands=[
                "aws kms get-parameters-for-import"
                " --key-id <key-id>"
                f" --wrapping-algorithm {wrapping_algorithm}"
                " --wrapping-key-spec RSA_4096"
                f"{_region_flag(region)}"
                " > import-parameters.json",
            ],
            notes=[
                f"--wrapping-algorithm must be {wrapping_algorithm} here, matching what "
                "the offline step uses. It is not recorded in the response, so a "
                "mismatch only surfaces as a failed import.",
                "PublicKey and ImportToken are an indivisible pair and expire together "
                "after 24 hours. Do not mix them with another download's.",
                "Carry import-parameters.json to the offline machine.",
            ],
        ),
    ]


def build_guide(
    result: WrapResult,
    params: ImportParameters,
    *,
    key_id: str | None = None,
    token_path: Path | None = None,
    now: datetime | None = None,
) -> KmsGuide:
    """What is left to do, once the key has been wrapped.

    ``create-key`` and ``get-parameters-for-import`` are deliberately absent:
    by the time this runs they have already happened -- their output is what
    ``--params`` was pointed at. ``s70 kms-prepare`` prints them, before they
    are needed. Numbering them here again put the user's actual next command at
    step 4 of 6, three of which were behind them.

    ``token_path`` is the import token file the caller wrote next to the blob.
    The commands reference files by bare name, so they work when run from the
    directory the two files were carried to.
    """
    key_id = key_id or params.key_id or "<key-id>"
    region = params.region
    profile = result.profile

    if token_path is not None:
        token_ref = f"fileb://{token_path.name}"
        token_note = (
            "The import token was written beside the blob and must be the one from "
            "the same `get-parameters-for-import` call as the wrapping key -- it is, "
            "because it came out of the same file."
        )
    else:
        token_ref = "fileb://ImportToken.bin"
        token_note = (
            "These import parameters carried no token, so nothing was written for "
            "you. Supply the ImportToken from the same download as the wrapping "
            "public key, decoded to raw bytes, and point --import-token at it."
        )

    preamble = [
        "Wrapped and written:",
        f"     {result.path}  ({result.blob_len} bytes)",
    ]
    if token_path is not None:
        preamble.append(f"     {token_path}  (import token, {len(params.import_token or b'')} bytes)")
    preamble.extend(
        _wrap_note(
            f"{result.plaintext_len}-byte PKCS#8 DER, wrapped with "
            f"{result.wrapping_algorithm} under an RSA-{result.rsa_key_size} wrapping "
            f"key from {params.source}.",
            84,
        )
    )
    preamble.extend(
        _wrap_note(
            "Carry both files to the online machine, into the same directory, and run "
            "the commands below from there. Both are safe to carry on an untrusted "
            "USB stick: the blob is encrypted to AWS's own HSM public key and the "
            "import token is public.",
            84,
        )
        if token_path is not None
        else _wrap_note(
            "Carry the blob to the online machine. It is safe to carry on an "
            "untrusted USB stick: it is encrypted to AWS's own HSM public key.",
            84,
        )
    )

    steps = [
        KmsStep(
            title="ONLINE -- import the key material",
            commands=[
                "aws kms import-key-material"
                f" --key-id {key_id}"
                f" --encrypted-key-material fileb://{result.path.name}"
                f" --import-token {token_ref}"
                " --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE"
                f"{_region_flag(region)}",
            ],
            notes=[
                token_note,
                "KEY_MATERIAL_DOES_NOT_EXPIRE keeps the key usable indefinitely. Use "
                "--expiration-model KEY_MATERIAL_EXPIRES with --valid-to if you want it "
                "to lapse on its own.",
            ],
        )
    ]

    steps.append(
        KmsStep(
            title="ONLINE -- verify KMS holds the key you think it does",
            commands=[
                "aws kms get-public-key"
                f" --key-id {key_id}"
                f"{_region_flag(region)}"
                " --query PublicKey --output text | base64 -d | openssl dgst -sha256",
                f"# must print: {result.public_key_sha256}",
            ],
            notes=[
                "This is the check worth doing. The fingerprint above was computed "
                "here, from the private key in your backup, before anything was "
                "wrapped. If KMS reports a different one, the material landed on the "
                "wrong key: disable that KMS key and stop.",
                f"Full public key, if you would rather compare it directly: "
                f"{result.public_key_b64}",
            ],
        )
    )

    sign_commands = []
    sign_notes = []
    for algorithm in profile.signing_algorithms:
        sign_commands.append(
            "aws kms sign"
            f" --key-id {key_id}"
            f" --signing-algorithm {algorithm.name}"
            f" --message-type {algorithm.message_type}"
            " --message fileb://message.bin"
            f"{_region_flag(region)}"
        )
        if algorithm.note:
            sign_notes.append(f"{algorithm.name} / {algorithm.message_type}: {algorithm.note}")
    sign_notes.extend(profile.signing_notes)
    sign_notes.append(_CUSTODY_NOTE)

    steps.append(
        KmsStep(
            title="ONLINE -- sign with it",
            commands=sign_commands,
            notes=sign_notes,
        )
    )

    warnings = age_warnings(params, now=now) + list(params.notes) + list(result.warnings)
    return KmsGuide(steps=steps, warnings=warnings, preamble=preamble)


__all__ = [
    "DEFAULT_WRAPPING_ALGORITHM",
    "KEYSPEC_ED25519",
    "KEYSPEC_SECP256K1",
    "KmsGuide",
    "KmsStep",
    "KeySpecProfile",
    "ImportParameters",
    "PROFILES",
    "RSA_KEY_SIZES",
    "SigningAlgorithm",
    "WRAPPING_ALGORITHMS",
    "WrapResult",
    "age_warnings",
    "build_guide",
    "check_import_token_destination",
    "key_spec_steps",
    "load_import_parameters",
    "max_oaep_plaintext",
    "parse_wrapping_algorithm",
    "permission_warning",
    "pkcs8_der",
    "profile_for_curve",
    "profile_for_key_spec",
    "resolve_key_spec",
    "wrap_key_material",
    "wrap_plaintext",
    "write_encrypted_key_material",
    "write_import_token",
]
