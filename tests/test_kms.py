"""AWS KMS export.

The load-bearing tests here are the round trips: they undo the wrap exactly as
KMS's HSM does -- RSA-OAEP the first ``key_size/8`` bytes to get the AES key,
AES-KWP the rest -- and assert the original PKCS#8 DER comes back. That is the
only way to prove the byte layout offline, and it is what makes the feature
safe to ship without an AWS account in CI.

The two mistakes worth pinning explicitly, because both produce a blob that
looks fine and fails hours later inside AWS:

* the AES key going *last* instead of first, and
* using RFC 3394 AES-KW instead of RFC 5649 AES-KWP, which passes for the
  48-byte Ed25519 key and fails for the 135-byte secp256k1 one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from conftest import valid_secp256k1_scalar
from s70 import kms
from s70.errors import KmsKeySpecError, KmsParametersError, KmsWrapError, S70Error
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, parse_candidates

TOKEN = b"opaque-import-token" * 20


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def wrapping_key() -> rsa.RSAPrivateKey:
    """Stands in for the RSA wrapping key KMS would issue.

    Module-scoped: RSA keygen dominates this file's runtime otherwise.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def wrapping_spki(wrapping_key) -> bytes:
    return wrapping_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture
def ed_key():
    seed = hashlib.sha256(b"kms-ed25519").digest()
    return next(k for k in parse_candidates(seed) if k.curve == CURVE_ED25519)


@pytest.fixture
def k1_key():
    scalar = valid_secp256k1_scalar(b"kms-secp256k1")
    return next(k for k in parse_candidates(scalar) if k.curve == CURVE_SECP256K1)


@pytest.fixture
def console_dir(tmp_path, wrapping_spki):
    """A console import-parameters download, as unzipped by the user."""
    bundle = tmp_path / "Import_Parameters_1234abcd_0809092909"
    bundle.mkdir()
    (bundle / kms.CONSOLE_PUBLIC_KEY_NAME).write_bytes(wrapping_spki)
    (bundle / kms.CONSOLE_TOKEN_NAME).write_bytes(TOKEN)
    (bundle / kms.CONSOLE_README_NAME).write_text(
        "Wrapping algorithm: RSA_AES_KEY_WRAP_SHA_256\n"
        "These parameters expire in 24 hours.\n"
    )
    return bundle


@pytest.fixture
def params_json(tmp_path, wrapping_spki):
    """The JSON `aws kms get-parameters-for-import` prints."""
    valid_to = datetime.now(timezone.utc) + timedelta(hours=23)
    path = tmp_path / "import-parameters.json"
    path.write_text(
        json.dumps(
            {
                "KeyId": "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab",
                "PublicKey": base64.b64encode(wrapping_spki).decode(),
                "ImportToken": base64.b64encode(TOKEN).decode(),
                "ParametersValidTo": valid_to.timestamp(),
            }
        )
    )
    return path


def _oaep(digest):
    return padding.OAEP(mgf=padding.MGF1(digest), algorithm=digest, label=None)


def _unwrap(blob: bytes, private: rsa.RSAPrivateKey, digest) -> bytes:
    """Undo a two-step wrap the way KMS's HSM does."""
    split = private.key_size // 8
    aes_key = private.decrypt(blob[:split], _oaep(digest))
    assert len(aes_key) == kms.AES_KEY_BYTES
    return keywrap.aes_key_unwrap_with_padding(aes_key, blob[split:])


# --------------------------------------------------------------------------
# the wrap round trip
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("algorithm", "digest"),
    [
        (kms.WRAP_RSA_AES_SHA256, hashes.SHA256()),
        (kms.WRAP_RSA_AES_SHA1, hashes.SHA1()),
    ],
)
@pytest.mark.parametrize("curve", [CURVE_ED25519, CURVE_SECP256K1])
def test_two_step_wrap_round_trips(
    algorithm, digest, curve, ed_key, k1_key, wrapping_key
):
    """Unwrap as KMS does and get the PKCS#8 DER back, byte for byte."""
    key = ed_key if curve == CURVE_ED25519 else k1_key
    profile = kms.profile_for_curve(curve)
    plaintext = kms.pkcs8_der(key, profile).reveal()

    blob = kms.wrap_plaintext(plaintext, wrapping_key.public_key(), algorithm)
    recovered = _unwrap(blob, wrapping_key, digest)

    assert recovered == plaintext

    reloaded = serialization.load_der_private_key(recovered, password=None)
    if curve == CURVE_ED25519:
        assert isinstance(reloaded, ed25519.Ed25519PrivateKey)
        assert (
            reloaded.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            == key.scalar.reveal()
        )
    else:
        assert isinstance(reloaded.curve, ec.SECP256K1)
        assert reloaded.private_numbers().private_value.to_bytes(
            32, "big"
        ) == key.scalar.reveal()


@pytest.mark.parametrize("curve", [CURVE_ED25519, CURVE_SECP256K1])
def test_single_step_oaep_round_trips(curve, ed_key, k1_key, wrapping_key):
    key = ed_key if curve == CURVE_ED25519 else k1_key
    plaintext = kms.pkcs8_der(key).reveal()

    blob = kms.wrap_plaintext(
        plaintext, wrapping_key.public_key(), kms.WRAP_OAEP_SHA256
    )

    assert len(blob) == wrapping_key.key_size // 8
    assert wrapping_key.decrypt(blob, _oaep(hashes.SHA256())) == plaintext


def test_aes_key_comes_first_not_last(k1_key, wrapping_key):
    """The single easiest thing to get backwards, and the costliest."""
    plaintext = kms.pkcs8_der(k1_key).reveal()
    blob = kms.wrap_plaintext(
        plaintext, wrapping_key.public_key(), kms.WRAP_RSA_AES_SHA256
    )
    split = wrapping_key.key_size // 8

    # Front half is the RSA block.
    assert len(wrapping_key.decrypt(blob[:split], _oaep(hashes.SHA256()))) == 32
    # Back half is not: reading the blob the other way round must not work.
    with pytest.raises(Exception):
        wrapping_key.decrypt(blob[-split:], _oaep(hashes.SHA256()))


def test_kwp_uses_the_rfc5649_alternative_iv(wrapping_key):
    """Pin RFC 5649 rather than trusting a function name.

    An 8-byte payload is a single KW block, so the A65959A6 || length AIV
    survives decryption intact and can be read straight back out.
    """
    kek = bytes(32)
    wrapped = keywrap.aes_key_wrap_with_padding(kek, bytes(8))
    decryptor = Cipher(algorithms.AES(kek), modes.ECB()).decryptor()
    plain = decryptor.update(wrapped) + decryptor.finalize()
    assert plain[:8].hex() == "a65959a600000008"


@pytest.mark.parametrize(
    ("length", "expected"), [(48, 56), (135, 144), (8, 16), (32, 40)]
)
def test_kwp_output_length(length, expected):
    assert len(keywrap.aes_key_wrap_with_padding(bytes(32), bytes(length))) == expected


def test_blob_length_is_rsa_block_plus_kwp(ed_key, k1_key, wrapping_key):
    split = wrapping_key.key_size // 8
    for key, kwp_len in ((ed_key, 56), (k1_key, 144)):
        blob = kms.wrap_plaintext(
            kms.pkcs8_der(key).reveal(),
            wrapping_key.public_key(),
            kms.WRAP_RSA_AES_SHA256,
        )
        assert len(blob) == split + kwp_len


def test_sha1_variant_differs_only_in_the_oaep_hash(k1_key, wrapping_key):
    plaintext = kms.pkcs8_der(k1_key).reveal()
    blob = kms.wrap_plaintext(
        plaintext, wrapping_key.public_key(), kms.WRAP_RSA_AES_SHA1
    )
    assert _unwrap(blob, wrapping_key, hashes.SHA1()) == plaintext
    with pytest.raises(Exception):
        _unwrap(blob, wrapping_key, hashes.SHA256())


# --------------------------------------------------------------------------
# plaintext key material
# --------------------------------------------------------------------------


def test_pkcs8_der_shapes(ed_key, k1_key):
    from s70.keymaterial import PKCS8_ED25519_HEADER

    ed_der = kms.pkcs8_der(ed_key).reveal()
    assert len(ed_der) == 48
    assert ed_der.startswith(PKCS8_ED25519_HEADER)
    assert ed_der[16:48] == ed_key.scalar.reveal()

    k1_der = kms.pkcs8_der(k1_key).reveal()
    assert len(k1_der) == 135
    reloaded = serialization.load_der_private_key(k1_der, password=None)
    assert reloaded.private_numbers().private_value.to_bytes(
        32, "big"
    ) == k1_key.scalar.reveal()


def test_pkcs8_der_keeps_a_leading_zero_scalar():
    """A short big-integer scalar must stay 32 bytes, not shrink to 30."""
    scalar = bytes(2) + valid_secp256k1_scalar(b"leading-zeros")[2:]
    key = next(k for k in parse_candidates(scalar) if k.curve == CURVE_SECP256K1)
    der = kms.pkcs8_der(key).reveal()
    reloaded = serialization.load_der_private_key(der, password=None)
    assert reloaded.private_numbers().private_value.to_bytes(32, "big") == scalar


def test_pkcs8_der_is_a_secret(ed_key):
    secret = kms.pkcs8_der(ed_key)
    assert secret.reveal().hex() not in repr(secret)
    assert len(secret) == 48


def test_mislabelled_curve_is_refused(ed_key):
    """A public key that does not match the private one must not be wrapped."""
    import dataclasses

    tampered = dataclasses.replace(ed_key, public_key=bytes(32))
    with pytest.raises(KmsKeySpecError, match="mislabelled"):
        kms.pkcs8_der(tampered)


# --------------------------------------------------------------------------
# key spec resolution
# --------------------------------------------------------------------------


def test_key_spec_follows_the_curve(ed_key, k1_key):
    assert kms.profile_for_curve(CURVE_ED25519).key_spec == kms.KEYSPEC_ED25519
    assert kms.profile_for_curve(CURVE_SECP256K1).key_spec == kms.KEYSPEC_SECP256K1
    for key in (ed_key, k1_key):
        assert kms.resolve_key_spec(key).key_usage == "SIGN_VERIFY"


def test_matching_key_spec_is_accepted(ed_key):
    profile = kms.resolve_key_spec(ed_key, kms.KEYSPEC_ED25519)
    assert profile.key_spec == kms.KEYSPEC_ED25519


def test_contradicting_key_spec_is_refused(ed_key, k1_key):
    with pytest.raises(KmsKeySpecError, match="different accounts"):
        kms.resolve_key_spec(ed_key, kms.KEYSPEC_SECP256K1)
    with pytest.raises(KmsKeySpecError, match="different accounts"):
        kms.resolve_key_spec(k1_key, kms.KEYSPEC_ED25519)


def test_unknown_key_spec_is_refused(ed_key):
    with pytest.raises(KmsKeySpecError):
        kms.resolve_key_spec(ed_key, "RSA_4096")


def test_ed25519_signing_algorithm_is_pure_eddsa():
    """RAW/ED25519_SHA_512 is what Solana, Stellar, Aptos and Sui verify."""
    profile = kms.profile_for_curve(CURVE_ED25519)
    primary = profile.signing_algorithms[0]
    assert primary.name == "ED25519_SHA_512"
    assert primary.message_type == "RAW"
    # The prehashed variant must be present but not first -- no chain wants it.
    prehashed = profile.signing_algorithms[1]
    assert prehashed.name == "ED25519_PH_SHA_512"
    assert prehashed.message_type == "DIGEST"


# --------------------------------------------------------------------------
# OAEP size ceiling
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("bits", "hash_len", "expected"),
    [(2048, 32, 190), (2048, 20, 214), (3072, 32, 318), (4096, 32, 446)],
)
def test_max_oaep_plaintext(bits, hash_len, expected):
    assert kms.max_oaep_plaintext(bits, hash_len) == expected


def test_single_step_oaep_refuses_oversized_plaintext(wrapping_key):
    with pytest.raises(KmsWrapError, match="190"):
        kms.wrap_plaintext(
            bytes(200), wrapping_key.public_key(), kms.WRAP_OAEP_SHA256
        )


def test_bad_aes_key_length_is_refused(wrapping_key):
    with pytest.raises(KmsWrapError, match="32 bytes"):
        kms.wrap_plaintext(
            bytes(48),
            wrapping_key.public_key(),
            kms.WRAP_RSA_AES_SHA256,
            aes_key=bytes(16),
        )


def test_unknown_wrapping_algorithm_is_refused(wrapping_key):
    with pytest.raises(KmsParametersError):
        kms.wrap_plaintext(bytes(48), wrapping_key.public_key(), "AES_GCM")


# --------------------------------------------------------------------------
# import parameters
# --------------------------------------------------------------------------


def test_loads_console_directory(console_dir, wrapping_spki):
    params = kms.load_import_parameters(console_dir)
    assert params.wrapping_algorithm == kms.WRAP_RSA_AES_SHA256
    assert params.algorithm_source == kms.CONSOLE_README_NAME
    assert params.import_token == TOKEN
    assert params.import_token_path.name == kms.CONSOLE_TOKEN_NAME
    assert params.rsa_key_size == 2048


def test_loads_nested_extracted_directory(console_dir):
    """Pointing at the folder you unzipped *into* has to work too."""
    params = kms.load_import_parameters(console_dir.parent)
    assert params.import_token == TOKEN


def test_loads_console_zip(tmp_path, wrapping_spki):
    archive = tmp_path / "Import_Parameters.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        prefix = "Import_Parameters_1234abcd_0809092909/"
        zf.writestr(prefix + kms.CONSOLE_PUBLIC_KEY_NAME, wrapping_spki)
        zf.writestr(prefix + kms.CONSOLE_TOKEN_NAME, TOKEN)
        zf.writestr(
            prefix + kms.CONSOLE_README_NAME,
            "Wrapping algorithm: RSAES_OAEP_SHA_256\n",
        )
    params = kms.load_import_parameters(archive)
    assert params.wrapping_algorithm == kms.WRAP_OAEP_SHA256
    assert params.import_token == TOKEN


def test_loads_get_parameters_for_import_json(params_json):
    params = kms.load_import_parameters(params_json)
    assert params.import_token == TOKEN
    assert params.region == "eu-west-1"
    assert params.key_id.startswith("arn:aws:kms:")
    assert params.parameters_valid_to is not None
    # The API does not echo the algorithm back, so this is assumed and said so.
    assert params.algorithm_source == "default (assumed)"
    assert any("assumed" in note for note in params.notes)


def test_console_and_json_agree_on_the_wrapping_key(console_dir, params_json):
    from_dir = kms.load_import_parameters(console_dir)
    from_json = kms.load_import_parameters(params_json)
    assert (
        from_dir.wrapping_public_key.public_numbers()
        == from_json.wrapping_public_key.public_numbers()
    )


def test_parameters_valid_to_accepts_an_iso_z_suffix(tmp_path, wrapping_spki):
    """`fromisoformat` only learned to parse the trailing Z in 3.11.

    This package supports 3.10, and a dev machine on 3.13 would never see the
    failure, so the normalisation needs its own test.
    """
    path = tmp_path / "p.json"
    path.write_text(
        json.dumps(
            {
                "PublicKey": base64.b64encode(wrapping_spki).decode(),
                "ImportToken": base64.b64encode(TOKEN).decode(),
                "ParametersValidTo": "2026-09-11T15:41:51Z",
            }
        )
    )
    params = kms.load_import_parameters(path)
    assert params.parameters_valid_to == datetime(
        2026, 9, 11, 15, 41, 51, tzinfo=timezone.utc
    )


def test_bare_wrapping_public_key_is_accepted_with_a_note(tmp_path, wrapping_spki):
    path = tmp_path / kms.CONSOLE_PUBLIC_KEY_NAME
    path.write_bytes(wrapping_spki)
    params = kms.load_import_parameters(path)
    assert params.import_token is None
    assert any("import token" in note.lower() for note in params.notes)


def test_rejects_non_rsa_wrapping_key(tmp_path):
    path = tmp_path / kms.CONSOLE_PUBLIC_KEY_NAME
    path.write_bytes(
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(KmsParametersError, match="RSA"):
        kms.load_import_parameters(path)


def test_rejects_wrong_rsa_size(tmp_path):
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    path = tmp_path / kms.CONSOLE_PUBLIC_KEY_NAME
    path.write_bytes(
        small.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(KmsParametersError, match="1024"):
        kms.load_import_parameters(path)


def test_missing_path_is_reported(tmp_path):
    with pytest.raises(KmsParametersError, match="no such path"):
        kms.load_import_parameters(tmp_path / "nope")


def test_directory_without_a_wrapping_key_is_reported(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(KmsParametersError, match=kms.CONSOLE_PUBLIC_KEY_NAME):
        kms.load_import_parameters(tmp_path / "empty")


def test_malformed_json_is_reported(tmp_path):
    path = tmp_path / "p.json"
    path.write_text('{"PublicKey": "not base64!!!"}')
    with pytest.raises(KmsParametersError):
        kms.load_import_parameters(path)


# --------------------------------------------------------------------------
# wrapping algorithm precedence
# --------------------------------------------------------------------------


def test_readme_algorithm_is_parsed():
    assert (
        kms.parse_wrapping_algorithm("Wrapping algorithm: RSAES_OAEP_SHA_1")
        == kms.WRAP_OAEP_SHA1
    )
    assert kms.parse_wrapping_algorithm("nothing useful here") is None


def test_readme_naming_two_algorithms_is_refused():
    with pytest.raises(KmsParametersError, match="more than one"):
        kms.parse_wrapping_algorithm(
            "either RSA_AES_KEY_WRAP_SHA_256 or RSAES_OAEP_SHA_256"
        )


def test_withdrawn_pkcs1_algorithm_is_refused():
    with pytest.raises(KmsParametersError, match="withdrew"):
        kms.parse_wrapping_algorithm("Wrapping algorithm: RSAES_PKCS1_V1_5")


def test_explicit_algorithm_conflicting_with_readme_is_refused(console_dir):
    with pytest.raises(KmsParametersError, match="has to match"):
        kms.load_import_parameters(
            console_dir, wrapping_algorithm=kms.WRAP_OAEP_SHA256
        )


def test_explicit_algorithm_agreeing_with_readme_is_fine(console_dir):
    params = kms.load_import_parameters(
        console_dir, wrapping_algorithm=kms.WRAP_RSA_AES_SHA256
    )
    assert params.wrapping_algorithm == kms.WRAP_RSA_AES_SHA256


def test_explicit_algorithm_wins_when_there_is_no_readme(params_json):
    params = kms.load_import_parameters(
        params_json, wrapping_algorithm=kms.WRAP_OAEP_SHA1
    )
    assert params.wrapping_algorithm == kms.WRAP_OAEP_SHA1
    assert params.algorithm_source == "--wrapping-algorithm"


def test_duplicate_basenames_in_a_bundle_are_refused(tmp_path, wrapping_spki):
    """Mixing two downloads mismatches the key and token pair."""
    bundle = tmp_path / "two"
    (bundle / "a").mkdir(parents=True)
    (bundle / kms.CONSOLE_PUBLIC_KEY_NAME).write_bytes(wrapping_spki)
    (bundle / "a" / kms.CONSOLE_PUBLIC_KEY_NAME).write_bytes(wrapping_spki)
    with pytest.raises(KmsParametersError, match="more than one"):
        kms.load_import_parameters(bundle)


# --------------------------------------------------------------------------
# freshness
# --------------------------------------------------------------------------


def test_fresh_parameters_produce_no_warnings(params_json):
    assert kms.age_warnings(kms.load_import_parameters(params_json)) == []


def test_expired_parameters_warn_but_do_not_block(tmp_path, wrapping_spki, ed_key):
    path = tmp_path / "old.json"
    stale = datetime.now(timezone.utc) - timedelta(hours=30)
    path.write_text(
        json.dumps(
            {
                "PublicKey": base64.b64encode(wrapping_spki).decode(),
                "ImportToken": base64.b64encode(TOKEN).decode(),
                "ParametersValidTo": stale.timestamp(),
            }
        )
    )
    params = kms.load_import_parameters(path)
    warnings = kms.age_warnings(params)
    assert any("expired" in w for w in warnings)
    assert any("clock" in w for w in warnings)

    # And it still works: the blob is correct regardless of the clock.
    blob, _, _ = kms.wrap_key_material(ed_key, params)
    assert len(blob) == params.rsa_key_size // 8 + 56


def test_clock_before_creation_warns_about_the_clock(params_json):
    params = kms.load_import_parameters(params_json)
    long_ago = datetime(2001, 1, 1, tzinfo=timezone.utc)
    warnings = kms.age_warnings(params, now=long_ago)
    assert any("clock is wrong" in w for w in warnings)


# --------------------------------------------------------------------------
# writing the blob
# --------------------------------------------------------------------------


def test_write_produces_an_unwrappable_blob(tmp_path, k1_key, console_dir, wrapping_key):
    params = kms.load_import_parameters(console_dir)
    out = tmp_path / "EncryptedKeyMaterial.bin"
    result = kms.write_encrypted_key_material(out, k1_key, params)

    assert result.blob_len == out.stat().st_size
    recovered = _unwrap(out.read_bytes(), wrapping_key, hashes.SHA256())
    assert recovered == kms.pkcs8_der(k1_key).reveal()


def test_written_blob_is_owner_only(tmp_path, ed_key, console_dir):
    params = kms.load_import_parameters(console_dir)
    out = tmp_path / "blob.bin"
    kms.write_encrypted_key_material(out, ed_key, params)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600


def test_write_refuses_to_overwrite(tmp_path, ed_key, console_dir):
    params = kms.load_import_parameters(console_dir)
    out = tmp_path / "blob.bin"
    out.write_bytes(b"existing")
    with pytest.raises(S70Error, match="refusing to overwrite"):
        kms.write_encrypted_key_material(out, ed_key, params)
    assert out.read_bytes() == b"existing"


def test_failed_wrap_writes_nothing(tmp_path, k1_key, console_dir):
    """A wrap that fails must not leave a file the retry then refuses."""
    params = kms.load_import_parameters(
        console_dir, wrapping_algorithm=kms.WRAP_RSA_AES_SHA256
    )
    out = tmp_path / "blob.bin"
    with pytest.raises(KmsKeySpecError):
        kms.write_encrypted_key_material(
            out, k1_key, params, key_spec=kms.KEYSPEC_ED25519
        )
    assert not out.exists()


def test_write_import_token(tmp_path, params_json):
    params = kms.load_import_parameters(params_json)
    out = tmp_path / "ImportToken.bin"
    kms.write_import_token(out, params)
    assert out.read_bytes() == TOKEN
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600


def test_write_import_token_without_one_is_refused(tmp_path, wrapping_spki):
    path = tmp_path / kms.CONSOLE_PUBLIC_KEY_NAME
    path.write_bytes(wrapping_spki)
    params = kms.load_import_parameters(path)
    with pytest.raises(KmsParametersError, match="no import token"):
        kms.write_import_token(tmp_path / "t.bin", params)


# --------------------------------------------------------------------------
# the guide
# --------------------------------------------------------------------------


@pytest.fixture
def wrapped(tmp_path, k1_key, console_dir):
    params = kms.load_import_parameters(console_dir)
    result = kms.write_encrypted_key_material(tmp_path / "blob.bin", k1_key, params)
    return result, params


def test_guide_covers_what_is_left_to_do(wrapped):
    result, params = wrapped
    text = kms.build_guide(result, params, key_id="abc-123").render()
    for expected in (
        "import-key-material",
        "fileb://",
        "--expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE",
        "get-public-key",
        "aws kms sign",
        "abc-123",
    ):
        assert expected in text, expected


def test_guide_does_not_re_list_steps_already_done(wrapped):
    """create-key and get-parameters-for-import happened before this ran.

    Their output is what --params was pointed at. Numbering them again put the
    user's actual next command at step 4 of 6.
    """
    result, params = wrapped
    text = kms.build_guide(result, params, key_id="abc-123").render()
    assert "aws kms create-key" not in text
    assert "get-parameters-for-import" not in text
    # The first numbered step is the first thing left to do.
    assert "1. ONLINE -- import the key material" in text


def test_guide_reports_what_was_written_before_the_steps(wrapped):
    result, params = wrapped
    text = kms.build_guide(result, params, token_path=result.path.parent / "ImportToken.bin")
    rendered = text.render()
    assert rendered.index("Wrapped and written:") < rendered.index("1. ")
    assert result.path.name in rendered
    assert "ImportToken.bin" in rendered


def test_guide_carries_the_derived_public_key(wrapped, k1_key):
    result, params = wrapped
    text = kms.build_guide(result, params).render()

    assert result.public_key_sha256 in text
    assert result.public_key_sha256 == hashlib.sha256(result.public_key_der).hexdigest()

    public = serialization.load_der_public_key(
        base64.b64decode(result.public_key_b64)
    )
    numbers = public.public_numbers()
    assert numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(
        32, "big"
    ) == k1_key.public_key


def test_guide_names_the_right_signing_algorithm(tmp_path, ed_key, console_dir):
    params = kms.load_import_parameters(console_dir)
    result = kms.write_encrypted_key_material(tmp_path / "ed.bin", ed_key, params)
    text = kms.build_guide(result, params).render()

    assert "ED25519_SHA_512" in text
    assert "--message-type RAW" in text
    # The prehashed variant is listed, and flagged as the wrong one.
    assert "ED25519_PH_SHA_512" in text
    assert "do not use it" in text


def test_secp256k1_guide_warns_about_der_and_low_s(wrapped):
    result, params = wrapped
    text = kms.build_guide(result, params).render()
    assert "low-S" in text
    assert "recovery id" in text


def test_guide_warns_that_import_is_one_way(wrapped):
    result, params = wrapped
    assert "never" in kms.build_guide(result, params).render()


def test_guide_commands_are_never_broken_across_lines(wrapped):
    """Prose wraps; commands must not, or they cannot be copied."""
    result, params = wrapped
    guide = kms.build_guide(result, params, key_id="abc-123")
    rendered = guide.render(width=60)
    for step in guide.steps:
        for command in step.commands:
            assert command in rendered


def test_key_spec_steps_need_no_key():
    """`kms-prepare` prints these before anything is decrypted."""
    steps = kms.key_spec_steps(
        kms.profile_for_curve(CURVE_ED25519), region="eu-west-1"
    )
    text = kms.KmsGuide(steps=steps).render()
    assert kms.KEYSPEC_ED25519 in text
    assert "--region eu-west-1" in text
    assert "get-parameters-for-import" in text


# --------------------------------------------------------------------------
# leak discipline
# --------------------------------------------------------------------------


def test_wrap_result_holds_no_key_material(wrapped, k1_key):
    result, _ = wrapped
    scalar = k1_key.scalar.reveal()
    pkcs8 = kms.pkcs8_der(k1_key).reveal()

    from s70.security import Secret

    for value in vars(result).values():
        assert not isinstance(value, Secret)

    blob = repr(result) + repr(vars(result))
    for secret in (scalar.hex(), pkcs8.hex(), str(list(scalar))):
        assert secret not in blob


def test_nothing_leaks_through_the_guide_or_reprs(wrapped, k1_key):
    result, params = wrapped
    scalar = k1_key.scalar.reveal()
    text = kms.build_guide(result, params).render() + repr(params) + repr(result)
    assert scalar.hex() not in text
    assert kms.pkcs8_der(k1_key).reveal().hex() not in text


def test_import_parameters_repr_is_compact(console_dir):
    params = kms.load_import_parameters(console_dir)
    assert repr(params).startswith("<ImportParameters")
    assert "RSA-2048" in repr(params)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


@pytest.fixture
def declared_curve_backup(tmp_path, wrapping_key):
    """A backup that states `key_type`, as every real one does.

    The shared `synthetic` fixture omits it, so `declared_curve` is None there
    and `kms-prepare` has nothing to report -- but that field is what the
    command is built on, so it needs a file that carries it.

    The ciphertexts are junk: `kms-prepare` decrypts nothing. The recovery key
    still has to load, because opening a backup at all requires one, so the
    module's RSA key is reused here rather than generating a second one.
    """
    recovery_der = wrapping_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "declared.json"
    path.write_text(
        json.dumps(
            {
                "wallet_provider": "S70 Test",
                "recovery_key": base64.b64encode(recovery_der).decode(),
                "keys": [
                    {
                        "key_name": "Treasury EVM",
                        "key_type": "ECDSA_SECP256k1",
                        "shares": [
                            {
                                "metadata": {
                                    "address": "0x" + "11" * 20,
                                    "chain_id": "ch-60",
                                },
                                "encryption": {"ciphertext": "AA=="},
                            }
                        ],
                    },
                    {
                        "key_name": "Solana Main",
                        "key_type": "EDDSA_ED25519",
                        "shares": [
                            {
                                "metadata": {"chain_id": "ch-501"},
                                "encryption": {"ciphertext": "AA=="},
                            }
                        ],
                    },
                ],
            }
        )
    )
    return path


def test_cli_kms_prepare_reports_both_key_specs(declared_curve_backup, capsys):
    from s70 import cli

    assert cli.main(["kms-prepare", str(declared_curve_backup)]) == 0
    out = capsys.readouterr().out
    assert kms.KEYSPEC_SECP256K1 in out
    assert kms.KEYSPEC_ED25519 in out
    # One create-key block per distinct key spec, not one per wallet.
    assert out.count("aws kms create-key") == 2


def test_cli_kms_prepare_says_so_when_the_curve_is_not_stated(synthetic, capsys):
    """A backup with no `key_type` cannot be prepared without decrypting.

    Say that plainly rather than guessing a key spec -- guessing it wrong
    creates a KMS key for the other curve entirely.
    """
    from s70 import cli

    path, _ = synthetic
    assert cli.main(["kms-prepare", str(path)]) == 0
    captured = capsys.readouterr()
    assert "not stated" in captured.out
    assert "do not state a curve" in captured.err


def test_cli_kms_export_end_to_end(synthetic, console_dir, tmp_path, wrapping_key):
    """Backup file in, importable blob out."""
    from s70 import cli

    path, _ = synthetic
    out = tmp_path / "EncryptedKeyMaterial.bin"
    code = cli.main(
        [
            "kms-export",
            "--backup",
            str(path),
            "--wallet",
            "Treasury EVM",
            "--params",
            str(console_dir),
            "--out",
            str(out),
        ]
    )
    assert code == 0

    recovered = _unwrap(out.read_bytes(), wrapping_key, hashes.SHA256())
    reloaded = serialization.load_der_private_key(recovered, password=None)
    assert isinstance(reloaded.curve, ec.SECP256K1)


def test_cli_kms_export_never_prints_the_key(synthetic, console_dir, tmp_path, capsys):
    from s70 import cli

    path, wallets = synthetic

    cli.main(
        [
            "kms-export",
            "--backup",
            str(path),
            "--wallet",
            "Treasury EVM",
            "--params",
            str(console_dir),
            "--out",
            str(tmp_path / "b.bin"),
        ]
    )
    captured = capsys.readouterr()
    wallet = next(w for w in wallets if w.name == "Treasury EVM")
    # The plaintext for this wallet is the raw 32-byte scalar itself.
    assert wallet.plaintext.hex() not in (captured.out + captured.err)


# --------------------------------------------------------------------------
# the import token the printed command points at
# --------------------------------------------------------------------------


def _token_ref(text: str) -> str:
    """The path `--import-token fileb://...` names in the generated command."""
    line = next(l for l in text.splitlines() if "import-key-material" in l)
    return line.split("--import-token fileb://")[1].split()[0]


def test_kms_export_writes_the_token_the_command_points_at(
    synthetic, params_json, tmp_path, capsys
):
    """The generated import command used to name a file nobody had created.

    `--params import-parameters.json` is the documented path, and it carries
    the token as base64. The command needs it as raw bytes, so the export
    writes it out beside the blob and points at it there.
    """
    from s70 import cli

    path, _ = synthetic
    out = tmp_path / "EncryptedKeyMaterial.bin"
    assert cli.main(
        ["kms-export", "--backup", str(path), "--wallet", "Treasury EVM",
         "--params", str(params_json), "--out", str(out)]
    ) == 0

    referenced = out.parent / _token_ref(capsys.readouterr().out)
    assert referenced.exists(), "the command names a file that was never written"
    assert referenced.read_bytes() == TOKEN
    assert stat.S_IMODE(os.stat(referenced).st_mode) == 0o600


def test_generated_commands_use_bare_filenames(synthetic, params_json, tmp_path, capsys):
    """Both files are carried to another machine; absolute paths won't survive."""
    from s70 import cli

    path, _ = synthetic
    out = tmp_path / "deep" / "EncryptedKeyMaterial.bin"
    cli.main(
        ["kms-export", "--backup", str(path), "--wallet", "Treasury EVM",
         "--params", str(params_json), "--out", str(out)]
    )
    command = next(
        l for l in capsys.readouterr().out.splitlines() if "import-key-material" in l
    )
    assert "fileb://EncryptedKeyMaterial.bin" in command
    assert "fileb://ImportToken.bin" in command
    assert str(tmp_path) not in command


def test_write_import_token_overrides_where_it_goes(synthetic, params_json, tmp_path, capsys):
    from s70 import cli

    path, _ = synthetic
    elsewhere = tmp_path / "carried" / "tok.bin"
    cli.main(
        ["kms-export", "--backup", str(path), "--wallet", "Treasury EVM",
         "--params", str(params_json), "--out", str(tmp_path / "b.bin"),
         "--write-import-token", str(elsewhere)]
    )
    assert elsewhere.read_bytes() == TOKEN
    assert _token_ref(capsys.readouterr().out) == "tok.bin"


def test_a_stale_token_at_the_destination_is_refused_before_wrapping(
    synthetic, params_json, tmp_path, capsys
):
    """Pairing last week's token with this week's key gives a blob KMS rejects."""
    from s70 import cli

    path, _ = synthetic
    out = tmp_path / "EncryptedKeyMaterial.bin"
    (tmp_path / "ImportToken.bin").write_bytes(b"a token from an earlier download")

    assert cli.main(
        ["kms-export", "--backup", str(path), "--wallet", "Treasury EVM",
         "--params", str(params_json), "--out", str(out)]
    ) == 1
    assert "different import token" in capsys.readouterr().err
    # Refused before the wrap, so there is no half-finished output to clean up.
    assert not out.exists()


def test_rewriting_the_identical_token_is_not_an_error(synthetic, params_json, tmp_path):
    """A re-run after a failed wrap must not need manual cleanup first."""
    from s70 import cli

    path, _ = synthetic
    (tmp_path / "ImportToken.bin").write_bytes(TOKEN)
    assert cli.main(
        ["kms-export", "--backup", str(path), "--wallet", "Treasury EVM",
         "--params", str(params_json), "--out", str(tmp_path / "blob.bin")]
    ) == 0


def test_bare_public_key_says_the_token_is_missing(tmp_path, wrapping_spki, synthetic, capsys):
    """No token in the parameters means none can be written -- say so."""
    from s70 import cli

    key_only = tmp_path / "WrappingPublicKey.bin"
    key_only.write_bytes(wrapping_spki)
    path, _ = synthetic
    assert cli.main(
        ["kms-export", "--backup", str(path), "--wallet", "Treasury EVM",
         "--params", str(key_only), "--out", str(tmp_path / "blob.bin")]
    ) == 0
    captured = capsys.readouterr()
    assert "carry no import token" in captured.err
    assert "Supply the ImportToken" in captured.out
    assert not (tmp_path / "ImportToken.bin").exists()
