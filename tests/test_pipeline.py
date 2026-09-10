"""End-to-end tests over a synthetic backup.

These cover the paths that decide whether the tool is trustworthy:

* a wrong key must be *reported* as wrong, not quietly accepted
* a 32-byte plaintext must not be assigned a curve by guesswork
* Aptos and Sui must be told apart despite identical address shapes
* a chain with no offline derivation must still hand over its key
* every import string must have the shape its target wallet expects

The ``synthetic`` and ``session`` fixtures live in ``conftest.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from s70 import backup as backup_mod
from s70 import chains, wallets
from s70.chains import Status
from s70.errors import BackupFormatError, KeyMaterialError
from s70.keymaterial import (
    CURVE_ED25519,
    CURVE_SECP256K1,
    PKCS8_ED25519_HEADER,
    ed25519_public_from_seed,
    parse_candidates,
)
from s70.session import RecoverySession

# conftest is importable directly: pytest's default import mode puts this
# directory on sys.path, and there is no tests/__init__.py to make it a package.
from conftest import RSA_BITS, generate_backup, valid_secp256k1_scalar


# --------------------------------------------------------------------------
# backup parsing
# --------------------------------------------------------------------------


def test_loads_synthetic_backup(synthetic):
    path, wallets_meta = synthetic
    parsed = backup_mod.load(path)
    assert parsed.share_count == len(wallets_meta)
    assert parsed.recovery_key_b64


def test_rejects_batch_backup_array(tmp_path):
    path = tmp_path / "batch.json"
    path.write_text(json.dumps([{"encrypted_key": "00", "wallet_address": "0x0"}]))
    with pytest.raises(BackupFormatError, match="batch-backup"):
        backup_mod.load(path)


def test_rejects_file_without_keys(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"wallet_provider": "x"}))
    with pytest.raises(BackupFormatError, match="'keys'"):
        backup_mod.load(path)


# --------------------------------------------------------------------------
# recovery and verification
# --------------------------------------------------------------------------


def test_recovers_and_verifies_every_supported_wallet(session, synthetic):
    _, wallets_meta = synthetic
    session.recover_all()

    for meta, record in zip(wallets_meta, session.records, strict=True):
        # Unsupported chains are recovered too -- they just carry no verdict
        # from an address check. Nothing is skipped any more.
        assert record.skipped_reason is None
        assert record.error is None, record.error
        assert record.verdict is meta.expected_status, (
            f"{meta.name}: expected {meta.expected_status}, got {record.verdict}"
        )


def test_integrity_check_passes_for_all(session):
    session.recover_all()
    for record in session.records:
        if record.skipped_reason:
            continue
        assert record.integrity_result is True


def test_tampered_address_is_reported_as_mismatch(session):
    """The address check must be load-bearing, not decorative."""
    session.recover_all()
    tampered = [r for r in session.records if r.name == "Tampered Stellar"]
    assert tampered, "the synthetic set should contain a deliberately wrong entry"
    assert tampered[0].verdict is Status.MISMATCH
    assert not tampered[0].fully_verified


def test_canton_is_unverifiable_not_verified(session):
    session.recover_all()
    canton = [r for r in session.records if r.name == "Canton Party"]
    assert canton[0].verdict is Status.UNVERIFIABLE


def test_unsupported_chain_still_yields_its_key(session):
    """An unrecoverable *address* must not withhold a recoverable *key*."""
    session.recover_all()
    radix = [r for r in session.records if r.name == "Radix Main"][0]

    assert radix.skipped_reason is None
    assert radix.decrypted is not None
    assert radix.integrity_result is True
    assert not radix.supported

    # The key bytes are the deliverable; the verdict only says what was proved.
    assert radix.key is not None
    assert len(radix.key.scalar.reveal()) == 32
    assert radix.verdict is Status.UNSUPPORTED
    assert not radix.verified_for_signing


def test_unsupported_chain_renders_raw_key_formats(session):
    """No chain builder, so the guide must fall back to raw encodings."""
    session.recover_all()
    radix = [r for r in session.records if r.name == "Radix Main"][0]
    guide = wallets.guide_for(radix.chain, radix.key, radix.chain_label)

    values = [f.value for f in guide.formats]
    scalar = radix.key.scalar.reveal()
    assert "0x" + scalar.hex() in values
    assert base64.b64encode(scalar).decode("ascii") in values
    # Every value must be a faithful encoding of the same key, and the guide
    # must say plainly that the address was never checked.
    assert all(scalar.hex() in v or base64.b64encode(scalar).decode("ascii") in v
               for v in values)
    assert any("not" in w.lower() and "cross-check" in w.lower() for w in guide.warnings)


def test_wrong_recovery_key_fails_cleanly(tmp_path):
    """A different RSA key must fail, not return plausible garbage."""
    good, _ = generate_backup(tmp_path / "a.json", rsa_bits=RSA_BITS)
    other, _ = generate_backup(tmp_path / "b.json", rsa_bits=RSA_BITS)

    document = json.loads(good.read_text())
    document["recovery_key"] = json.loads(other.read_text())["recovery_key"]
    swapped = tmp_path / "swapped.json"
    swapped.write_text(json.dumps(document))

    session = RecoverySession.open(backup_mod.load(swapped))
    stats = session.recover_all()
    assert stats.verified == 0
    assert stats.failed > 0
    for record in session.records:
        if not record.skipped_reason:
            assert record.error is not None


def test_forget_keeps_the_verdict_but_drops_the_key(session):
    record = session.records[0]
    session.recover(record)
    assert record.recovered
    verdict = record.verdict

    session.forget(record)
    assert record.decrypted is None
    assert record.key is None
    assert record.verdict is verdict  # the finding survives the key


# --------------------------------------------------------------------------
# key material interpretation
# --------------------------------------------------------------------------


def test_32_byte_plaintext_is_ambiguous_by_design():
    candidates = parse_candidates(bytes(range(32)))
    assert {c.curve for c in candidates} == {CURVE_ED25519, CURVE_SECP256K1}


def test_pkcs8_ed25519_is_unambiguous():
    seed = hashlib.sha256(b"pkcs8").digest()
    candidates = parse_candidates(PKCS8_ED25519_HEADER + seed)
    assert len(candidates) == 1
    assert candidates[0].curve == CURVE_ED25519
    assert candidates[0].scalar.reveal() == seed


def test_seed_and_public_key_pair_is_validated():
    seed = hashlib.sha256(b"pair").digest()
    good = seed + ed25519_public_from_seed(seed)
    assert parse_candidates(good)[0].scalar.reveal() == seed

    bad = seed + bytes(32)  # public half does not match the seed
    with pytest.raises(KeyMaterialError, match="does not match"):
        parse_candidates(bad)


def test_ascii_armoured_hex_is_unwrapped():
    seed = hashlib.sha256(b"armour").digest()
    candidates = parse_candidates(("0x" + seed.hex()).encode("ascii"))
    assert any(c.scalar.reveal() == seed for c in candidates)
    assert "ASCII-armoured" in candidates[0].encoding


def test_16_byte_plaintext_is_rejected():
    """XRPL keys in this backup format are raw private keys, never seeds."""
    entropy = hashlib.sha256(b"entropy").digest()[:16]
    with pytest.raises(KeyMaterialError, match="does not match any known"):
        parse_candidates(entropy)


def test_unrecognised_length_is_an_error():
    with pytest.raises(KeyMaterialError, match="does not match any known"):
        parse_candidates(b"\x01" * 37)


def test_secret_does_not_leak_through_repr():
    candidates = parse_candidates(bytes(range(32)))
    rendered = repr(candidates[0])
    assert candidates[0].scalar.reveal().hex() not in rendered
    assert "Secret" in repr(candidates[0].scalar)


# --------------------------------------------------------------------------
# chain detection
# --------------------------------------------------------------------------


def test_aptos_and_sui_share_a_shape_but_not_a_derivation():
    """Both are 0x + 64 hex. Only derivation can tell them apart."""
    seed = hashlib.sha256(b"apt-vs-sui").digest()
    key = next(c for c in parse_candidates(seed) if c.curve == CURVE_ED25519)

    aptos = chains.by_id("aptos")
    sui = chains.by_id("sui")
    aptos_address = aptos.addresses_for(key)[0]
    sui_address = sui.addresses_for(key)[0]

    assert aptos_address != sui_address
    assert aptos.matches_shape(sui_address) and sui.matches_shape(aptos_address)

    assert chains.identify(aptos_address, [key]).chain.id == "aptos"
    assert chains.identify(sui_address, [key]).chain.id == "sui"


def test_solana_and_polkadot_are_distinguished():
    seed = hashlib.sha256(b"sol-vs-dot").digest()
    key = next(c for c in parse_candidates(seed) if c.curve == CURVE_ED25519)

    solana_address = chains.by_id("solana").addresses_for(key)[0]
    polkadot_address = chains.by_id("polkadot").addresses_for(key)[0]

    assert chains.identify(solana_address, [key]).chain.id == "solana"
    assert chains.identify(polkadot_address, [key]).chain.id == "polkadot"


def test_curve_ambiguity_resolved_by_address():
    """The same 32 bytes are a valid key on both curves.

    An EVM address can only be produced by the secp256k1 reading, and a
    Stellar address only by the Ed25519 one, so identification must pick the
    right candidate rather than the first one.
    """
    seed = hashlib.sha256(b"curve-choice").digest()
    candidates = parse_candidates(seed)

    evm_key = next(c for c in candidates if c.curve == CURVE_SECP256K1)
    ed_key = next(c for c in candidates if c.curve == CURVE_ED25519)

    evm_address = chains.by_id("evm").addresses_for(evm_key)[0]
    stellar_address = chains.by_id("stellar").addresses_for(ed_key)[0]

    evm_result = chains.identify(evm_address, candidates)
    assert evm_result.chain.id == "evm"
    assert evm_result.key.curve == CURVE_SECP256K1

    stellar_result = chains.identify(stellar_address, candidates)
    assert stellar_result.chain.id == "stellar"
    assert stellar_result.key.curve == CURVE_ED25519


def test_unknown_address_shape_is_unsupported():
    result = chains.identify("account_rdx12" + "8" * 53, parse_candidates(bytes(range(32))))
    assert result.status is Status.UNSUPPORTED
    assert result.chain is None


def test_evm_address_comparison_is_case_insensitive():
    seed = hashlib.sha256(b"eip55").digest()
    key = next(c for c in parse_candidates(seed) if c.curve == CURVE_SECP256K1)
    checksummed = chains.by_id("evm").addresses_for(key)[0]
    assert chains.identify(checksummed.lower(), [key]).status is Status.VERIFIED
    assert any(c.isupper() for c in checksummed[2:]), "expected EIP-55 mixed case"


# --------------------------------------------------------------------------
# import formats
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("chain_id", "curve"),
    [
        ("evm", CURVE_SECP256K1),
        ("solana", CURVE_ED25519),
        ("aptos", CURVE_ED25519),
        ("sui", CURVE_ED25519),
        ("stellar", CURVE_ED25519),
        ("polkadot", CURVE_ED25519),
        ("canton", CURVE_ED25519),
    ],
)
def test_every_chain_produces_an_import_guide(chain_id, curve):
    seed = hashlib.sha256(chain_id.encode()).digest()
    if curve == CURVE_SECP256K1:
        seed = valid_secp256k1_scalar(seed)
    key = next(c for c in parse_candidates(seed) if c.curve == curve)
    guide = wallets.guide_for(chains.by_id(chain_id), key)
    assert guide.formats or guide.blocked
    assert guide.wallet


def test_ed25519_chains_produce_four_different_strings():
    """One key, four wallets, four incompatible encodings.

    This is the reason formats are keyed off the target wallet rather than the
    curve.
    """
    seed = hashlib.sha256(b"one-key-many-wallets").digest()
    key = next(c for c in parse_candidates(seed) if c.curve == CURVE_ED25519)

    values = {}
    for chain_id in ("solana", "aptos", "sui", "stellar"):
        guide = wallets.guide_for(chains.by_id(chain_id), key)
        values[chain_id] = next(f.value for f in guide.formats if f.primary)

    assert len(set(values.values())) == 4
    assert values["stellar"].startswith("S")
    assert values["sui"].startswith("suiprivkey1")
    assert values["aptos"].startswith("0x")
    assert not values["solana"].startswith("0x")


def test_evm_hex_keeps_leading_zeros():
    """MetaMask length-checks the 0x-prefixed string, so padding matters."""
    scalar = bytes(2) + hashlib.sha256(b"pad").digest()[2:]
    key = next(c for c in parse_candidates(scalar) if c.curve == CURVE_SECP256K1)
    value = next(f.value for f in wallets.guide_for(chains.by_id("evm"), key).formats)
    assert len(value) == 66
    assert value.startswith("0x0000")


def test_xrpl_derived_key_reports_no_import_path():
    """A 32-byte XRPL key genuinely cannot be imported anywhere."""
    scalar = valid_secp256k1_scalar(hashlib.sha256(b"xrp").digest())
    key = next(c for c in parse_candidates(scalar) if c.curve == CURVE_SECP256K1)
    guide = wallets.guide_for(chains.by_id("xrpl"), key)
    assert guide.blocked is not None
    assert "family seed" in guide.blocked


def test_xrpl_offers_raw_hex_only():
    """No family seeds: the extensions want one and we cannot produce it."""
    scalar = valid_secp256k1_scalar(hashlib.sha256(b"xrp2").digest())
    key = next(c for c in parse_candidates(scalar) if c.curve == CURVE_SECP256K1)
    guide = wallets.guide_for(chains.by_id("xrpl"), key)

    values = [f.value for f in guide.formats]
    assert scalar.hex() in values
    assert not any(v.startswith("sEd") or v.startswith("s1") for v in values)


def test_polkadot_is_marked_blocked_and_writes_a_file():
    seed = hashlib.sha256(b"dot").digest()
    key = next(c for c in parse_candidates(seed) if c.curve == CURVE_ED25519)
    guide = wallets.guide_for(chains.by_id("polkadot"), key)
    assert guide.blocked is not None
    assert guide.writes_file


def test_import_format_repr_hides_the_value():
    seed = hashlib.sha256(b"repr").digest()
    key = next(c for c in parse_candidates(seed) if c.curve == CURVE_ED25519)
    entry = wallets.guide_for(chains.by_id("stellar"), key).formats[0]
    assert entry.value not in repr(entry)


# --------------------------------------------------------------------------
# Polkadot keystore
# --------------------------------------------------------------------------


def test_polkadot_keystore_structure():
    from s70 import keystore_polkadot

    seed = hashlib.sha256(b"keystore").digest()
    document = keystore_polkadot.build_keystore(seed, "Recovered")

    assert document["encoding"]["content"] == ["pkcs8", "ed25519"]
    # Written unencrypted so Talisman imports it without a passphrase.
    assert document["encoding"]["type"] == ["none"]
    assert document["encoding"]["version"] == "3"

    encoded = base64.b64decode(document["encoded"])
    # header(16) + secretKey(64) + divider(5) + publicKey(32)
    assert len(encoded) == 16 + 64 + 5 + 32


def test_polkadot_keystore_holds_the_right_key():
    """Read the keystore back the way polkadot-js would."""
    from s70 import keystore_polkadot

    seed = hashlib.sha256(b"keystore-roundtrip").digest()
    public = ed25519_public_from_seed(seed)
    document = keystore_polkadot.build_keystore(seed, "Recovered")

    plaintext = base64.b64decode(document["encoded"])
    header = keystore_polkadot.PKCS8_HEADER
    divider = keystore_polkadot.PKCS8_DIVIDER

    assert plaintext.startswith(header)
    secret_key = plaintext[len(header) : len(header) + 64]
    assert plaintext[len(header) + 64 : len(header) + 64 + len(divider)] == divider
    assert plaintext[len(header) + 64 + len(divider) :] == public

    # polkadot-js stores the 64-byte libsodium secret key, not the 32-byte seed.
    assert secret_key == seed + public


def test_polkadot_keystore_rejects_a_bad_seed_length():
    from s70 import keystore_polkadot
    from s70.errors import S70Error

    with pytest.raises(S70Error, match="32 bytes"):
        keystore_polkadot.build_keystore(bytes(16), "x")


def test_polkadot_keystore_is_owner_only(tmp_path):
    """It is a plaintext private key: it must never touch disk world-readable."""
    import os
    import stat

    from s70 import keystore_polkadot

    path = keystore_polkadot.write_keystore(tmp_path / "ks.json", bytes(32), "x")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_polkadot_keystore_refuses_to_overwrite(tmp_path):
    from s70 import keystore_polkadot
    from s70.errors import S70Error

    path = tmp_path / "ks.json"
    path.write_text("existing")
    with pytest.raises(S70Error, match="refusing to overwrite"):
        keystore_polkadot.write_keystore(path, bytes(32), "x")


# --------------------------------------------------------------------------
# phase 2 guards
# --------------------------------------------------------------------------


def test_transfer_rejects_a_destination_on_the_wrong_chain():
    from s70 import txn
    from s70.errors import S70Error

    with pytest.raises(S70Error, match="not a valid"):
        txn.inspect("stellar", "GA" + "A" * 54, "0x" + "0" * 40)


def test_transfer_refuses_unsupported_chains():
    from s70 import txn
    from s70.errors import UnsupportedChainError

    for chain_id in ("evm", "polkadot", "canton"):
        with pytest.raises(UnsupportedChainError):
            txn.module_for(chain_id)


def test_sui_signing_digest_is_intent_prefixed():
    """Sui signs blake2b(intent || bcs), not the bytes themselves."""
    import hashlib as _hashlib

    from s70.txn import sui_tx

    payload = b"\x01\x02\x03"
    expected = _hashlib.blake2b(
        bytes([0, 0, 0]) + payload, digest_size=32
    ).digest()
    assert sui_tx.sui_signing_digest(payload) == expected
    assert sui_tx.sui_signing_digest(payload) != _hashlib.blake2b(
        payload, digest_size=32
    ).digest()


def test_sui_serialized_signature_layout():
    from s70.errors import S70Error
    from s70.txn import sui_tx

    signature = bytes(64)
    public = bytes(range(32))
    serialized = base64.b64decode(sui_tx.serialize_signature(signature, public, 0x00))
    assert len(serialized) == 1 + 64 + 32
    assert serialized[0] == 0x00
    assert serialized[65:] == public

    with pytest.raises(S70Error, match="64 bytes"):
        sui_tx.serialize_signature(b"short", public, 0x00)


def test_job_file_round_trip(tmp_path):
    from s70.txn.job import Asset, Precondition, TransferJob

    job = TransferJob(
        chain="stellar",
        source_address="G" + "A" * 55,
        destination_address="G" + "B" * 55,
        network={"sequence": "1"},
        assets=[Asset(symbol="XLM", amount="1.5", identifier="native")],
        preconditions=[Precondition("exists", True, "fine")],
    )
    path = job.write(tmp_path / "job.json")
    reloaded = TransferJob.read(path)

    assert reloaded.chain == job.chain
    assert reloaded.assets[0].symbol == "XLM"
    assert reloaded.preconditions[0].satisfied is True
    assert reloaded.ready


def test_job_with_blocking_precondition_is_not_ready():
    from s70.txn.job import Precondition, TransferJob

    job = TransferJob(
        chain="xrpl",
        source_address="r1",
        destination_address="r2",
        preconditions=[
            Precondition("too soon", False, "wait 256 ledgers", blocking=True),
            Precondition("cosmetic", False, "whatever", blocking=False),
        ],
    )
    assert not job.ready
    assert len(job.blocking_failures) == 1
