"""Shared test fixtures.

The synthetic backup generator lives here rather than in ``s70`` itself: it is
test scaffolding, not something the shipped tool needs. It writes a file in the
real backup schema, encrypted to a throwaway RSA key, covering one wallet per
chain plus the awkward paths -- a tampered key, a chain with no offline address
derivation, and a share with no recorded address at all.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from s70 import backup as backup_mod
from s70.chains import Status
from s70.codecs import b58, ss58, strkey
from s70.keymaterial import (
    PKCS8_ED25519_HEADER,
    SECP256K1_N,
    ed25519_public_from_seed,
    secp256k1_public_from_scalar,
)
from s70.session import RecoverySession

#: Small on purpose: these tests generate a keypair per backup, and 4096-bit
#: RSA keygen dominates the runtime of the whole suite.
RSA_BITS = 2048


#: This tool's chain id -> the ``ch-<SLIP-44>`` a real backup writes. Kept here
#: rather than imported from s70.chains so the fixtures pin the mapping instead
#: of agreeing with whatever the code currently believes.
CHAIN_IDS = {
    "evm": "ch-60",
    "xrpl": "ch-144",
    "stellar": "ch-148",
    "polkadot": "ch-354",
    "solana": "ch-501",
    "aptos": "ch-637",
    "sui": "ch-784",
    "canton": "ch-6767",
    "radix": "ch-1022",
}

#: ``key_type`` as the backup spells it, per curve.
KEY_TYPES = {"ed25519": "EDDSA_ED25519", "secp256k1": "ECDSA_SECP256k1"}


@dataclass
class SyntheticWallet:
    name: str
    chain_id: str
    plaintext: bytes
    address: str | None
    expected_status: Status
    #: How the plaintext is encoded, so a failure says which path broke.
    encoding: str
    #: Curve key for KEY_TYPES, or "" to omit key_type from the file.
    curve: str = ""
    #: False to omit metadata.chain_id, exercising shape-only detection.
    declare_chain_id: bool = True


def _pkcs8_ed25519(seed: bytes) -> bytes:
    return PKCS8_ED25519_HEADER + seed


def valid_secp256k1_scalar(source: bytes) -> bytes:
    """Coerce arbitrary bytes into a valid, in-range secp256k1 scalar."""
    value = int.from_bytes(source, "big") % (SECP256K1_N - 1) + 1
    return value.to_bytes(32, "big")


def build_synthetic_wallets() -> list[SyntheticWallet]:
    """One wallet per chain, deliberately covering every awkward path."""
    seeds = [hashlib.sha256(f"s70-test-{i}".encode()).digest() for i in range(12)]
    out: list[SyntheticWallet] = []

    # EVM -- secp256k1, raw 32-byte plaintext.
    evm_scalar = valid_secp256k1_scalar(seeds[0])
    evm_public = secp256k1_public_from_scalar(evm_scalar)
    from s70.chains.evm import to_checksum_address
    from s70.codecs.hashes import keccak256

    out.append(
        SyntheticWallet(
            "Treasury EVM",
            "evm",
            evm_scalar,
            to_checksum_address(keccak256(evm_public)[-20:]),
            Status.VERIFIED,
            "raw 32-byte scalar",
            curve="secp256k1",
        )
    )

    # Solana -- Ed25519, 64-byte seed||public plaintext.
    sol_seed = seeds[1]
    sol_public = ed25519_public_from_seed(sol_seed)
    out.append(
        SyntheticWallet(
            "Solana Main",
            "solana",
            sol_seed + sol_public,
            b58.encode(sol_public),
            Status.VERIFIED,
            "Ed25519 seed||public (64 bytes)",
            curve="ed25519",
        )
    )

    # Aptos -- Ed25519, PKCS#8 plaintext, legacy authentication key.
    apt_seed = seeds[2]
    apt_public = ed25519_public_from_seed(apt_seed)
    from s70.codecs.hashes import sha3_256

    out.append(
        SyntheticWallet(
            "Aptos Main",
            "aptos",
            _pkcs8_ed25519(apt_seed),
            "0x" + sha3_256(apt_public + b"\x00").hex(),
            Status.VERIFIED,
            "PKCS#8 Ed25519 (48 bytes)",
            curve="ed25519",
        )
    )

    # Sui -- Ed25519, raw 32 bytes. Same address *shape* as Aptos, which is
    # the point: detection must separate them by derivation, not by regex.
    sui_seed = seeds[3]
    sui_public = ed25519_public_from_seed(sui_seed)
    from s70.codecs.hashes import blake2b_256

    out.append(
        SyntheticWallet(
            "Sui Main",
            "sui",
            sui_seed,
            "0x" + blake2b_256(b"\x00" + sui_public).hex(),
            Status.VERIFIED,
            "raw 32-byte scalar",
            curve="ed25519",
            # No chain_id: Aptos and Sui share an address shape, so this one
            # can only be resolved by deriving both and comparing.
            declare_chain_id=False,
        )
    )

    # Stellar -- Ed25519, raw 32 bytes.
    xlm_seed = seeds[4]
    out.append(
        SyntheticWallet(
            "Stellar Main",
            "stellar",
            xlm_seed,
            strkey.encode_ed25519_public_key(ed25519_public_from_seed(xlm_seed)),
            Status.VERIFIED,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    # Polkadot -- Ed25519, raw 32 bytes. Base58 like Solana, distinguished by
    # the SS58 version byte and checksum.
    dot_seed = seeds[5]
    out.append(
        SyntheticWallet(
            "Polkadot Main",
            "polkadot",
            dot_seed,
            ss58.encode(ed25519_public_from_seed(dot_seed), ss58.PREFIX_POLKADOT),
            Status.VERIFIED,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    # XRPL -- secp256k1 derived key, raw 32 bytes.
    xrp_scalar = valid_secp256k1_scalar(seeds[6])
    from s70.chains.xrpl import account_id_to_address
    from s70.codecs.hashes import hash160
    from s70.keymaterial import compress_secp256k1

    xrp_public = secp256k1_public_from_scalar(xrp_scalar)
    out.append(
        SyntheticWallet(
            "XRPL Main",
            "xrpl",
            xrp_scalar,
            account_id_to_address(hash160(compress_secp256k1(xrp_public))),
            Status.VERIFIED,
            "raw 32-byte scalar",
            curve="secp256k1",
        )
    )

    # A wallet with no recorded address. Exercises the "nothing to check
    # against" path, which must still recover and display the key.
    out.append(
        SyntheticWallet(
            "Solana No Address",
            "solana",
            seeds[7],
            None,
            Status.NO_ADDRESS,
            "raw 32-byte Ed25519 seed",
            # No key_type either: nothing settles the curve, so both readings
            # are offered and the UI has to say which one it picked.
            curve="",
        )
    )

    # Canton -- a party id built the way the tool believes Canton builds them.
    # The hash purpose is spelled out here rather than imported, so that
    # changing the constant in s70 breaks this test instead of moving with it.
    canton_seed = seeds[8]
    canton_public = ed25519_public_from_seed(canton_seed)
    canton_fingerprint = "1220" + hashlib.sha256(
        (12).to_bytes(4, "big") + canton_public
    ).hexdigest()
    out.append(
        SyntheticWallet(
            "Canton Party",
            "canton",
            canton_seed,
            f"testparty::{canton_fingerprint}",
            Status.VERIFIED,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    # A Canton party id the tool cannot reproduce. Canton is verifiable, so
    # this is a MISMATCH -- a check that ran and failed -- and must never be
    # reported as a check that could not be run.
    out.append(
        SyntheticWallet(
            "Canton Foreign Scheme",
            "canton",
            seeds[8],
            "otherparty::1220" + hashlib.sha256(b"not-our-scheme").hexdigest(),
            Status.MISMATCH,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    # An unsupported chain, to check the key is still handed over rather than
    # withheld or mis-detected as something we do support.
    out.append(
        SyntheticWallet(
            "Radix Main",
            "radix",
            seeds[9],
            "account_rdx12" + "8" * 53,
            Status.UNSUPPORTED,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    # A Substrate account whose Ed25519 reading does not reproduce the recorded
    # address -- in the field this means sr25519. The tool must refuse to write
    # a keystore from it, because the file would import a different account.
    out.append(
        SyntheticWallet(
            "Polkadot Sr25519",
            "polkadot",
            seeds[5],
            ss58.encode(ed25519_public_from_seed(seeds[11]), ss58.PREFIX_POLKADOT),
            Status.MISMATCH,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    # A key whose recorded address is simply wrong, to check MISMATCH is
    # reported rather than silently accepted.
    bad_seed = seeds[10]
    out.append(
        SyntheticWallet(
            "Tampered Stellar",
            "stellar",
            bad_seed,
            strkey.encode_ed25519_public_key(ed25519_public_from_seed(seeds[11])),
            Status.MISMATCH,
            "raw 32-byte scalar",
            curve="ed25519",
        )
    )

    return out


def generate_backup(
    path: str | Path,
    *,
    rsa_bits: int = RSA_BITS,
    wallet_provider: str = "S70 Test",
) -> tuple[Path, list[SyntheticWallet]]:
    """Write a synthetic backup file in the real schema."""
    path = Path(path).expanduser()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    public_key = private_key.public_key()

    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=_hashes.SHA256()),
        algorithm=_hashes.SHA256(),
        label=None,
    )

    recovery_spki_b64 = base64.b64encode(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")

    synthetic = build_synthetic_wallets()
    keys: list[dict[str, Any]] = []
    for wallet in synthetic:
        ciphertext = public_key.encrypt(wallet.plaintext, oaep)
        metadata: dict[str, Any] = {}
        if wallet.address is not None:
            metadata["address"] = wallet.address
        if wallet.declare_chain_id and wallet.chain_id in CHAIN_IDS:
            metadata["chain_id"] = CHAIN_IDS[wallet.chain_id]
        entry: dict[str, Any] = {
            "key_name": wallet.name,
            "shares": [
                {
                    "metadata": metadata,
                    "encryption": {
                        "ciphersuite": f"RSA-{rsa_bits}-OAEP-SHA256",
                        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                        "original_sha256": base64.b64encode(
                            hashlib.sha256(wallet.plaintext).digest()
                        ).decode("ascii"),
                        # Real backups record the key the share was encrypted
                        # to; RecoverySession.open checks it before decrypting.
                        "public_key": recovery_spki_b64,
                    },
                }
            ],
        }
        if wallet.curve:
            entry["key_type"] = KEY_TYPES[wallet.curve]
        keys.append(entry)

    recovery_key_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    document = {
        "version": "1.0",
        "wallet_provider": wallet_provider,
        "recovery_key": base64.b64encode(recovery_key_der).decode("ascii"),
        "keys": keys,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass
    return path, synthetic


@pytest.fixture(scope="session")
def synthetic(tmp_path_factory) -> tuple[Path, list[SyntheticWallet]]:
    """A generated backup, shared across the suite -- RSA keygen is slow."""
    path = tmp_path_factory.mktemp("s70") / "backup.json"
    return generate_backup(path, rsa_bits=RSA_BITS)


@pytest.fixture
def session(synthetic) -> RecoverySession:
    path, _ = synthetic
    return RecoverySession.open(backup_mod.load(path))
