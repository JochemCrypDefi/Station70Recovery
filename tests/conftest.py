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


@dataclass
class SyntheticWallet:
    name: str
    chain_id: str
    plaintext: bytes
    address: str | None
    expected_status: Status
    #: How the plaintext is encoded, so a failure says which path broke.
    encoding: str


def _pkcs8_ed25519(seed: bytes) -> bytes:
    return PKCS8_ED25519_HEADER + seed


def valid_secp256k1_scalar(source: bytes) -> bytes:
    """Coerce arbitrary bytes into a valid, in-range secp256k1 scalar."""
    value = int.from_bytes(source, "big") % (SECP256K1_N - 1) + 1
    return value.to_bytes(32, "big")


# Kept under the old private name too: the wallet builders below call it.
_valid_secp256k1_scalar = valid_secp256k1_scalar


def build_synthetic_wallets() -> list[SyntheticWallet]:
    """One wallet per chain, deliberately covering every awkward path."""
    seeds = [hashlib.sha256(f"s70-test-{i}".encode()).digest() for i in range(12)]
    out: list[SyntheticWallet] = []

    # EVM -- secp256k1, raw 32-byte plaintext.
    evm_scalar = _valid_secp256k1_scalar(seeds[0])
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
        )
    )

    # XRPL -- secp256k1 derived key, raw 32 bytes.
    xrp_scalar = _valid_secp256k1_scalar(seeds[6])
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
        )
    )

    # Canton -- deliberately given a fingerprint we cannot reproduce, so the
    # test asserts the UNVERIFIABLE path rather than a fake success.
    canton_seed = seeds[8]
    out.append(
        SyntheticWallet(
            "Canton Party",
            "canton",
            canton_seed,
            "testparty::1220" + hashlib.sha256(b"not-our-scheme").hexdigest(),
            Status.UNVERIFIABLE,
            "raw 32-byte scalar",
        )
    )

    # An unsupported chain, to check the key is still handed over rather than
    # withheld or mis-detected as something we do support.
    out.append(
        SyntheticWallet(
            "Radix Main",
            "unsupported",
            seeds[9],
            "account_rdx12" + "8" * 53,
            Status.UNSUPPORTED,
            "raw 32-byte scalar",
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

    synthetic = build_synthetic_wallets()
    keys: list[dict[str, Any]] = []
    for wallet in synthetic:
        ciphertext = public_key.encrypt(wallet.plaintext, oaep)
        metadata: dict[str, Any] = {}
        if wallet.address is not None:
            metadata["address"] = wallet.address
        keys.append(
            {
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
                        },
                    }
                ],
            }
        )

    recovery_key_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    document = {
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
