"""Sui: sign transaction bytes produced by the ``sui`` CLI.

This chain is handled differently from the others, deliberately.

Sui disabled JSON-RPC on Foundation mainnet fullnodes in mid-2025, and the
Python SDK (pysui) removed its legacy client and rewrote its transaction
builder across several releases in quick succession. Building a PTB from
Python and pinning the exact object references would mean writing a lot of
code against an API surface that is both moving and, for the "sweep every
coin" case, missing a documented equivalent of the old ``payAllSui``.

Sui's signing scheme, by contrast, is short, stable and fully specified:

    digest    = blake2b_256( intent(3 bytes) || bcs(TransactionData) )
    signature = ed25519_sign(secret_key, digest)
    serialized = base64( flag(1) || signature(64) || public_key(32) )

So the split here is: the ``sui`` CLI builds the transaction (online, with no
key), and this tool signs it (offline, with the key). That is also the flow
Sui's own documentation recommends for an air-gapped signer, and it means
this module has **no third-party dependency at all**.

The one rule you must not break: never sign transaction bytes you have not
decoded and read. ``sui client verify-transaction`` or
``sui keytool decode-tx`` will show you what the bytes actually do.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519

from s70.chains.sui import FLAG_ED25519, FLAG_SECP256K1
from s70.errors import S70Error
from s70.keymaterial import CURVE_ED25519, KeyMaterial
from s70.txn.job import Asset, Precondition, SignedBundle, TransferJob

CHAIN_ID = "sui"

#: Intent scope 0 (TransactionData), version 0, app id 0 (Sui).
INTENT_TRANSACTION_DATA = bytes([0, 0, 0])

MIST_PER_SUI = 10**9


def sui_signing_digest(transaction_data_bcs: bytes) -> bytes:
    """The 32-byte digest Sui actually signs."""
    return hashlib.blake2b(
        INTENT_TRANSACTION_DATA + transaction_data_bcs, digest_size=32
    ).digest()


def serialize_signature(signature: bytes, public_key: bytes, flag: int) -> str:
    """Sui's serialised signature: base64(flag || signature || public key)."""
    if len(signature) != 64:
        raise S70Error(f"Ed25519 signature must be 64 bytes, got {len(signature)}")
    return base64.b64encode(bytes([flag]) + signature + public_key).decode("ascii")


# --------------------------------------------------------------------------
# online phase
# --------------------------------------------------------------------------


def inspect(
    source: str,
    destination: str,
    *,
    rpc_url: str | None = None,
    tx_bytes: str | None = None,
) -> TransferJob:
    """Record the plan and the CLI commands that produce the unsigned bytes.

    Pass ``tx_bytes`` if you already have the base64 unsigned transaction from
    the ``sui`` CLI; otherwise the job carries the commands to generate it.
    """
    merge = (
        f"sui client merge-coin --primary-coin <GAS_COIN_ID> "
        f"--coin-to-merge <OTHER_COIN_ID> --serialize-unsigned-transaction"
    )
    transfer = (
        f"sui client transfer-sui --to {destination} --sui-coin-object-id <GAS_COIN_ID> "
        f"--gas-budget 5000000 --serialize-unsigned-transaction"
    )

    preconditions = [
        Precondition(
            "unsigned transaction bytes supplied",
            bool(tx_bytes),
            "run the sui CLI command in the plan and re-run inspect with --tx-bytes, "
            "or pass --tx-bytes directly to sign",
        ),
        Precondition(
            "destination differs from source",
            source != destination,
            "",
        ),
    ]

    return TransferJob(
        chain=CHAIN_ID,
        source_address=source,
        destination_address=destination,
        network={
            "rpc": rpc_url or "(sui CLI default)",
            "tx_bytes": tx_bytes,
        },
        assets=[
            Asset(
                symbol="SUI",
                amount="see `sui client gas`",
                identifier="0x2::sui::SUI",
                decimals=9,
                blocked=(
                    "balances are not read by this tool; the sui CLI enumerates coins "
                    "and pins their object references when it builds the transaction"
                ),
            )
        ],
        preconditions=preconditions,
        warnings=[
            "A Sui transaction pins each input coin's (id, version, digest). If anything "
            "touches those objects -- the attacker, or a staking reward landing -- the "
            "signed blob is permanently invalid. There is no timer; it is event-driven.",
            "The gas coin cannot also be an input to a transfer. Merge your coins into "
            "the gas coin first, then transfer that one coin.",
            "Hundreds of small coins will exceed the PTB input limit. Merge in batches.",
            "Never sign bytes you have not decoded. Run `sui keytool decode-tx --tx-bytes "
            "<BASE64>` and confirm the recipient before signing.",
        ],
        plan=[
            "1. List coins:  sui client gas --json",
            f"2. Merge every SUI coin into the gas coin:  {merge}",
            f"3. Build the transfer:  {transfer}",
            "4. Sign the resulting base64 bytes with:  s70 sign --job <job.json> --tx-bytes <BASE64>",
            "5. Submit:  sui client execute-signed-tx --tx-bytes <BASE64> --signatures <SIG>",
        ],
        ttl_seconds=None,
        ttl_note=(
            "Sui blobs do not expire on a clock. They expire when any input object is "
            "modified, which can happen at any moment."
        ),
    )


# --------------------------------------------------------------------------
# offline phase
# --------------------------------------------------------------------------


def sign(job: TransferJob, key: KeyMaterial, *, tx_bytes: str | None = None) -> SignedBundle:
    """Sign base64 unsigned transaction bytes with a recovered key."""
    payload = tx_bytes or job.network.get("tx_bytes")
    if not payload:
        raise S70Error(
            "no unsigned transaction bytes to sign. Build them with the sui CLI:\n"
            "  sui client transfer-sui --to <DEST> --sui-coin-object-id <COIN> "
            "--gas-budget 5000000 --serialize-unsigned-transaction\n"
            "then pass the result with --tx-bytes."
        )

    if key.curve != CURVE_ED25519:
        raise S70Error(
            "this signer supports Ed25519 Sui keys only. secp256k1 and secp256r1 Sui "
            f"accounts need a different flag byte and signing path; got {key.curve}"
        )

    try:
        transaction_data = base64.b64decode(payload, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise S70Error(f"--tx-bytes is not valid base64: {exc}") from exc

    # Confirm the key owns the address the job is about, before signing
    # anything.
    from s70.chains import sui as sui_chain

    derived = sui_chain.SPEC.addresses_for(key)
    normalized_source = sui_chain.SPEC.normalize(job.source_address)
    if derived and sui_chain.SPEC.normalize(derived[0]) != normalized_source:
        raise S70Error(
            f"this key derives {derived[0]} but the job is for {job.source_address} -- "
            "refusing to sign"
        )

    digest = sui_signing_digest(transaction_data)

    private = ed25519.Ed25519PrivateKey.from_private_bytes(key.scalar.reveal())
    signature = private.sign(digest)

    flag = FLAG_ED25519 if key.curve == CURVE_ED25519 else FLAG_SECP256K1
    serialized = serialize_signature(signature, key.public_key, flag)

    return SignedBundle(
        chain=CHAIN_ID,
        blobs=[serialized],
        encoding="base64",
        submit_command=(
            f"sui client execute-signed-tx --tx-bytes {payload} --signatures {serialized}"
        ),
        submit_notes=[
            "Decode and read the transaction before submitting: "
            f"sui keytool decode-tx --tx-bytes {payload[:32]}...",
            "The blob above is the *signature*, not the transaction. Submission needs "
            "both it and the original tx-bytes.",
            "If execution fails with an object-version error, an input coin was touched "
            "after the transaction was built. Rebuild from step 1.",
        ],
        summary=[
            f"signed {len(transaction_data)} bytes of TransactionData for {job.source_address}",
            f"signing digest: {digest.hex()}",
            f"scheme flag: 0x{flag:02x} (Ed25519)",
        ],
        expires_note=(
            "No time limit, but invalid the moment any input object is modified."
        ),
    )
