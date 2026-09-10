"""Solana: sweep SPL tokens and then the native SOL balance.

The awkward constraint here is time. A Solana blockhash is valid for about
151 blocks -- roughly **60 to 90 seconds** -- so the classic air-gap dance of
walking a USB stick to another machine will always fail. Plan for a tight
inspect-sign-submit loop on one machine, or accept that you will re-run
``inspect`` several times.

Ordering matters:

1. create the destination's associated token account, if missing
2. ``transfer_checked`` each SPL balance (never bare ``transfer`` -- checked
   validates the mint and decimals, which is what stops a wrong-decimals
   transfer)
3. ``close_account`` each drained token account, reclaiming ~0.002 SOL of rent
4. transfer the remaining SOL **last**, minus the fee

Token accounts are enumerated for both the original Token program and
Token-2022, because ``getTokenAccountsByOwner`` takes one program id at a
time and an owner can hold both.
"""

from __future__ import annotations

from decimal import Decimal

from s70.errors import MissingDependencyError, S70Error
from s70.keymaterial import CURVE_ED25519, KeyMaterial
from s70.txn.job import Asset, Precondition, SignedBundle, TransferJob

CHAIN_ID = "solana"

MAINNET_RPC = "https://api.mainnet-beta.solana.com"

LAMPORTS_PER_SOL = Decimal(10) ** 9

#: Base fee per signature.
LAMPORTS_PER_SIGNATURE = 5_000

#: Blockhash lifetime, in slots and in wall-clock seconds.
BLOCKHASH_SLOTS = 151
BLOCKHASH_TTL_SECONDS = 75


def _require_sdk():
    try:
        import solders  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError("solders", "Solana transaction building") from exc


def _require_rpc():
    try:
        import solana  # noqa: F401
        import spl.token.instructions  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError("solana", "Solana RPC access") from exc


# --------------------------------------------------------------------------
# online phase
# --------------------------------------------------------------------------


def inspect(source: str, destination: str, *, rpc_url: str | None = None) -> TransferJob:
    """Read balances, token accounts and a fresh blockhash."""
    _require_sdk()
    _require_rpc()

    from solana.rpc.api import Client
    from solders.pubkey import Pubkey
    from spl.token.constants import TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID

    endpoint = rpc_url or MAINNET_RPC
    client = Client(endpoint)

    owner = Pubkey.from_string(source)
    recipient = Pubkey.from_string(destination)

    balance = client.get_balance(owner).value
    blockhash_response = client.get_latest_blockhash()
    blockhash = str(blockhash_response.value.blockhash)
    last_valid_block_height = blockhash_response.value.last_valid_block_height

    assets: list[Asset] = [
        Asset(
            symbol="SOL",
            amount=str(Decimal(balance) / LAMPORTS_PER_SOL),
            identifier="native",
            decimals=9,
            extra={"lamports": str(balance)},
        )
    ]

    token_accounts: list[dict] = []
    for program_id in (TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID):
        from solana.rpc.types import TokenAccountOpts

        try:
            response = client.get_token_accounts_by_owner_json_parsed(
                owner, TokenAccountOpts(program_id=program_id)
            )
        except Exception as exc:  # noqa: BLE001 - one program may be unavailable
            assets.append(
                Asset(
                    symbol="?",
                    amount="0",
                    identifier=str(program_id),
                    blocked=f"could not enumerate token accounts: {exc}",
                )
            )
            continue

        for item in response.value:
            info = item.account.data.parsed["info"]
            token_amount = info["tokenAmount"]
            raw_amount = int(token_amount["amount"])
            if raw_amount == 0:
                continue

            mint = info["mint"]
            decimals = int(token_amount["decimals"])

            # Does the destination already have an ATA for this mint?
            from spl.token.instructions import get_associated_token_address

            dest_ata = get_associated_token_address(
                recipient, Pubkey.from_string(mint), token_program_id=program_id
            )
            dest_exists = client.get_account_info(dest_ata).value is not None

            record = {
                "mint": mint,
                "decimals": decimals,
                "amount": str(raw_amount),
                "source_account": str(item.pubkey),
                "program_id": str(program_id),
                "destination_ata": str(dest_ata),
                "destination_ata_exists": dest_exists,
            }
            token_accounts.append(record)
            assets.append(
                Asset(
                    symbol=mint[:6] + "..",
                    amount=str(Decimal(raw_amount) / (Decimal(10) ** decimals)),
                    identifier=mint,
                    decimals=decimals,
                    extra=record,
                )
            )

    signature_count = 1
    estimated_fee = LAMPORTS_PER_SIGNATURE * signature_count

    preconditions = [
        Precondition(
            "source has a positive SOL balance",
            balance > estimated_fee,
            f"{balance} lamports, need more than {estimated_fee} to cover the fee",
        ),
        Precondition(
            "destination differs from source",
            source != destination,
            "",
        ),
    ]

    plan = []
    for record in token_accounts:
        if not record["destination_ata_exists"]:
            plan.append(f"create the destination token account for mint {record['mint'][:12]}..")
        plan.append(
            f"transfer_checked {record['amount']} raw units of {record['mint'][:12]}.."
        )
        plan.append(f"close the drained token account {record['source_account'][:12]}..")
    plan.append("transfer the remaining SOL, minus the fee, last")

    return TransferJob(
        chain=CHAIN_ID,
        source_address=source,
        destination_address=destination,
        network={
            "endpoint": endpoint,
            "blockhash": blockhash,
            "last_valid_block_height": last_valid_block_height,
            "lamports": str(balance),
            "estimated_fee_lamports": str(estimated_fee),
            "token_accounts": token_accounts,
        },
        assets=assets,
        preconditions=preconditions,
        warnings=[
            f"This blockhash dies at block height {last_valid_block_height}, about "
            f"{BLOCKHASH_TTL_SECONDS} seconds after inspection. If signing and submitting "
            "will take longer than that, do not bother walking this to another machine -- "
            "re-run inspect immediately before signing.",
            "Closing a drained token account reclaims about 0.002 SOL of rent each. That "
            "is why SOL is swept last.",
            "Token-2022 mints can carry transfer fees or transfer hooks, so the amount "
            "received may be less than the amount sent.",
            "If this address was compromised rather than merely lost, a sweeper bot may "
            "take any SOL you send to cover fees. There is no fee-payer separation in "
            "this plan.",
        ],
        plan=plan,
        ttl_seconds=BLOCKHASH_TTL_SECONDS,
        ttl_note=(
            f"A Solana blockhash is valid for {BLOCKHASH_SLOTS} slots. Past that the "
            "transaction is rejected outright."
        ),
    )


# --------------------------------------------------------------------------
# offline phase
# --------------------------------------------------------------------------


def sign(job: TransferJob, key: KeyMaterial) -> SignedBundle:
    """Compile and sign the sweep offline."""
    _require_sdk()
    try:
        from spl.token.instructions import (
            CloseAccountParams,
            TransferCheckedParams,
            close_account,
            create_associated_token_account,
            transfer_checked,
        )
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError("solana", "SPL token instructions") from exc

    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.message import MessageV0
    from solders.pubkey import Pubkey
    from solders.system_program import TransferParams, transfer
    from solders.transaction import VersionedTransaction

    if key.curve != CURVE_ED25519:
        raise S70Error("Solana keys are Ed25519; got " + key.curve)

    keypair = Keypair.from_seed(key.scalar.reveal())
    if str(keypair.pubkey()) != job.source_address:
        raise S70Error(
            f"this key belongs to {keypair.pubkey()} but the job is for "
            f"{job.source_address} -- refusing to sign"
        )

    owner = keypair.pubkey()
    recipient = Pubkey.from_string(job.destination_address)

    instructions = []
    summary: list[str] = []

    for record in job.network.get("token_accounts", []):
        program_id = Pubkey.from_string(record["program_id"])
        mint = Pubkey.from_string(record["mint"])
        source_account = Pubkey.from_string(record["source_account"])
        destination_ata = Pubkey.from_string(record["destination_ata"])

        if not record["destination_ata_exists"]:
            instructions.append(
                create_associated_token_account(
                    payer=owner, owner=recipient, mint=mint, token_program_id=program_id
                )
            )
            summary.append(f"create destination ATA for {record['mint'][:12]}..")

        instructions.append(
            transfer_checked(
                TransferCheckedParams(
                    program_id=program_id,
                    source=source_account,
                    mint=mint,
                    dest=destination_ata,
                    owner=owner,
                    amount=int(record["amount"]),
                    decimals=int(record["decimals"]),
                    signers=[],
                )
            )
        )
        summary.append(f"transfer {record['amount']} raw units of {record['mint'][:12]}..")

        instructions.append(
            close_account(
                CloseAccountParams(
                    program_id=program_id,
                    account=source_account,
                    dest=owner,
                    owner=owner,
                    signers=[],
                )
            )
        )
        summary.append(f"close {record['source_account'][:12]}.. and reclaim its rent")

    lamports = int(job.network["lamports"])
    fee = int(job.network["estimated_fee_lamports"])
    sweep = lamports - fee
    if sweep <= 0:
        raise S70Error(
            f"balance {lamports} lamports does not cover the {fee} lamport fee -- "
            "there is nothing to sweep"
        )

    instructions.append(
        transfer(TransferParams(from_pubkey=owner, to_pubkey=recipient, lamports=sweep))
    )
    summary.append(
        f"transfer {Decimal(sweep) / LAMPORTS_PER_SOL} SOL to {job.destination_address}"
    )

    message = MessageV0.try_compile(
        payer=owner,
        instructions=instructions,
        address_lookup_table_accounts=[],
        recent_blockhash=Hash.from_string(job.network["blockhash"]),
    )
    transaction = VersionedTransaction(message, [keypair])

    raw = bytes(transaction)
    # Cheap guard against a serialisation mismatch producing a blob that
    # deserialises to something else.
    if VersionedTransaction.from_bytes(raw) != transaction:
        raise S70Error("signed transaction failed to round-trip; refusing to emit it")

    import base64

    return SignedBundle(
        chain=CHAIN_ID,
        blobs=[base64.b64encode(raw).decode("ascii")],
        encoding="base64",
        submit_command=(
            f"curl -X POST {job.network['endpoint']} -H 'Content-Type: application/json' "
            '-d \'{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["<BASE64>",'
            '{"encoding":"base64","skipPreflight":false,"maxRetries":5}]}\''
        ),
        submit_notes=[
            f"Submit before block height {job.network['last_valid_block_height']}. "
            "After that this blob is dead and you must re-inspect and re-sign.",
            "Leave skipPreflight false -- preflight simulation is the last chance to "
            "catch a stale blockhash or a missing account before you pay a fee.",
            "Confirm with `solana confirm -v <signature>` afterwards.",
        ],
        summary=summary,
        expires_note=(
            f"Dead after block height {job.network['last_valid_block_height']} "
            f"(~{BLOCKHASH_TTL_SECONDS}s from inspection)."
        ),
    )
