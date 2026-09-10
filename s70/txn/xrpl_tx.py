"""XRPL: close the account with ``AccountDelete``.

``AccountDelete`` sends the entire remaining XRP balance minus the fee to the
destination and removes the account, so it *is* the whole sweep -- there is
normally no separate Payment step. It also recovers the 1 XRP base reserve
that a partial sweep would have to leave behind, at the cost of a 0.2 XRP fee
that is burned. Net, deleting beats sweeping by about 0.8 XRP.

It is blocked by owned ledger objects, though, and some of those cannot be
removed unilaterally. So the flow is: try to delete; if blocked, say exactly
which objects are in the way; and if they cannot be cleared, fall back to a
partial Payment that leaves the reserve behind.

Two details that reliably bite:

* The fee must be **at least the owner reserve**, currently 0.2 XRP =
  200000 drops -- not the usual 10 drops. It is read from ``server_state``
  rather than hardcoded, but defaults defensively.
* ``Sequence + 256`` must be below the current ledger index, so an account
  younger than ~256 ledgers (~15 minutes) simply cannot be deleted yet.

Signing here does **not** go through ``Wallet.from_seed``. A recovered
32-byte private key has no seed -- the seed-to-key derivation is one-way --
so we drive xrpl-py's low-level codec directly, which accepts a private key.
"""

from __future__ import annotations

from decimal import Decimal

from s70.chains.xrpl import SPEC
from s70.errors import MissingDependencyError, S70Error
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, KeyMaterial
from s70.txn.job import Asset, Precondition, SignedBundle, TransferJob

CHAIN_ID = "xrpl"

MAINNET_JSON_RPC = "https://s1.ripple.com:51234/"

#: Owner reserve as of the December 2024 reduction. Read from the network when
#: possible; this is the fallback.
DEFAULT_ACCOUNT_DELETE_FEE_DROPS = 200_000

#: AccountDelete requires Sequence + 256 < current ledger index.
SEQUENCE_LEDGER_GAP = 256

#: LastLedgerSequence offset. xrpl-py's autofill uses +20 (~80s), which is not
#: enough time to move a blob to an offline machine and back.
LAST_LEDGER_OFFSET = 200

DROPS_PER_XRP = Decimal(10) ** 6

#: Ledger object types that XRPL removes automatically with the account.
AUTO_DELETED = {"Offer", "Ticket", "SignerList", "DepositPreauth", "DID"}

#: Types that block deletion and that this tool can clear.
CLEARABLE = {"RippleState", "Check"}


def _require_sdk():
    try:
        import xrpl
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError("xrpl-py", "XRPL transaction building") from exc
    return xrpl


# --------------------------------------------------------------------------
# online phase
# --------------------------------------------------------------------------


def inspect(source: str, destination: str, *, rpc_url: str | None = None) -> TransferJob:
    """Read account state and work out whether AccountDelete can succeed."""
    _require_sdk()
    from xrpl.clients import JsonRpcClient
    from xrpl.models.requests import (
        AccountInfo,
        AccountLines,
        AccountObjects,
        Ledger,
        ServerState,
    )

    endpoint = rpc_url or MAINNET_JSON_RPC
    client = JsonRpcClient(endpoint)

    def call(request):
        response = client.request(request)
        if not response.is_successful():
            raise S70Error(f"{type(request).__name__} failed on {endpoint}: {response.result}")
        return response.result

    info = call(AccountInfo(account=source, ledger_index="validated"))
    account_data = info["account_data"]

    ledger = call(Ledger(ledger_index="validated"))
    current_ledger = int(ledger["ledger_index"])

    try:
        state = call(ServerState())
        reserve_inc = int(
            state["state"]["validated_ledger"].get("reserve_inc", DEFAULT_ACCOUNT_DELETE_FEE_DROPS)
        )
        reserve_base = int(state["state"]["validated_ledger"].get("reserve_base", 1_000_000))
    except Exception:  # noqa: BLE001 - some public nodes restrict server_state
        reserve_inc = DEFAULT_ACCOUNT_DELETE_FEE_DROPS
        reserve_base = 1_000_000

    objects = call(AccountObjects(account=source, ledger_index="validated", limit=400))
    owned = objects.get("account_objects", [])

    try:
        lines = call(AccountLines(account=source, ledger_index="validated"))
        trustlines = lines.get("lines", [])
    except S70Error:
        trustlines = []

    destination_ok = True
    try:
        call(AccountInfo(account=destination, ledger_index="validated"))
    except S70Error:
        destination_ok = False

    balance_drops = int(account_data["Balance"])
    sequence = int(account_data["Sequence"])

    assets: list[Asset] = [
        Asset(
            symbol="XRP",
            amount=str(Decimal(balance_drops) / DROPS_PER_XRP),
            identifier="native",
            decimals=6,
            extra={"drops": str(balance_drops)},
        )
    ]

    clearable_lines = []
    blocked_lines = []
    for line in trustlines:
        amount = Decimal(line.get("balance", "0"))
        entry = Asset(
            symbol=line.get("currency", "?"),
            amount=str(amount),
            identifier=f"{line.get('currency')}:{line.get('account')}",
            extra={
                "issuer": line.get("account"),
                "limit": line.get("limit"),
                "freeze_peer": line.get("freeze_peer", False),
                "no_ripple": line.get("no_ripple", False),
            },
        )
        if amount < 0:
            entry.blocked = (
                "negative balance -- this account owes the issuer, and the trustline "
                "cannot be closed until the debt is settled"
            )
            blocked_lines.append(entry)
        elif line.get("freeze_peer"):
            entry.blocked = "issuer has frozen this trustline"
            blocked_lines.append(entry)
        else:
            clearable_lines.append(entry)
        assets.append(entry)

    blocking_objects: dict[str, int] = {}
    for obj in owned:
        kind = obj.get("LedgerEntryType", "Unknown")
        if kind in AUTO_DELETED:
            continue
        if kind == "RippleState":
            continue  # accounted for via account_lines
        blocking_objects[kind] = blocking_objects.get(kind, 0) + 1

    sponsoring = int(account_data.get("SponsoringOwnerCount", 0) or 0) + int(
        account_data.get("SponsoringAccountCount", 0) or 0
    )

    sequence_ready = sequence + SEQUENCE_LEDGER_GAP < current_ledger
    unclearable = {
        kind: count for kind, count in blocking_objects.items() if kind not in CLEARABLE
    }

    preconditions = [
        Precondition(
            "account old enough to delete",
            sequence_ready,
            f"Sequence {sequence} + {SEQUENCE_LEDGER_GAP} must be below the current "
            f"ledger {current_ledger}. "
            + (
                "satisfied"
                if sequence_ready
                else f"deletable after ledger {sequence + SEQUENCE_LEDGER_GAP} "
                f"(~{max(0, (sequence + SEQUENCE_LEDGER_GAP - current_ledger)) * 4 // 60} min)"
            ),
        ),
        Precondition(
            "destination exists and is funded",
            destination_ok,
            f"{destination} must already exist (tecNO_DST otherwise)",
        ),
        Precondition(
            "not sponsoring other accounts",
            sponsoring == 0,
            f"sponsoring count = {sponsoring} (tecHAS_OBLIGATIONS)",
        ),
        Precondition(
            "no unclearable owned objects",
            not unclearable,
            ", ".join(f"{count}x {kind}" for kind, count in unclearable.items()) or "none",
        ),
        Precondition(
            "no negative or frozen trustlines",
            not blocked_lines,
            ", ".join(a.symbol for a in blocked_lines) or "none",
        ),
        Precondition(
            "owned object count under 1000",
            len(owned) <= 1000,
            f"{len(owned)} objects (tefTOO_BIG above 1000)",
        ),
        Precondition(
            "balance covers the delete fee",
            balance_drops > reserve_inc,
            f"balance {balance_drops} drops vs fee {reserve_inc} drops",
        ),
    ]

    can_delete = all(p.satisfied for p in preconditions if p.blocking)

    plan: list[str] = []
    for entry in clearable_lines:
        if Decimal(entry.amount) > 0:
            plan.append(f"pay {entry.amount} {entry.symbol} to {destination}")
        plan.append(f"clear the {entry.symbol} trustline (TrustSet limit 0)")
    if can_delete:
        net = Decimal(balance_drops - reserve_inc) / DROPS_PER_XRP
        plan.append(
            f"AccountDelete -> sends ~{net} XRP to {destination} and closes the account"
        )
    else:
        spendable = Decimal(balance_drops - reserve_base - 10) / DROPS_PER_XRP
        plan.append(
            f"AccountDelete is blocked, so fall back to a Payment of ~{spendable} XRP, "
            f"leaving the {Decimal(reserve_base) / DROPS_PER_XRP} XRP base reserve behind"
        )

    warnings: list[str] = []
    if unclearable:
        warnings.append(
            "These owned objects block deletion and must be removed manually: "
            + ", ".join(f"{count}x {kind}" for kind, count in unclearable.items())
            + ". Checks need CheckCancel, escrows need EscrowFinish/EscrowCancel (which "
            "may be impossible unilaterally), payment channels need PaymentChannelClaim "
            "with tfClose, and every NFT must be burned individually."
        )
    warnings.append(
        f"The AccountDelete fee ({reserve_inc} drops) is burned, not sent. The "
        f"{reserve_base} drop base reserve is recovered."
    )

    return TransferJob(
        chain=CHAIN_ID,
        source_address=source,
        destination_address=destination,
        network={
            "endpoint": endpoint,
            "sequence": sequence,
            "current_ledger": current_ledger,
            "last_ledger_sequence": current_ledger + LAST_LEDGER_OFFSET,
            "delete_fee_drops": str(reserve_inc),
            "reserve_base_drops": str(reserve_base),
            "balance_drops": str(balance_drops),
            "can_delete": can_delete,
            "owned_object_count": len(owned),
        },
        assets=assets,
        preconditions=preconditions,
        warnings=warnings,
        plan=plan,
        ttl_seconds=LAST_LEDGER_OFFSET * 4,
        ttl_note=(
            f"LastLedgerSequence is set to {current_ledger + LAST_LEDGER_OFFSET}, roughly "
            f"{LAST_LEDGER_OFFSET * 4 // 60} minutes from inspection. After that the blob "
            "is permanently invalid, though it is safe to resubmit before then."
        ),
    )


# --------------------------------------------------------------------------
# offline phase
# --------------------------------------------------------------------------


def _xrpl_key_pair(key: KeyMaterial) -> tuple[str, str]:
    """Return (public_key_hex, private_key_hex) in XRPL's 33-byte forms."""
    if key.curve == CURVE_ED25519:
        public = "ED" + key.public_key.hex().upper()
        private = "ED" + key.scalar.reveal().hex().upper()
    elif key.curve == CURVE_SECP256K1:
        public = key.compressed_public_key.hex().upper()
        private = "00" + key.scalar.reveal().hex().upper()
    else:  # pragma: no cover
        raise S70Error(f"unsupported curve for XRPL: {key.curve}")
    return public, private


def _sign_transaction(transaction, public_key: str, private_key: str) -> str:
    """Sign a transaction with a raw private key, returning the tx_blob hex.

    This is what ``xrpl.transaction.sign`` does internally, minus the Wallet
    wrapper -- which we cannot use, because a recovered private key has no
    recoverable seed.
    """
    from xrpl.core import binarycodec, keypairs

    payload = transaction.to_xrpl()
    payload["SigningPubKey"] = public_key
    signing_blob = binarycodec.encode_for_signing(payload)
    payload["TxnSignature"] = keypairs.sign(bytes.fromhex(signing_blob), private_key)
    return binarycodec.encode(payload)


def sign(job: TransferJob, key: KeyMaterial) -> SignedBundle:
    """Build and sign the teardown plus AccountDelete offline."""
    _require_sdk()
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.models.transactions import AccountDelete, Payment, TrustSet
    from xrpl.models.transactions.trust_set import TrustSetFlag

    public_key, private_key = _xrpl_key_pair(key)

    source = job.source_address

    # Refuse a key that does not control the account being deleted. Every
    # other signer in this package does the same check; XRPL needs it most,
    # because the payload is AccountDelete.
    derived = SPEC.addresses_for(key)
    if source not in derived:
        raise S70Error(
            f"this key controls {derived[0] if derived else '<no address>'} but the "
            f"job is for {source} -- refusing to sign"
        )

    destination = job.destination_address
    sequence = int(job.network["sequence"])
    last_ledger = int(job.network["last_ledger_sequence"])
    delete_fee = str(job.network["delete_fee_drops"])

    transactions = []
    summary: list[str] = []
    offset = 0

    # Clear IOU balances and trustlines first -- each is its own transaction.
    for asset in job.assets:
        if asset.identifier == "native" or asset.blocked:
            continue
        issuer = asset.extra.get("issuer")
        currency = asset.symbol
        amount = Decimal(asset.amount)

        if amount > 0:
            transactions.append(
                Payment(
                    account=source,
                    destination=destination,
                    amount=IssuedCurrencyAmount(
                        currency=currency, issuer=issuer, value=str(amount)
                    ),
                    sequence=sequence + offset,
                    fee="12",
                    last_ledger_sequence=last_ledger,
                )
            )
            summary.append(f"pay {amount} {currency} to {destination}")
            offset += 1

        transactions.append(
            TrustSet(
                account=source,
                limit_amount=IssuedCurrencyAmount(
                    currency=currency, issuer=issuer, value="0"
                ),
                sequence=sequence + offset,
                fee="12",
                last_ledger_sequence=last_ledger,
                flags=TrustSetFlag.TF_CLEAR_NO_RIPPLE,
            )
        )
        summary.append(f"clear the {currency} trustline")
        offset += 1

    if job.network.get("can_delete"):
        transactions.append(
            AccountDelete(
                account=source,
                destination=destination,
                sequence=sequence + offset,
                # Hardcoded from the job rather than autofilled: a standard
                # 10-drop fee gets telINSUF_FEE_P.
                fee=delete_fee,
                last_ledger_sequence=last_ledger,
            )
        )
        summary.append(f"AccountDelete -> {destination} (closes the account)")
    else:
        balance = int(job.network["balance_drops"])
        reserve = int(job.network["reserve_base_drops"])
        send = balance - reserve - 12
        if send <= 0:
            raise S70Error(
                f"balance {balance} drops does not exceed the {reserve} drop reserve "
                "plus fee -- there is nothing to sweep"
            )
        transactions.append(
            Payment(
                account=source,
                destination=destination,
                amount=str(send),
                sequence=sequence + offset,
                fee="12",
                last_ledger_sequence=last_ledger,
            )
        )
        summary.append(
            f"partial sweep: pay {Decimal(send) / DROPS_PER_XRP} XRP to {destination} "
            f"(AccountDelete was blocked, so the reserve stays behind)"
        )

    blobs = [_sign_transaction(tx, public_key, private_key) for tx in transactions]

    return SignedBundle(
        chain=CHAIN_ID,
        blobs=blobs,
        encoding="hex",
        submit_command=(
            "curl -X POST https://s1.ripple.com:51234/ -H 'Content-Type: application/json' "
            '-d \'{"method":"submit","params":[{"tx_blob":"<HEX_BLOB>","fail_hard":false}]}\''
        ),
        submit_notes=[
            f"There {'is' if len(blobs) == 1 else 'are'} {len(blobs)} blob(s). Submit them "
            "in order; each depends on the previous one's sequence number.",
            "The same blob is safe to resubmit -- XRPL's docs recommend persisting it "
            "precisely so a failed submission can be retried.",
            "Verify before submitting: paste the blob into an XRPL transaction decoder "
            "and confirm the Account, Destination and Amount.",
            f"Every blob expires at ledger {last_ledger}. After that it is permanently "
            "invalid and you must re-inspect.",
        ],
        summary=summary,
        expires_note=f"Invalid after ledger {last_ledger}.",
    )
