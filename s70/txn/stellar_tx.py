"""Stellar: sweep everything and close the account with ``account_merge``.

``account_merge`` is the cleanest sweep of any chain here -- it sends the
entire XLM balance and deletes the account, recovering the 1 XLM base reserve
that a plain payment would have to leave behind. But it has a **high**
threshold and fails unless the account has no subentries at all, so the real
work is the ordered teardown in front of it:

1. cancel every open offer     (they are subentries, and they reserve balance)
2. delete every data entry     (also subentries)
3. for each non-native asset: pay the full balance out, then delete the trustline
4. ``account_merge``

Step 3 has a trap worth stating plainly: ``change_trust`` with ``limit=0``
fails with ``CHANGE_TRUST_INVALID_LIMIT`` if *any* balance remains -- even
dust. And ``selling_liabilities`` from an open offer reserves part of the
balance, which is why offers must be cancelled first. The order above is not
cosmetic.

The whole thing is one atomic transaction, so either the account is emptied
and closed or nothing happens. Stellar caps a transaction at 100 operations,
so accounts with many trustlines are split across several sequential
transactions with the merge in the last one.
"""

from __future__ import annotations

from decimal import Decimal

from s70.errors import MissingDependencyError, S70Error
from s70.keymaterial import CURVE_ED25519, KeyMaterial
from s70.txn.job import Asset, Precondition, SignedBundle, TransferJob

CHAIN_ID = "stellar"

HORIZON_MAINNET = "https://horizon.stellar.org"

#: Stellar's hard cap on operations per transaction.
MAX_OPS_PER_TX = 100

#: Stroops per operation. The network minimum is 100; 200 gives headroom
#: without meaningfully costing anything on a sweep.
BASE_FEE = 200

#: Transactions stay valid for an hour, which is plenty for a walk between
#: machines and, unlike Solana, is entirely our choice.
TIMEOUT_SECONDS = 3600


def _require_sdk():
    try:
        import stellar_sdk
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError("stellar-sdk", "Stellar transaction building") from exc
    return stellar_sdk


# --------------------------------------------------------------------------
# online phase
# --------------------------------------------------------------------------


def inspect(source: str, destination: str, *, rpc_url: str | None = None) -> TransferJob:
    """Read account state from Horizon and plan the teardown."""
    sdk = _require_sdk()
    horizon = rpc_url or HORIZON_MAINNET
    server = sdk.Server(horizon)

    try:
        account = server.accounts().account_id(source).call()
    except Exception as exc:  # noqa: BLE001
        raise S70Error(f"could not load {source} from {horizon}: {exc}") from exc

    try:
        offers = server.offers().for_account(source).limit(200).call()
        offer_records = offers["_embedded"]["records"]
    except Exception:  # noqa: BLE001 - an account with no offers can 404
        offer_records = []

    destination_exists = True
    try:
        server.accounts().account_id(destination).call()
    except Exception:  # noqa: BLE001
        destination_exists = False

    balances = account.get("balances", [])
    data_entries = account.get("data", {}) or {}
    flags = account.get("flags", {}) or {}

    assets: list[Asset] = []
    native_balance = Decimal("0")

    for balance in balances:
        asset_type = balance.get("asset_type")
        amount = Decimal(balance.get("balance", "0"))
        if asset_type == "native":
            native_balance = amount
            assets.append(Asset(symbol="XLM", amount=str(amount), identifier="native"))
            continue

        code = balance.get("asset_code", "?")
        issuer = balance.get("asset_issuer", "")
        selling = Decimal(balance.get("selling_liabilities", "0") or "0")
        blocked = None
        if balance.get("is_authorized") is False:
            blocked = (
                "trustline is not authorized by the issuer; the balance cannot be moved "
                "and the trustline cannot be deleted, so account_merge will fail"
            )
        assets.append(
            Asset(
                symbol=code,
                amount=str(amount),
                identifier=f"{code}:{issuer}",
                decimals=7,
                extra={
                    "asset_type": asset_type,
                    "issuer": issuer,
                    "selling_liabilities": str(selling),
                    "is_authorized": balance.get("is_authorized", True),
                    "liquidity_pool_id": balance.get("liquidity_pool_id"),
                },
                blocked=blocked,
            )
        )

    num_sponsoring = int(account.get("num_sponsoring", 0) or 0)
    num_sponsored = int(account.get("num_sponsored", 0) or 0)
    subentry_count = int(account.get("subentry_count", 0) or 0)

    non_native = [a for a in assets if a.identifier != "native"]
    unauthorized = [a for a in non_native if a.blocked]
    pool_shares = [a for a in non_native if a.extra.get("liquidity_pool_id")]

    preconditions = [
        Precondition(
            "destination account exists",
            destination_exists,
            f"{destination} must already be funded; account_merge fails with "
            "ACCOUNT_MERGE_NO_ACCOUNT otherwise",
        ),
        Precondition(
            "AUTH_IMMUTABLE not set",
            not flags.get("auth_immutable", False),
            "an account with AUTH_IMMUTABLE can never be merged",
        ),
        Precondition(
            "not sponsoring other accounts' reserves",
            num_sponsoring == 0,
            f"num_sponsoring = {num_sponsoring}; sponsorships must be revoked first "
            "(ACCOUNT_MERGE_IS_SPONSOR)",
        ),
        Precondition(
            "no unauthorized or frozen trustlines",
            not unauthorized,
            "; ".join(a.symbol for a in unauthorized) or "none",
        ),
        Precondition(
            "no liquidity pool shares",
            not pool_shares,
            "pool shares count as trustlines and must be withdrawn before the merge",
        ),
        Precondition(
            "destination differs from source",
            source != destination,
            "an account cannot be merged into itself",
        ),
        Precondition(
            "sponsored entries reviewed",
            num_sponsored == 0,
            f"num_sponsored = {num_sponsored}; entries sponsored *for* this account "
            "are removed with it, which is usually fine but worth knowing",
            blocking=False,
        ),
    ]

    op_count = len(offer_records) + len(data_entries) + 2 * len(non_native) + 1

    plan = []
    if offer_records:
        plan.append(f"cancel {len(offer_records)} open offer(s)")
    if data_entries:
        plan.append(f"delete {len(data_entries)} data entry/entries")
    for asset in non_native:
        if not asset.blocked:
            plan.append(f"pay out {asset.amount} {asset.symbol} then delete its trustline")
    plan.append(f"account_merge into {destination} (sends {native_balance} XLM and closes the account)")

    warnings = []
    if op_count > MAX_OPS_PER_TX:
        warnings.append(
            f"The teardown needs {op_count} operations but Stellar caps a transaction at "
            f"{MAX_OPS_PER_TX}. It will be split across "
            f"{(op_count + MAX_OPS_PER_TX - 1) // MAX_OPS_PER_TX} transactions that must "
            "be submitted strictly in order -- if one fails, stop and re-inspect."
        )
    warnings.append(
        f"Fee is base_fee x operations = {BASE_FEE} x {op_count} = "
        f"{BASE_FEE * op_count} stroops ({Decimal(BASE_FEE * op_count) / Decimal(10**7)} XLM)."
    )

    return TransferJob(
        chain=CHAIN_ID,
        source_address=source,
        destination_address=destination,
        network={
            "horizon": horizon,
            "network_passphrase": sdk.Network.PUBLIC_NETWORK_PASSPHRASE,
            "sequence": str(account["sequence"]),
            "base_fee": BASE_FEE,
            "subentry_count": subentry_count,
            "offers": [
                {
                    "id": str(record["id"]),
                    "selling": record.get("selling", {}),
                    "buying": record.get("buying", {}),
                }
                for record in offer_records
            ],
            "data_entries": list(data_entries.keys()),
            "native_balance": str(native_balance),
        },
        assets=assets,
        preconditions=preconditions,
        warnings=warnings,
        plan=plan,
        ttl_seconds=None,
        ttl_note=(
            "A Stellar sequence number stays valid until the account transacts, so this "
            "job does not expire on a timer. It becomes invalid the moment anything else "
            "submits a transaction from this account."
        ),
    )


# --------------------------------------------------------------------------
# offline phase
# --------------------------------------------------------------------------


def sign(job: TransferJob, key: KeyMaterial) -> SignedBundle:
    """Build and sign the teardown offline. Opens no sockets."""
    sdk = _require_sdk()

    if key.curve != CURVE_ED25519:
        raise S70Error("Stellar keys are Ed25519; got " + key.curve)

    keypair = sdk.Keypair.from_raw_ed25519_seed(key.scalar.reveal())
    if keypair.public_key != job.source_address:
        raise S70Error(
            f"this key belongs to {keypair.public_key} but the job is for "
            f"{job.source_address} -- refusing to sign"
        )

    sequence = int(job.network["sequence"])
    passphrase = job.network["network_passphrase"]
    base_fee = int(job.network.get("base_fee", BASE_FEE))
    destination = job.destination_address

    # Assemble the ordered operation list, then chunk it.
    operations: list[tuple[str, dict]] = []
    for offer in job.network.get("offers", []):
        operations.append(("cancel_offer", {"offer_id": int(offer["id"]), "selling": offer["selling"], "buying": offer["buying"]}))
    for name in job.network.get("data_entries", []):
        operations.append(("delete_data", {"name": name}))
    for asset in job.assets:
        if asset.identifier == "native" or asset.blocked:
            continue
        operations.append(("pay_out", {"asset": asset}))
        operations.append(("close_trustline", {"asset": asset}))
    operations.append(("merge", {}))

    chunks = [
        operations[i : i + MAX_OPS_PER_TX]
        for i in range(0, len(operations), MAX_OPS_PER_TX)
    ]

    blobs: list[str] = []
    summary: list[str] = []

    for chunk_index, chunk in enumerate(chunks):
        account = sdk.Account(job.source_address, sequence + chunk_index)
        builder = sdk.TransactionBuilder(
            source_account=account,
            network_passphrase=passphrase,
            base_fee=base_fee,
        )

        for kind, params in chunk:
            if kind == "cancel_offer":
                selling = _asset_from_horizon(sdk, params["selling"])
                buying = _asset_from_horizon(sdk, params["buying"])
                builder.append_manage_sell_offer_op(
                    selling=selling,
                    buying=buying,
                    amount="0",
                    price="1",
                    offer_id=params["offer_id"],
                )
                summary.append(f"cancel offer {params['offer_id']}")

            elif kind == "delete_data":
                builder.append_manage_data_op(data_name=params["name"], data_value=None)
                summary.append(f"delete data entry {params['name']!r}")

            elif kind == "pay_out":
                asset: Asset = params["asset"]
                code, issuer = asset.identifier.split(":", 1)
                builder.append_payment_op(
                    destination=destination,
                    asset=sdk.Asset(code, issuer),
                    amount=asset.amount,
                )
                summary.append(f"pay {asset.amount} {code} to {destination}")

            elif kind == "close_trustline":
                asset = params["asset"]
                code, issuer = asset.identifier.split(":", 1)
                builder.append_change_trust_op(asset=sdk.Asset(code, issuer), limit="0")
                summary.append(f"delete {code} trustline")

            elif kind == "merge":
                builder.append_account_merge_op(destination=destination)
                summary.append(f"account_merge into {destination}")

        transaction = builder.set_timeout(TIMEOUT_SECONDS).build()
        transaction.sign(keypair)
        blobs.append(transaction.to_xdr())

    return SignedBundle(
        chain=CHAIN_ID,
        blobs=blobs,
        encoding="base64-xdr",
        submit_command=(
            'curl -X POST https://horizon.stellar.org/transactions '
            '--data-urlencode "tx=<BASE64_XDR>"'
        ),
        submit_notes=[
            "Decode and read the XDR before submitting: https://lab.stellar.org/xdr/view",
            "Submit via Stellar Lab (Clear and import new -> paste XDR -> Submit) or the "
            "curl command above. Note the body is form-encoded, not JSON.",
            f"There {'is' if len(blobs) == 1 else 'are'} {len(blobs)} transaction(s). "
            "Submit them strictly in order and confirm each one succeeds before the next.",
            "The account_merge is in the final transaction. If an earlier one fails, "
            "stop and re-run `s70 inspect` -- the sequence numbers will have moved.",
        ],
        summary=summary,
        expires_note=(
            f"Valid for {TIMEOUT_SECONDS}s from signing, and invalidated immediately if "
            "anything else transacts from this account."
        ),
    )


def _asset_from_horizon(sdk, payload: dict):
    """Rebuild a stellar_sdk.Asset from Horizon's JSON representation."""
    if payload.get("asset_type") == "native":
        return sdk.Asset.native()
    return sdk.Asset(payload["asset_code"], payload["asset_issuer"])
