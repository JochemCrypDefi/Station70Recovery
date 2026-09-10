"""Aptos: sweep fungible assets and then native APT.

Aptos migrated most assets from Coin v1 to the Fungible Asset standard during
mid-2025, which means three different entry functions depending on what the
asset actually is:

* native APT            -> ``0x1::aptos_account::transfer``
* legacy paired Coin v1 -> ``0x1::aptos_account::transfer_coins<CoinType>``
* natively-FA asset     -> ``0x1::primary_fungible_store::transfer``

Asset discovery needs the **Indexer**, not a fullnode: FA balances live in
separate ``FungibleStore`` objects that the fullnode's resource endpoint does
not enumerate. The online phase queries ``current_fungible_asset_balances``
over GraphQL for that, and the fullnode only for chain id, sequence number
and gas price.

Each Aptos transaction consumes exactly one sequence number and they must be
submitted gaplessly and in order. One transaction per asset, APT last so the
gas is still there to pay for the earlier ones.

The online phase deliberately uses ``urllib`` rather than the Aptos SDK, so
inspection has no dependency on it -- only signing does.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from decimal import Decimal
from typing import Any

from s70.errors import MissingDependencyError, S70Error
from s70.keymaterial import CURVE_ED25519, KeyMaterial
from s70.txn.job import Asset, Precondition, SignedBundle, TransferJob

CHAIN_ID = "aptos"

MAINNET_REST = "https://api.mainnet.aptoslabs.com/v1"
MAINNET_INDEXER = "https://api.mainnet.aptoslabs.com/v1/graphql"

APT_METADATA = "0x000000000000000000000000000000000000000000000000000000000000000a"
APT_COIN_TYPE = "0x1::aptos_coin::AptosCoin"
APT_DECIMALS = 8

#: Aptos' default expiry is 600s. We set it explicitly and longer, because the
#: offline half of the flow takes as long as it takes.
EXPIRY_SECONDS = 3600

DEFAULT_MAX_GAS = 20_000

_FA_QUERY = """
query Balances($owner: String!) {
  current_fungible_asset_balances(
    where: {owner_address: {_eq: $owner}, amount: {_gt: "0"}}
    limit: 200
  ) {
    asset_type
    amount
    token_standard
    metadata { decimals symbol name }
  }
}
"""


def _get_json(url: str, timeout: float = 20.0) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise S70Error(f"GET {url} failed: HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise S70Error(f"GET {url} failed: {exc.reason}") from exc


def _post_json(url: str, payload: dict, timeout: float = 20.0) -> Any:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise S70Error(f"POST {url} failed: HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise S70Error(f"POST {url} failed: {exc.reason}") from exc


# --------------------------------------------------------------------------
# online phase
# --------------------------------------------------------------------------


def inspect(
    source: str,
    destination: str,
    *,
    rpc_url: str | None = None,
    indexer_url: str | None = None,
) -> TransferJob:
    """Read chain id, sequence number, gas price and every FA balance."""
    rest = (rpc_url or MAINNET_REST).rstrip("/")
    indexer = indexer_url or MAINNET_INDEXER

    ledger = _get_json(rest)
    chain_id = int(ledger["chain_id"])

    account = _get_json(f"{rest}/accounts/{source}")
    sequence_number = int(account["sequence_number"])
    authentication_key = account.get("authentication_key", "")

    try:
        gas = _get_json(f"{rest}/estimate_gas_price")
        gas_unit_price = int(gas.get("gas_estimate", 100))
    except S70Error:
        gas_unit_price = 100

    assets: list[Asset] = []
    transfers: list[dict[str, Any]] = []
    warnings: list[str] = []

    try:
        response = _post_json(indexer, {"query": _FA_QUERY, "variables": {"owner": source}})
        if "errors" in response:
            raise S70Error(str(response["errors"]))
        balances = response["data"]["current_fungible_asset_balances"]
    except S70Error as exc:
        balances = []
        warnings.append(
            f"Could not reach the Aptos indexer ({exc}). Only native APT will be swept; "
            "fungible-asset balances could not be enumerated. Check the address on an "
            "explorer before assuming it is empty."
        )

    apt_amount = 0
    for balance in balances:
        asset_type = balance["asset_type"]
        raw = int(balance["amount"])
        metadata = balance.get("metadata") or {}
        decimals = int(metadata.get("decimals", 0) or 0)
        symbol = metadata.get("symbol") or asset_type[:10]
        standard = balance.get("token_standard", "")

        is_apt = asset_type in (APT_METADATA, APT_COIN_TYPE) or symbol.upper() == "APT"
        if is_apt:
            apt_amount = raw
            assets.append(
                Asset(
                    symbol="APT",
                    amount=str(Decimal(raw) / (Decimal(10) ** APT_DECIMALS)),
                    identifier=APT_COIN_TYPE,
                    decimals=APT_DECIMALS,
                    extra={"raw": str(raw), "kind": "native"},
                )
            )
            continue

        if "::" in asset_type and standard.lower() == "v1":
            kind = "coin_v1"
        else:
            kind = "fungible_asset"

        record = {
            "kind": kind,
            "asset_type": asset_type,
            "raw": str(raw),
            "decimals": decimals,
            "symbol": symbol,
        }
        transfers.append(record)
        assets.append(
            Asset(
                symbol=symbol,
                amount=str(Decimal(raw) / (Decimal(10) ** decimals)) if decimals else str(raw),
                identifier=asset_type,
                decimals=decimals,
                extra=record,
            )
        )

    if apt_amount == 0:
        try:
            resources = _get_json(f"{rest}/accounts/{source}/resources")
            for resource in resources:
                if resource.get("type") == f"0x1::coin::CoinStore<{APT_COIN_TYPE}>":
                    apt_amount = int(resource["data"]["coin"]["value"])
                    assets.append(
                        Asset(
                            symbol="APT",
                            amount=str(Decimal(apt_amount) / (Decimal(10) ** APT_DECIMALS)),
                            identifier=APT_COIN_TYPE,
                            decimals=APT_DECIMALS,
                            extra={"raw": str(apt_amount), "kind": "native"},
                        )
                    )
                    break
        except S70Error:
            pass

    gas_reserve = DEFAULT_MAX_GAS * gas_unit_price * (len(transfers) + 1)

    preconditions = [
        Precondition(
            "account exists on chain",
            bool(authentication_key),
            f"authentication_key = {authentication_key or 'missing'}",
        ),
        Precondition(
            "APT balance covers gas for every transaction",
            apt_amount > gas_reserve,
            f"{apt_amount} octas available, need about {gas_reserve} to pay for "
            f"{len(transfers) + 1} transaction(s)",
        ),
        Precondition(
            "destination differs from source",
            source != destination,
            "",
        ),
    ]

    plan = [
        f"transfer {record['raw']} raw units of {record['symbol']} "
        f"({'Coin v1' if record['kind'] == 'coin_v1' else 'FA'})"
        for record in transfers
    ]
    plan.append("transfer the remaining APT last, keeping back the gas reserve")

    warnings.append(
        "Each transaction consumes one sequence number and they must be submitted in "
        "order with no gaps. If anything else transacts from this account first, every "
        "blob below becomes invalid and you must re-inspect."
    )
    warnings.append(
        "If the address check on this key failed, the account may have had its key "
        "rotated. Verify on an explorer before spending gas."
    )

    return TransferJob(
        chain=CHAIN_ID,
        source_address=source,
        destination_address=destination,
        network={
            "rest": rest,
            "indexer": indexer,
            "chain_id": chain_id,
            "sequence_number": sequence_number,
            "gas_unit_price": gas_unit_price,
            "max_gas_amount": DEFAULT_MAX_GAS,
            "apt_octas": str(apt_amount),
            "gas_reserve_octas": str(gas_reserve),
            "transfers": transfers,
            "expiry_seconds": EXPIRY_SECONDS,
        },
        assets=assets,
        preconditions=preconditions,
        warnings=warnings,
        plan=plan,
        ttl_seconds=EXPIRY_SECONDS,
        ttl_note=(
            "The expiry is stamped into each transaction at signing time, so the clock "
            "starts when you sign, not when you inspect. The sequence number, however, "
            "is only valid until the account next transacts."
        ),
    )


# --------------------------------------------------------------------------
# offline phase
# --------------------------------------------------------------------------


def sign(job: TransferJob, key: KeyMaterial) -> SignedBundle:
    """Build and sign one transaction per asset, offline."""
    if key.curve != CURVE_ED25519:
        raise S70Error(
            "this signer supports Ed25519 Aptos accounts only; got " + key.curve
        )

    try:
        from aptos_sdk.account import Account
        from aptos_sdk.account_address import AccountAddress
        from aptos_sdk.bcs import Serializer
        from aptos_sdk.transactions import (
            EntryFunction,
            RawTransaction,
            SignedTransaction,
            TransactionArgument,
            TransactionPayload,
        )
        from aptos_sdk.type_tag import StructTag, TypeTag
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError("aptos-sdk", "Aptos transaction building") from exc

    account = Account.load_key(key.scalar.reveal().hex())
    if str(account.address()) != _normalize(job.source_address):
        raise S70Error(
            f"this key derives {account.address()} but the job is for "
            f"{job.source_address} -- refusing to sign. If this account had its key "
            "rotated, sign manually with the SDK instead."
        )

    destination = AccountAddress.from_str(job.destination_address)
    network = job.network
    sequence = int(network["sequence_number"])
    chain_id = int(network["chain_id"])
    gas_price = int(network["gas_unit_price"])
    max_gas = int(network["max_gas_amount"])
    expiry = int(time.time()) + int(network.get("expiry_seconds", EXPIRY_SECONDS))

    payloads: list[tuple[str, Any]] = []

    for record in network.get("transfers", []):
        amount = int(record["raw"])
        if record["kind"] == "coin_v1":
            payloads.append(
                (
                    f"transfer {amount} raw units of {record['symbol']} (Coin v1)",
                    EntryFunction.natural(
                        "0x1::aptos_account",
                        "transfer_coins",
                        [TypeTag(StructTag.from_str(record["asset_type"]))],
                        [
                            TransactionArgument(destination, Serializer.struct),
                            TransactionArgument(amount, Serializer.u64),
                        ],
                    ),
                )
            )
        else:
            metadata = AccountAddress.from_str(record["asset_type"])
            payloads.append(
                (
                    f"transfer {amount} raw units of {record['symbol']} (FA)",
                    EntryFunction.natural(
                        "0x1::primary_fungible_store",
                        "transfer",
                        [TypeTag(StructTag.from_str("0x1::fungible_asset::Metadata"))],
                        [
                            TransactionArgument(metadata, Serializer.struct),
                            TransactionArgument(destination, Serializer.struct),
                            TransactionArgument(amount, Serializer.u64),
                        ],
                    ),
                )
            )

    apt = int(network["apt_octas"])
    reserve = int(network["gas_reserve_octas"])
    sweep = apt - reserve
    if sweep <= 0:
        raise S70Error(
            f"APT balance {apt} octas does not exceed the {reserve} octa gas reserve -- "
            "there is nothing to sweep"
        )

    payloads.append(
        (
            f"transfer {Decimal(sweep) / (Decimal(10) ** APT_DECIMALS)} APT",
            EntryFunction.natural(
                "0x1::aptos_account",
                "transfer",
                [],
                [
                    TransactionArgument(destination, Serializer.struct),
                    TransactionArgument(sweep, Serializer.u64),
                ],
            ),
        )
    )

    blobs: list[str] = []
    summary: list[str] = []
    for offset, (description, entry_function) in enumerate(payloads):
        raw_transaction = RawTransaction(
            account.address(),
            sequence + offset,
            TransactionPayload(entry_function),
            max_gas,
            gas_price,
            expiry,
            chain_id,
        )
        authenticator = account.sign_transaction(raw_transaction)
        signed = SignedTransaction(raw_transaction, authenticator)
        blobs.append(signed.bytes().hex())
        summary.append(f"seq {sequence + offset}: {description}")

    return SignedBundle(
        chain=CHAIN_ID,
        blobs=blobs,
        encoding="hex",
        submit_command=(
            "xxd -r -p tx.hex > tx.bcs && "
            f"curl -X POST {network['rest']}/transactions "
            "-H 'Content-Type: application/x.aptos.signed_transaction+bcs' "
            "--data-binary @tx.bcs"
        ),
        submit_notes=[
            "That Content-Type is mandatory. A normal application/json POST will be "
            "rejected.",
            f"There are {len(blobs)} transaction(s) using sequence numbers "
            f"{sequence}..{sequence + len(blobs) - 1}. Submit them in order and wait for "
            "each to commit -- a gap makes every later one invalid.",
            "Poll GET /v1/transactions/by_hash/<hash> after each submission; a 202 "
            "response only means accepted into the mempool, not committed.",
        ],
        summary=summary,
        expires_note=f"Each transaction expires at unix time {expiry}.",
    )


def _normalize(address: str) -> str:
    body = address.strip().lower().removeprefix("0x")
    return "0x" + body.rjust(64, "0")
