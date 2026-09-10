# Transfer guide

Phase 2: getting the money out. Per-chain walkthroughs, the precondition
checklists, and the deadlines you need to respect.

**This tool never submits a transaction.** It produces a signed blob and the
command to submit it.

---

## The two-phase model

None of these chains can build a valid transaction fully offline. Every one
needs at least a sequence number, and most need more. So:

```
   ONLINE, no keys                OFFLINE, keys                YOU, manually
┌─────────────────────┐      ┌──────────────────────┐      ┌────────────────┐
│  s70 inspect        │      │  s70 sign            │      │  curl / CLI    │
│  reads chain state  │─────▶│  builds + signs      │─────▶│  submit        │
│  writes job.json    │ job  │  writes signed blob  │ blob │                │
└─────────────────────┘      └──────────────────────┘      └────────────────┘
```

A job file holds only public data — addresses, balances, sequence numbers,
gas prices — so it is safe to carry between machines on a USB stick.

```bash
s70 inspect --chain <CHAIN> --source <OLD> --destination <SAFE> --out job.json
s70 sign --job job.json --backup backup.json --wallet <N> --out signed.json
```

`inspect` exits non-zero and refuses to bless the job if a blocking
precondition fails, so you find out before you sign rather than from an
on-chain error code.

### Deadlines

| Chain | Blob lifetime | Governed by |
|---|---|---|
| **Solana** | **60–90 seconds** | blockhash validity (151 slots) |
| XRPL | ~13 minutes | `LastLedgerSequence` (set to +200) |
| Stellar | 1 hour | `set_timeout(3600)` — our choice |
| Aptos | 1 hour | `expiration_timestamp_secs` — our choice |
| Sui | no timer | dies when any input object is touched |

Solana is the one that breaks the air-gap workflow outright. Do not plan to
walk a USB stick anywhere; run inspect, sign and submit as a tight loop on
one machine, and expect to repeat it.

Separately, **every** chain's job dies if anything else transacts from the
source account first, because the sequence number moves. If the address is
under active attack, you are racing.

---

## Stellar — `account_merge`

The cleanest sweep available here. `account_merge` sends the entire XLM
balance *and* deletes the account, recovering the 1 XLM base reserve that a
plain payment must leave behind.

It has a **high** threshold and fails unless the account has no subentries at
all, so the real work is the ordered teardown in front of it:

1. cancel every open offer — they are subentries, and they reserve balance
2. delete every data entry — also subentries
3. for each non-native asset: pay the full balance out, **then** delete the
   trustline
4. `account_merge`

All in **one atomic transaction**: either the account is emptied and closed,
or nothing happens.

### Why that order is not cosmetic

`change_trust` with `limit=0` deletes a trustline, but fails with
`CHANGE_TRUST_INVALID_LIMIT` if *any* balance remains — including dust. And
`selling_liabilities` from an open offer reserves part of the balance, so the
payout cannot drain the trustline while offers are live. Offers first, then
payout, then trustline deletion.

### Precondition checklist

| Precondition | Failure code | Checked via |
|---|---|---|
| No non-signer subentries: no trustlines, offers, or data entries | `ACCOUNT_MERGE_HAS_SUB_ENTRIES` (-4) | `balances[]`, `data{}`, `/offers` |
| `AUTH_IMMUTABLE` not set | `ACCOUNT_MERGE_IMMUTABLE_SET` (-3) | `flags.auth_immutable` |
| Not sponsoring other accounts' reserves | `ACCOUNT_MERGE_IS_SPONSOR` (-7) | `num_sponsoring == 0` |
| Sequence not too far ahead of the ledger | `ACCOUNT_MERGE_SEQNUM_TOO_FAR` (-5) | `seq < (ledgerSeq+1) << 32` |
| Destination can absorb the XLM | `ACCOUNT_MERGE_DEST_FULL` (-6) | destination funded |
| Destination exists | `ACCOUNT_MERGE_NO_ACCOUNT` | `GET /accounts/{dest}` |

Signers do **not** block a merge — they are removed automatically.

Dead ends the tool flags but cannot fix: **deauthorized or frozen
trustlines** (the balance cannot move, so the trustline cannot be deleted, so
the merge cannot happen) and **liquidity pool shares** (they count as
trustlines and must be withdrawn first). Claimable balances trip
`ACCOUNT_MERGE_IS_SPONSOR`.

### Operation limit

Stellar caps a transaction at **100 operations**, and the teardown costs
`offers + data_entries + 2 x trustlines + 1`. An account with 40 trustlines
needs 81+ operations and gets split across several sequential transactions
with the merge in the last one. Submit them **strictly in order**; if one
fails, stop and re-inspect, because the sequence numbers have moved.

Fee is `base_fee x operations` — 90 operations at 200 stroops is 18,000
stroops. Amounts are **7 decimals passed as decimal strings** (`"123.4567890"`),
not stroops.

### Submit

```bash
curl -X POST https://horizon.stellar.org/transactions \
    --data-urlencode "tx=<BASE64_XDR>"
```

Form-encoded, not JSON. Or use [Stellar Lab](https://lab.stellar.org/) →
*Clear and import new* → paste XDR → Submit. **Decode it first** at
<https://lab.stellar.org/xdr/view>.

---

## XRPL — `AccountDelete`

`AccountDelete` sends the entire remaining XRP balance minus the fee to the
destination and removes the account, so it **is** the whole sweep — there is
normally no separate Payment step. It also recovers the 1 XRP base reserve, at
the cost of a 0.2 XRP fee that is *burned*. Net, deleting beats a partial
sweep by about 0.8 XRP.

The tool tries to delete; if blocked, it says exactly which objects are in the
way; and if they cannot be cleared, it falls back to a Payment that leaves the
reserve behind.

### Precondition checklist

| Precondition | Failure | Checked via |
|---|---|---|
| `Sequence + 256` < current ledger index | `tecTOO_SOON` | `account_info`, `ledger` |
| Fee ≥ owner reserve (**0.2 XRP = 200000 drops**) | `telINSUF_FEE_P` | `server_state.reserve_inc` |
| No blocking owned objects | `tecHAS_OBLIGATIONS` | `account_objects` |
| ≤ 1000 owned objects | `tefTOO_BIG` | `account_objects` count |
| `SponsoringOwnerCount` / `SponsoringAccountCount` both 0 | `tecHAS_OBLIGATIONS` | `account_info` |
| Not the issuer of a still-existing NFT | `tecHAS_OBLIGATIONS` | issuer scan |
| Destination funded, not the source | `tecNO_DST` | `account_info` on dest |

Two things routinely bite:

- **The fee.** It must be at least the owner reserve, not the usual 10 drops.
  The tool reads it from `server_state` and writes it into the transaction
  explicitly rather than relying on `autofill`, because whether autofill
  applies the special fee varies by version.
- **`tecTOO_SOON`.** An account younger than ~256 ledgers (~15 minutes)
  simply cannot be deleted yet. The tool reports the ledger at which it
  becomes possible.

### Objects that block, and what clears them

| Object | Cleared by |
|---|---|
| Trustlines (`RippleState`) | Send the full IOU balance away, then `TrustSet` with limit `0` and `tfClearNoRipple` — **this tool does this** |
| Checks | `CheckCancel` |
| Escrows | `EscrowFinish` / `EscrowCancel` — may be impossible unilaterally |
| Payment channels | `PaymentChannelClaim` with `tfClose` |
| NFTokenPages | `NFTokenBurn`, one NFT at a time |
| AMM, bridges, MPTs, sponsorships | Varies; some cannot be removed unilaterally |

Deleted automatically with the account: Offers, Tickets, SignerLists,
DepositPreauth, DIDs.

Dead ends: a **negative trustline balance** (you owe the issuer) and
**frozen** trustlines.

### Signing without a seed

A recovered 32-byte XRPL private key has no seed — the derivation is one-way —
so `xrpl.wallet.Wallet.from_seed` is unusable. The tool drives the binary
codec directly instead:

```python
payload = transaction.to_xrpl()
payload["SigningPubKey"] = public_key_hex        # "ED…" or compressed secp256k1
signing_blob = binarycodec.encode_for_signing(payload)
payload["TxnSignature"] = keypairs.sign(bytes.fromhex(signing_blob), private_key_hex)
tx_blob = binarycodec.encode(payload)
```

Private keys are XRPL's 33-byte form: `00` + 32 bytes for secp256k1,
`ED` + 32 bytes for Ed25519.

### Submit

```bash
curl -X POST https://s1.ripple.com:51234/ -H 'Content-Type: application/json' \
  -d '{"method":"submit","params":[{"tx_blob":"<HEX_BLOB>","fail_hard":false}]}'
```

Submit blobs in order — each depends on the previous one's sequence number.
The same blob is **safe to resubmit**, which is precisely why XRPL's docs
recommend persisting it.

---

## Solana — sweep tokens, then SOL

Order matters:

1. create the destination's associated token account, if missing
2. `transfer_checked` each SPL balance
3. `close_account` each drained token account, reclaiming ~0.002 SOL of rent
4. transfer the remaining SOL **last**, minus the fee

Always `transfer_checked`, never bare `transfer`: checked validates the mint
and decimals, which is what stops a wrong-decimals transfer.

Token accounts are enumerated for **both** the original Token program and
Token-2022, because `getTokenAccountsByOwner` takes one program id at a time
and an owner can hold both.

### The 60–90 second problem

A blockhash is valid for about 151 slots. That is the entire lifetime of the
signed blob. Consequences:

- An air-gapped walk-between-machines flow will **always** fail here.
- Run inspect → sign → submit as a tight loop, and expect to repeat.
- Durable nonces are the textbook fix and a trap in this context: the nonce
  account must already exist, and creating it *from the compromised address*
  is chicken-and-egg. Only viable if a safe address funded it beforehand.

### Other gotchas

- **Token-2022 extensions** — transfer fees, hooks, non-transferable flags —
  mean the amount received may be less than the amount sent.
- **Sweeper bots.** There is no fee-payer separation in this plan: the SOL
  you need for the fee is the SOL you are trying to rescue. If a bot is
  draining the address, you are racing it.

### Submit

```bash
curl -X POST https://api.mainnet-beta.solana.com -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["<BASE64>",
       {"encoding":"base64","skipPreflight":false,"maxRetries":5}]}'
```

Leave `skipPreflight` false — preflight simulation is your last chance to
catch a stale blockhash or a missing account before paying a fee. Confirm with
`solana confirm -v <signature>`.

---

## Aptos — one transaction per asset

Aptos migrated most assets from Coin v1 to the Fungible Asset standard during
mid-2025, so there are three entry functions depending on what the asset
actually is:

| Asset | Entry function |
|---|---|
| native APT | `0x1::aptos_account::transfer` |
| legacy paired Coin v1 | `0x1::aptos_account::transfer_coins<CoinType>` |
| natively-FA asset | `0x1::primary_fungible_store::transfer` |

`transfer_coins` auto-registers the recipient's store; bare
`0x1::coin::transfer` does not.

### Asset discovery needs the indexer

FA balances live in separate `FungibleStore` objects that the fullnode's
resource endpoint does not enumerate. `inspect` queries
`current_fungible_asset_balances` over GraphQL for that, and uses the fullnode
only for chain id, sequence number and gas price.

**If the indexer is unreachable, `inspect` says so** and sweeps only native
APT rather than reporting an empty wallet. Check an explorer before believing
an address is empty.

### Sequence numbers

Each Aptos transaction consumes exactly one sequence number, and they must be
submitted **gaplessly and in order**. One transaction per asset, with native
APT **last** so the gas is still there to pay for the earlier ones. An active
attacker invalidates your sequence the moment they transact.

APT is 8 decimals (octas). Never assume that for other assets.

### Submit

```bash
xxd -r -p tx.hex > tx.bcs
curl -X POST https://api.mainnet.aptoslabs.com/v1/transactions \
  -H 'Content-Type: application/x.aptos.signed_transaction+bcs' \
  --data-binary @tx.bcs
```

That Content-Type is **mandatory**. Poll
`GET /v1/transactions/by_hash/<hash>` after each submission — a 202 means
accepted into the mempool, not committed.

---

## Sui — CLI builds, this tool signs

Handled differently on purpose. Sui disabled JSON-RPC on Foundation mainnet
fullnodes in mid-2025, and its Python SDK rewrote its transaction builder
across several releases in quick succession, with no documented equivalent of
the old `payAllSui` for the sweep case.

Sui's **signing** scheme, by contrast, is short and stable:

```
digest     = blake2b_256( intent(0x00 0x00 0x00) ‖ bcs(TransactionData) )
signature  = ed25519_sign(secret_key, digest)
serialized = base64( flag(0x00) ‖ signature(64) ‖ public_key(32) )
```

So the split is: the `sui` CLI builds the transaction (online, no key), this
tool signs it (offline, with the key). No Sui SDK dependency at all.

### Walkthrough

```bash
# 1. List coins
sui client gas --json

# 2. Merge every SUI coin into the gas coin
sui client merge-coin --primary-coin <GAS_COIN_ID> \
    --coin-to-merge <OTHER_COIN_ID> --serialize-unsigned-transaction

# 3. Build the transfer
sui client transfer-sui --to <DEST> --sui-coin-object-id <GAS_COIN_ID> \
    --gas-budget 5000000 --serialize-unsigned-transaction

# 4. DECODE IT AND READ IT
sui keytool decode-tx --tx-bytes <BASE64>

# 5. Sign offline
s70 sign --job job.json --backup backup.json --wallet <N> --tx-bytes <BASE64>

# 6. Submit
sui client execute-signed-tx --tx-bytes <BASE64> --signatures <SIGNATURE>
```

Step 4 is not optional. Sui's own guidance is never to blind-sign opaque
bytes, and it applies to every chain here.

### Gotchas

- **Object references go stale.** `TransactionData` pins each input coin's
  `(id, version, digest)`. Any touch — the attacker, or a staking reward
  landing — permanently invalidates the blob. No timer, purely event-driven.
- **The gas coin cannot also be an input** to `transfer_objects`. Merge into
  the gas coin, then transfer that one coin.
- **Coin fragmentation.** Hundreds of small coins will exceed the PTB input
  limit. Merge in batches; note the 50-coin page cap on Mysten endpoints.
- SUI is 9 decimals (MIST).

---

## EVM — deliberately not offered

There is no reliable, complete way to enumerate everything of value at an EVM
address, and the reason is structural rather than a tooling gap.

ERC-20 has **no reverse index**. You cannot ask "which tokens does address X
hold?" — only "what is X's balance of token T?" for a T you already know.
Discovering the T-set means indexing `Transfer` logs across every chain's full
history. Wallets paper over this with curated token lists covering a few dozen
tokens per chain. Newly launched, low-cap and custom-contract assets are
invisible to them. So are LP positions, staked, vesting, locked and bridged
balances, NFTs, and unclaimed airdrops — each a separate discovery problem.

A sweep that looks complete but is not is worse than no sweep, because it
retires your attention.

**What to do instead.** Import the key into Rabby and cross-check with at
least two independent multi-chain views:

1. **Rabby** — portfolio across 100+ EVM chains, plus a built-in approval
   manager listing every active approval per chain with revoke buttons.
2. **[revoke.cash](https://revoke.cash)** — approvals across 100+ networks.
3. **A block explorer's "Token Holdings" tab**, or Blockscout's multichain
   view. Explorers index all `Transfer` logs, so this is the closest thing to
   ground truth.
4. **Manually check** staked, LP, vesting, locked and bridged positions.
   Nothing balance-based will find these.

And the hardest part: **revoking approvals does not help if the seed phrase
was compromised.** If a sweeper bot is draining incoming ETH, every derived
address on every chain is permanently hostile, and there is no recovering the
address — only racing it with a bundled sweep through a private mempool.

---

## Polkadot and Canton — not offered

**Polkadot.** Import the keystore into Talisman (see
[IMPORT-GUIDE.md](IMPORT-GUIDE.md)) and transfer from there. Talisman's own UI
handles nonces, existential deposits and fee estimation correctly, and there
is no advantage to reimplementing it.

**Canton.** Moving assets requires a Canton participant node and, generally,
the counterparty's cooperation. There is no self-service client-side sweep to
build. Hand the exported key encodings to whoever operates your participant
node.
