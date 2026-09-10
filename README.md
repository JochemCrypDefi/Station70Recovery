# S70 Recovery

Offline TUI for recovering CrypDefi wallet backup keys and preparing
asset-transfer transactions.

This is a **disaster-recovery tool**. It decrypts the private keys held in a
CrypDefi backup file so you can move the funds to a new, secure wallet. Once a
key has been through this tool, treat the account it controls as spent: move
everything off it and do not keep funds attached to those keys.

It works in two phases:

1. **Recover.** Decrypt the wallet private keys from a backup file, verify each
   one two independent ways, and render it in the exact string form the target
   browser extension accepts.
2. **Transfer.** Read chain state online with no keys loaded, then sign a sweep
   transaction offline. This tool never submits a transaction.

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Using the TUI](#using-the-tui)
- [Backup file format](#backup-file-format)
- [How verification works](#how-verification-works)
- [Chain and wallet support](#chain-and-wallet-support)
- [Phase 2: moving the money](#phase-2-moving-the-money)
- [Security](#security)
- [Testing status](#testing-status)
- [Troubleshooting](#troubleshooting)

---

## Install

Requires **Python 3.10+**.

> **Windows note:** if `python --version` prints *"Python was not found; run
> without arguments to install from the Microsoft Store"*, you have the
> Windows App Execution Alias stub rather than a real interpreter. Install
> Python properly first — `winget install Python.Python.3.12`, or download it
> from python.org — and make sure **Add python.exe to PATH** is ticked.

```bash
git clone <this repo> s70-recovery
cd s70-recovery

python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .            # gives you the `s70` command
```

### Offline / air-gapped install

On an internet-connected machine, download the wheels **and the build
backend** — an editable install needs `setuptools`, and `--no-index` will not
be able to fetch it later:

```bash
pip download -r requirements.txt -d wheels \
    --platform win_amd64 --python-version 312 --only-binary :all:
pip download setuptools wheel -d wheels
```

Copy the `wheels` directory and this repository to the offline machine, then:

```bash
pip install --no-index --find-links wheels -r requirements.txt
pip install --no-index --no-build-isolation --no-deps -e .
```

`--no-build-isolation` is required: without it pip tries to fetch the build
backend from PyPI even though the wheel is sitting in `wheels/`.

Note that `cryptography`, `pycryptodome` and `pynacl` are native extensions, so
the `--platform` / `--python-version` values above must match the offline
machine, not the one you download on.

### Phase-2 extras (optional)

Only needed for `s70 inspect` / `s70 sign`. Not needed to recover a key or
import it into a wallet.

```bash
pip install -r requirements-tx.txt
```

Prefer a **separate virtualenv** for these. They are heavy, they pin narrow
version ranges, and keeping them off the machine that holds your keys is a
real security improvement rather than a stylistic preference.

---

## Quick start

```bash
# 1. See what is in the backup. Decrypts nothing.
s70 list backup-1234567890.json

# 2. Check that every key is intact, without displaying any of them.
s70 verify backup-1234567890.json

# 3. Recover keys and get import strings.
s70 tui backup-1234567890.json
```

The recovery key is embedded in the backup file, so there is nothing else to
supply — no separate key file, no passphrase.

---

## Commands

| Command | Network | Keys loaded | What it does |
|---|---|---|---|
| `s70 tui <backup>` | no | yes | Interactive interface. **This is the tool.** |
| `s70 list <backup>` | no | no | Inventory the backup without decrypting. |
| `s70 verify <backup>` | no | transiently | Decrypt and check every key, display none. |
| `s70 inspect --chain C --source A --destination B --out job.json` | **yes** | **no** | Read chain state, write a job file. |
| `s70 sign --backup <b> --job job.json --wallet N` | no | yes | Sign the job offline. Never submits. |

No CLI command prints a private key. Revealing a key is the TUI's job, because
the TUI runs on the **alternate screen buffer** — what it draws is not added to
your terminal's scrollback and is gone when the app exits. Terminal scrollback
is not something this tool can clean up after; tmux, iTerm2 session logging and
CI all write it to disk.

`s70 inspect` also accepts `--rpc-url` to override the default endpoint, and
`--tx-bytes` for Sui. `s70 sign` accepts `--out` to write the signed bundle
somewhere specific, and `--tx-bytes` for Sui.

---

## Using the TUI

```bash
s70 tui backup-1234567890.json
```

**Consent screen.** Shows what the backup contains and what the tool is for.
Type `RECOVER` and press enter. Nothing is decrypted before this.

**Inventory.** On entry, every wallet is decrypted, checked, and its key
immediately discarded — so the table is complete and accurate the moment it
appears. Rows are sorted by chain, then by name, and show the SHA-256 result
and the address-check verdict separately.

| Key | Where | Does |
|---|---|---|
| `enter` | inventory | Open the selected wallet |
| `r` | wallet | Reveal / hide the private key |
| `k` | wallet (Polkadot) | Write the polkadot-js keystore |
| `escape` | wallet | Back to the inventory, discarding the key |
| `escape` | inventory / consent | Quit |
| `q` | anywhere | Quit |

**Wallet screen.** Three sections:

- **Private key** — the raw decrypted bytes as hex, followed by every encoding
  the target extension might want. Masked until you press `r`.
- **How to import** — the click-path for the wallet that takes this key, or
  simply *Not available.*
- **Move the funds out** — on chains this tool can sweep, the exact
  `s70 inspect` command for this account, with the source address filled in.

Leaving the screen discards the recovered key and the rendered copies of it.

---

## Backup file format

```json
{
  "version": "1.0",
  "wallet_provider": "CrypDefi",
  "recovery_key": "<base64 DER RSA-4096 private key>",
  "keys": [
    {
      "key_id": "...",
      "key_type": "EDDSA_ED25519",
      "key_name": "Treasury EVM",
      "share_algorithm": "single",
      "shares": [
        {
          "metadata": { "address": "0x...", "chain_id": "ch-60" },
          "encryption": {
            "ciphersuite": "RSA-4096-OAEP-SHA256",
            "ciphertext": "<base64>",
            "original_sha256": "<base64 sha256 of the plaintext>"
          }
        }
      ]
    }
  ]
}
```

Two fields carry information the tool would otherwise have to guess, and both
are treated as authoritative:

- **`key_type`** (`EDDSA_ED25519` or `ECDSA_SECP256k1`) gives the curve. A raw
  32-byte scalar is a valid private key on *both* curves, so without this the
  tool has to derive both and see which reproduces the address.
- **`metadata.chain_id`** is `ch-<SLIP-44 coin type>`. It is the only thing
  that separates Aptos (`ch-637`) from Sui (`ch-784`), whose addresses are
  identical in shape.

The address is still re-derived and compared in every case. The declared fields
choose *what* to derive; they never stand in for the check.

Everything else is read defensively. A backup missing `key_name`,
`metadata.address` or `metadata.chain_id` is still usable — you lose the
corresponding cross-check, which the UI reports rather than hides.

Full details, including the plaintext encodings the key parser accepts, are in
[docs/FORMAT.md](docs/FORMAT.md).

---

## How verification works

Every recovered key is checked two independent ways.

**1. SHA-256 integrity.** The backup records `original_sha256` of the
plaintext. The tool hashes what it decrypted and compares. This proves the
decryption returned exactly the bytes that were encrypted — it catches a wrong
recovery key or a corrupt share.

**2. Address re-derivation.** The public key is derived from the recovered
private key, the address is derived from that, and it must equal the address in
the backup. This is the one that proves the key actually controls the account.

The two are reported separately, because they mean different things. A key can
pass SHA-256 and still fail the address check.

| Status | Meaning |
|---|---|
| `verified` | Both checks passed. |
| `unverifiable` | Chain identified, but its address cannot be recomputed offline (Canton). Rests on SHA-256 alone. |
| `sha-256 only` | Recovered and hash-checked, but this tool has no address derivation for the chain (e.g. Radix). |
| `mismatch` | Checked and wrong. Investigate before using the key. |
| `ambiguous` | Address shape matched several chains and the key reproduced none. |
| `no address` | The backup recorded no address, so nothing could be cross-checked. |
| `HASH MISMATCH` | The SHA-256 check failed. Do not trust this key. |

A chain the tool cannot derive an address for is **not** skipped. The private
key is the deliverable; a missing cross-check is information shown alongside
it, never a reason to withhold it.

---

## Chain and wallet support

| Chain | `chain_id` | Curve | Wallet | Import format | Verify | Sign |
|---|---|---|---|---|---|---|
| EVM | `ch-60` | secp256k1 | Rabby / MetaMask | `0x` + 64 hex | yes | no — see below |
| Solana | `ch-501` | Ed25519 | Phantom | base58 of 64-byte secret | yes | yes |
| Aptos | `ch-637` | Ed25519 | Pontem | `0x` + 64 hex (+ AIP-80) | yes | yes |
| Sui | `ch-784` | Ed25519 | Suiet | bech32 `suiprivkey1…` | yes | yes (CLI-assisted) |
| Stellar | `ch-148` | Ed25519 | Freighter | StrKey `S…` | yes | yes |
| Polkadot | `ch-354` | Ed25519 | Talisman | **keystore file** | yes | no |
| XRPL | `ch-144` | secp256k1 / Ed25519 | **none** | — | yes | yes |
| Canton | `ch-6767` | Ed25519 | Console Wallet | **no confirmed path** | no | no |
| Radix | `ch-1022` | Ed25519 | — | raw key only | **no** | no |

Per-wallet click-paths and caveats are in
[docs/IMPORT-GUIDE.md](docs/IMPORT-GUIDE.md).

The three that need explaining:

**Polkadot / Talisman.** Talisman cannot import a raw Substrate private key —
its private-key field only accepts Ethereum and Solana keys. The only path is a
polkadot-js v3 keystore file, which the TUI writes when you press `k`. It is
written **unencrypted** so Talisman imports it without a passphrase; the file
is a plaintext private key at mode `0600`. Import it, then delete it.

**XRPL.** No wallet extension can import these keys. Gem Wallet, Xaman/Xumm and
Crossmark all import a 16-byte *family seed*, and this backup holds the derived
32-byte private key — the derivation is one-way and cannot be reversed. Use the
offline signing flow instead; XRPL is fully supported there.

**Canton and Radix.** No address derivation exists in this tool, so their keys
show as `unverifiable` / `sha-256 only`. The raw key bytes are still recovered
and displayed in hex, base64 and (for Canton) PKCS#8 PEM.

---

## Phase 2: moving the money

Two phases, on two machines, so keys and network never meet:

```
  ONLINE, no keys              OFFLINE, keys                YOU, manually
  s70 inspect        ──job──▶  s70 sign        ──blob──▶    curl / explorer
```

`s70 inspect` reads balances and preconditions and writes a `job.json`. It
loads no keys. `s70 sign` reads that job, signs it, and prints the blob plus
the command to submit it. **This tool never submits a transaction.**

| Chain | Strategy |
|---|---|
| **Stellar** | Cancel offers, delete data entries, pay out and close each trustline, then `account_merge`. One atomic transaction; recovers the 1 XLM base reserve. |
| **XRPL** | Clear trustlines, then `AccountDelete` — sweeps the whole balance and closes the account. |
| **Solana** | `transfer_checked` each SPL balance, close the drained token accounts to reclaim rent, then sweep SOL last. |
| **Aptos** | One transaction per fungible asset, then native APT last. Handles Coin v1 and the newer FA standard. |
| **Sui** | The `sui` CLI builds the transaction; this tool signs it offline. |
| **EVM** | **Not offered.** ERC-20 has no reverse index, so no scan can be complete. Import into Rabby and use its portfolio view instead. |
| **Polkadot** | Not offered. Import the keystore into Talisman and transfer from there. |
| **Canton / Radix** | Not offered. |

Chain-by-chain detail, fees and deadlines: [docs/TRANSFER-GUIDE.md](docs/TRANSFER-GUIDE.md).

---

## Security

Full reasoning in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). In short:

- **The TUI runs on the alternate screen buffer**, so revealed keys are not
  added to terminal scrollback. No CLI command prints a key at all.
- **Textual's command palette is disabled**, because it offers "Save
  screenshot" — which would write an SVG of a revealed key to disk.
- **Keys are masked until you press `r`**, and re-mask when you leave the
  screen or a dialog opens over it.
- **Keys are discarded when you leave a wallet screen**, along with the
  rendered copies of them. `verify` discards each key as soon as its verdict is
  recorded.
- **Secrets do not leak through `repr`.** Key material is wrapped in a `Secret`
  type that renders as `<Secret scalar len=32>`, and the parsed `Backup` object
  suppresses its own `repr` so the embedded RSA private key cannot be printed
  by accident.
- **The keystore file is created with `O_EXCL` at mode `0600`** in a single
  call, so it never exists at default permissions and an existing file is
  refused rather than overwritten.
- **`sign` opens no sockets.** All network access lives in `inspect`.

What it cannot protect you from: a compromised OS, a keylogger, or anyone
looking at the screen. If the key was *compromised* rather than merely lost,
assume someone is watching the address and do not send it gas.

---

## Testing status

**Read this before trusting the tool with real funds.**

The test suite (`pytest -q`, 78 tests) covers backup parsing, the decryption
pipeline, curve disambiguation, every codec's round-trip and checksum
rejection, the keystore layout and file permissions, and the job-file
round-trip.

What it **cannot** tell you is whether an address derivation is *correct*. The
tests check self-consistency — round-trips and documented invariants — not
agreement with an independent implementation. A subtly wrong derivation would
be consistently wrong and the suite would pass.

```bash
pip install pytest
pytest -q
```

So before moving anything of value: **recover one key, import it into the
wallet, and confirm the wallet shows the address you expect.** That is the only
end-to-end proof that counts.

Known-uncertain areas, flagged honestly:

- **Aptos unified `SingleKey` authentication keys.** The legacy Ed25519
  derivation is solid; the BCS layout for the newer scheme is inferred, so
  several variants are tried and any match is accepted.
- **Canton fingerprints.** Not reproducible offline. Marked `unverifiable`.
- **Radix.** No derivation at all. Raw key only, `sha-256 only`.
- **Pontem and AIP-80.** Pontem is closed source, so whether it accepts the
  prefixed form is unverified. Plain hex is offered first.
- **Every phase-2 chain module.** Written against documented SDK APIs.
  Decode every blob before submitting it.

---

## Troubleshooting

**`<file> has no 'recovery_key' field`** — every CrypDefi backup embeds the RSA
key that decrypts it. A file without one is truncated, or is not a CrypDefi
backup.

**`recovery_key is not valid base64`** — the field should be base64-encoded
DER. A PEM block pasted in directly is also accepted.

**`ciphertext is N bytes but the recovery key is RSA-4096`** — this share was
encrypted to a different backup public key. Check you have the right backup
file.

**`RSA-OAEP decryption failed for every hash combination tried`** — the
recovery key does not match the backup public key, or the ciphertext is
corrupt.

**`decrypted N bytes, which does not match any known private-key encoding`** —
the plaintext is not 32, 48 or 64 raw bytes nor a DER/PEM private key. Report
the length; do not assume the key is lost.

**Status is `mismatch`** — the key decrypted and passed its SHA-256 check but
derives a different address. On Aptos this may be a **rotated key**: an Aptos
address only equals its authentication key while the key has never been
rotated, so the key may still be current. On Polkadot it usually means the
account is sr25519, which this tool cannot rebuild — the keystore would import
a different address, so do not send funds to it.

**Status is `sha-256 only`** — the key is fine and the hash matched; this tool
just has no address derivation for that chain. Confirm the address in your
wallet after importing, before moving anything.
