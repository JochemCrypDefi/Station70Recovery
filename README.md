# S70 Recovery

Offline tool for recovering the wallet keys in a Station70 backup file, so you
can get into the accounts they control.

It does four things:

1. **Decrypts your keys** from the backup, using the recovery key the file
   itself carries.
2. **Checks each key two ways** and tells you plainly which checks passed.
3. **Shows each key in the format your wallet wants**, with the click path to
   import it.
4. **Exports a key to AWS KMS** if you want to migrate there for moving the funds.

**It runs entirely offline and opens no network connections.**

> Treat every key you recover as spent. It has been on a screen and on a
> general-purpose computer: move anything it holds to a new wallet, and don't
> keep using the old address.

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Using the app](#using-the-app)
- [Commands](#commands)
- [Using a recovered key](#using-a-recovered-key)
- [What's supported](#whats-supported)
- [How keys are verified](#how-keys-are-verified)

Also: [importing into a wallet](docs/IMPORT-GUIDE.md) ·
[exporting to AWS KMS](docs/KMS-EXPORT.md)

---

## Install

Requires **Python 3.10+**.

```bash
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .            # gives you the `s70` command
```

### Installing on an offline machine

On a machine with internet, download the packages, including the build tools,
which an offline install cannot fetch later:

```bash
pip download -r requirements.txt -d wheels \
    --platform manylinux2014_x86_64 \
    --platform manylinux_2_17_x86_64 \
    --platform manylinux_2_28_x86_64 \
    --python-version 312 --only-binary :all:
pip download setuptools wheel -d wheels
```

The `--platform` and `--python-version` must match the **offline** machine.
Copy the `wheels` folder and this repository across, then:

```bash
pip install --no-index --find-links wheels -r requirements.txt
pip install --no-index --no-build-isolation --no-deps -e .
```

---

## Quick start

Your backup is the `backup-….json` file you were given. Substitute its real
name below.

```bash
# 1. See what's in the backup. Decrypts nothing.
s70 list backup-2026-09-08T04_15_08.678372Z.json

# 2. Check every key is intact, without showing any of them.
s70 verify backup-2026-09-08T04_15_08.678372Z.json

# 3. Recover keys and get the strings to paste into your wallet.
s70 tui backup-2026-09-08T04_15_08.678372Z.json
```

---

## Using the app

```bash
s70 tui backup-2026-09-08T04_15_08.678372Z.json
```

**Consent screen.** Shows what the backup holds and what you're about to do.
Type `RECOVER` and press enter. Nothing is decrypted before this.

**Wallet list.** Every wallet is decrypted, checked and its key immediately
discarded, so the list is complete and accurate as soon as it appears. Each row
shows the chain, the address, and both verification results.

| Key | Where | Does |
|---|---|---|
| `enter` | list | Open the selected wallet |
| `r` | wallet | Show / hide the private key |
| `k` | wallet (Polkadot) | Write the keystore file Talisman needs, with a password |
| `ctrl+c` | anywhere | Copy the current mouse selection |
| `escape` | wallet | Back to the list, discarding the key |
| `escape` | list | Quit |
| `q` | anywhere | Quit |

**Wallet screen.** Three parts:

- **Private key** - the key in every format your wallet might accept, the
  right one first and marked `<-- paste this one`. Hidden until you press `r`.
- **How to import** - the click path for the wallet that takes this key, or,
  where no wallet will take it, what to do instead.
- **Sign with AWS KMS** - the `s70 kms-export` command for this account,
  ready to copy, and the KMS key spec it needs.

Leaving the screen discards the key.

Keys are hidden by default and never printed outside the app, so nothing ends
up in your terminal scrollback. Copying to the clipboard is your call.

---

## Commands

| Command | Network | Keys | What it does |
|---|---|---|---|
| `s70 tui <backup>` | no | yes | The interactive app. **Start here.** |
| `s70 list <backup>` | no | no | List what's in the backup without decrypting. |
| `s70 verify <backup>` | no | briefly | Decrypt and check every key, show none. |
| `s70 kms-prepare <backup>` | no | no | Which AWS KMS key spec each wallet needs, and how to create it. |
| `s70 kms-export --backup <b> --wallet N --params <p> --out <f>` | no | yes | Wrap one key for `aws kms import-key-material`, and write the import token beside it. |

`--wallet` takes an index, a name, or part of an address. `kms-export` also
takes `--wrapping-algorithm`, `--key-spec` and `--key-id` if you need to be
explicit, and `--write-import-token` to put the import token somewhere other
than beside the blob.

**No command opens a network connection, and none prints a private key.**
Keys are only ever shown in the app, where they stay out of your scrollback.
`kms-export` decrypts one key but emits only ciphertext, a public key and a
list of commands.

---

## Using a recovered key

Two routes. Which one you need depends on the chain.

### Import it into a wallet extension

EVM, Solana, Aptos, Sui, Stellar and Polkadot. The app gives you the exact
string that wallet accepts and the click path to paste it into. **Check the
address matches** once it's imported.

Per-wallet instructions: [docs/IMPORT-GUIDE.md](docs/IMPORT-GUIDE.md).

### Export the key to AWS KMS

You import the key into KMS once; after that KMS holds it and signs with it.
Every wallet in the backup can go this route, because KMS takes both curves:
`ECC_SECG_P256K1` for secp256k1 and `ECC_NIST_EDWARDS25519` for Ed25519.

```
  ONLINE                        OFFLINE                       ONLINE
  create-key                    s70 kms-export                import-key-material
  get-parameters-for-import ──▶ (wraps the key)          ──▶  get-public-key
       │  import-parameters.json         │  EncryptedKeyMaterial.bin
       │                                 │  ImportToken.bin
       └────────── USB drive ────────────┴───────── USB drive ─────────▶
```

```bash
s70 kms-prepare backup.json --wallet 27          # what to create; decrypts nothing
# ... create the key and fetch its import parameters online ...
s70 kms-export --backup backup.json --wallet 27 --params import-parameters.json --out EncryptedKeyMaterial.bin
```

`kms-prepare` prints the two online commands you need before you start.
`kms-export` wraps the key, writes `EncryptedKeyMaterial.bin` and
`ImportToken.bin` side by side, and prints the commands you have left.

Two things to know before you start:

- **It is one-way.** KMS never exports the key again. Keep this backup until
  you no longer need the key itself.
- **secp256k1 signatures need post-processing.** KMS returns DER with no
  recovery id and no low-S guarantee, which EVM, Bitcoin and XRPL all reject
  as-is. A KMS signing library handles this; raw `aws kms sign` does not.

Full walkthrough, key specs and failure modes:
[docs/KMS-EXPORT.md](docs/KMS-EXPORT.md).

---

## What's supported

| Chain | Wallet | Import format | Address checked | KMS key spec |
|---|---|---|---|---|
| EVM | Rabby / MetaMask | `0x` + 64 hex | yes | `ECC_SECG_P256K1` |
| Solana | Phantom | base58 | yes | `ECC_NIST_EDWARDS25519` |
| Aptos | Petra | `0x` + 64 hex | yes | either, by key |
| Sui | Suiet | `suiprivkey1…` | yes | either, by key |
| Stellar | Freighter | `S…` | yes | `ECC_NIST_EDWARDS25519` |
| Polkadot | Talisman | keystore file | yes | `ECC_NIST_EDWARDS25519` |
| XRPL | - | - | yes | either, by key |
| Canton | Console Wallet | no known path | yes | `ECC_NIST_EDWARDS25519` |
| Radix | - | raw key only | no | by key |

Every key can be exported to KMS - that column is which key spec to create,
and `s70 kms-prepare` will tell you per wallet. The address-checked column is
about this tool's own verification, not about whether the key works.

Three cases need an extra word:

**Polkadot.** Talisman can't take a pasted Substrate key, so the app writes a
polkadot-js keystore file instead (press `k`). You choose a password and
Talisman asks for the same one. Delete the file once the import worked.

**XRPL.** No wallet extension can import these keys - they all want a 16-byte
seed, and the backup holds the 32-byte key derived from it, which can't be
reversed. [Export it to AWS KMS](docs/KMS-EXPORT.md) and sign there.

**Radix.** The tool has no address derivation for Radix, so those keys show as
`sha-256 only`. The key itself is still recovered and shown, and its checksum
is still verified - you just have to confirm the address in your wallet.

---

## How keys are verified

Every recovered key is checked two ways.

**1. Checksum.** The backup records a hash of the original key. The tool
hashes what it decrypted and compares. This catches corruption and a wrong
recovery key.

**2. Address.** The tool derives the address from the recovered key and
compares it to the address in the backup. This is the one that proves the key
actually controls the account.

| Status | Meaning |
|---|---|
| `verified` | Both checks passed. This is the only status that proves the key opens the account. |
| `sha-256 only` | Key is intact, but this tool has no address derivation for that chain (Radix). |
| `mismatch` | The check ran and the key opens a *different* address. Investigate before using it. |
| `ambiguous` | The address could belong to several chains and the key matched none. |
| `no address` | Your backup recorded no address to compare against. |
| `HASH MISMATCH` | The checksum failed. Don't trust the key. |
| `not recovered` | Nothing has been decrypted yet - the state every wallet is in under `s70 list`. |
| `error` | This wallet could not be decrypted at all. The message says why. |