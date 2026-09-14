# Import guide

How to get a recovered key into a wallet, chain by chain: which string to
copy, where to paste it, and the traps worth knowing about.

The tool shows you every format a wallet might want on the wallet screen.
This page is the click path for the other end.

---

## Two rules that apply everywhere

**1. The format depends on the wallet, not on the key.** Several of these
chains use the same kind of key, and every wallet wants it written
differently:

| Chain | Wallet | Paste this |
|---|---|---|
| EVM | Rabby / MetaMask | `0x` + 64 hex characters |
| Solana | Phantom | base58, 87–88 characters |
| Aptos | Petra | `0x` + 64 hex characters |
| Sui | Suiet | `suiprivkey1…`, 70 characters |
| Stellar | Freighter | `S…`, 56 characters |
| Polkadot | Talisman | a keystore *file* — see below |
| XRPL | none | export to AWS KMS instead — see below |
| Canton | Console Wallet | no known import path |


The tool puts the right one first and marks it `<-- paste this one`. Copy that
line. Don't retype it, and don't trim leading zeros — some wallets check the
length and reject a short key.

**2. After importing, check the address the wallet shows.** It must match the
address the tool showed next to the key. That is the only proof you pasted the
right key into the right place. Do it before sending anything to that account.

---

## EVM — Rabby or MetaMask

Paste `0x` + 64 hex.

**Rabby:** account name at the top → *Add an Address* → *Import Private Key* →
paste → *Confirm*.

**MetaMask:** account selector (top centre) → *Add account or hardware wallet*
→ *Import account* → type *Private Key* → paste → *Import*.

---

## Solana — Phantom

Paste the base58 string (87–88 characters). That is the same form Phantom
exports, so it round-trips cleanly.

**Path:** Phantom → *I Already Have a Wallet* → *Import Private Key* → name
the account → **select the Solana network** → paste → *Import* → set a
password.

The network selector matters: Phantom is multichain and that one field means
different things per network. Pick Solana or you will import an unrelated
address.

The tool also offers a `[12,34,…]` byte array. That is for the `solana-keygen`
CLI, not for Phantom.

> Phantom no longer supports Sui. Don't route Sui through it.

---

## Aptos — Petra

Paste `0x` + 64 hex.

**Path:** Petra → account avatar (top left) → *Add Account* → *Import Private
Key* → paste → confirm.

The tool also shows an `ed25519-priv-0x…` form. It is the newer Aptos standard
and the Aptos CLI accepts it, but try the plain hex first.

**If an Aptos wallet shows `mismatch`,** the key may still be correct. An
Aptos address only equals its key while the key has never been rotated — after
a rotation the address stays and the key changes. Look the account up on an
explorer before concluding the key is wrong.

---

## Sui — Suiet

Paste the `suiprivkey1…` string. All lowercase, 70 characters.

**Path:** Suiet → *I already have a wallet* → paste the private key. For an
extra account: account menu → *Import private key*.

Plain hex import is being phased out across the Sui ecosystem and may already
be rejected, so use the `suiprivkey1…` form. Suiet or Slush both work;
Phantom no longer does.

---

## Stellar — Freighter

Paste the `S…` secret key (56 characters). Stellar never accepts hex, and
never a `0x` prefix.

**Path:** unlock Freighter → avatar menu (top right) → *Import a Stellar
secret key* → paste → enter your Freighter password → tick the
acknowledgement → *Import*.

> Freighter cannot recover an imported secret key from its recovery phrase,
> and warns you about this during import. Keep your backup file until the
> funds have actually moved.

---

## Polkadot — Talisman

Talisman cannot take a pasted Substrate key at all — its private-key field
only accepts Ethereum and Solana keys. You need a keystore file instead, and
the tool writes one for you.

1. Open the Polkadot wallet in the TUI and press **`k`**.
2. Choose where to save the file, and set a password. The keystore is
   encrypted; this password is the only thing protecting it.
3. Talisman → *Add account* → *Import* → *Import from Polkadot.js* → select
   the file → enter that same password.
4. Delete the keystore file once the import has worked.

**If the tool refuses to write a keystore**, the key did not reproduce the
address in your backup, so your account is almost certainly sr25519 — which
this tool cannot rebuild. It refuses on purpose: the file it could produce
would import a *different* address. Don't send funds to that address.

---

## XRPL — no wallet import

No XRPL wallet can import these keys, and no tool can change that.

Gem Wallet, Xaman/Xumm and Crossmark all import a 16-byte *family seed* (or a
mnemonic, or secret numbers — all the same 16 bytes). Your backup holds the
32-byte private key that was derived from those bytes, and that derivation
only runs one way.

So export the key to AWS KMS instead and sign XRPL transactions with the KMS
key. XRPL uses secp256k1 and Ed25519, and KMS imports both, so this works for
every XRPL key in the backup. See [KMS-EXPORT.md](KMS-EXPORT.md) — and note
that secp256k1 signatures out of KMS need DER parsing and low-S normalisation
before XRPL will take them.

This format never stores the 16 bytes, only the derived key, so there is no
family seed for the tool to show you and no setting that will produce one.

---

## Canton — no known import path

Console Wallet documents importing a *Party ID + Seed Phrase* only, and no key
format is published anywhere, so there is no click path to give you.

The tool still recovers the key and shows it as raw hex, base64 and PKCS#8
PEM. Hand it to whoever runs your Canton participant node — base64 of the raw
key is the form Digital Asset's own tutorial produces. Note that Canton nodes
store keys as protobuf rather than PEM, so the PEM cannot be fed to a node
directly.

A Canton party id ends in a fingerprint of the signing public key, and the
tool recomputes it, so Canton keys do get a real address check and normally
show `verified`.

The construction is reconstructed from one real account rather than from
published documentation. That makes a match trustworthy — reproducing a
SHA-256 digest is not luck — but a `mismatch` less so: it may mean your party
uses a scheme the tool doesn't know. Check the party id with whoever runs your
participant node before concluding the key is wrong.

Canton keys are Ed25519, so they can also be exported to AWS KMS
([KMS-EXPORT.md](KMS-EXPORT.md)) if signing there suits your node operator
better than handing over the raw key.

---

## Radix and anything else

Keys on chains this tool has no address derivation for — Radix, for instance —
are still decrypted and shown. They report `sha-256 only`: the key is intact,
but the tool cannot prove which account it opens, and it has no
wallet-specific guidance to offer. The wallet screen says as much next to the
key rather than leaving you to work it out from the status word.

Import it, then confirm the address in your wallet before moving anything.
