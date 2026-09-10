# Import guide

How to get a recovered private key into each browser extension: the exact
string format, the exact click path, and the caveats that will otherwise cost
you an hour.

## The one thing to understand first

Four of the eight supported chains use Ed25519. Every one of them wants a
**different string built from the same 32 bytes**:

| Chain | Wallet | What it wants | Length |
|---|---|---|---|
| Solana | Phantom | base58 of `seed ‖ public_key` (64 bytes) | 87–88 |
| Stellar | Freighter | StrKey `S…` of the 32-byte seed | 56 |
| Sui | Suiet | bech32 `suiprivkey1…` of `flag ‖ seed` | 70 |
| Aptos | Pontem | `0x` + 64 hex of the seed | 66 |

So the format is chosen by **target wallet**, never by curve. Pasting a
Stellar `S…` key into Suiet does nothing useful, and pasting a bare 32-byte
hex key into Phantom will either fail or — worse — import an unrelated
address.

**Always confirm the address the wallet shows after import matches the address
you expected.** That is the only check that proves you pasted the right thing
in the right place. Do it before sending anything to it.

---

## EVM — Rabby or MetaMask

**Format:** `0x` + exactly 64 hex characters. Curve: secp256k1.

The `0x` prefix is optional in both wallets — they normalise it. The
**length is not optional**: MetaMask validates the length of the
`0x`-prefixed string, so a key with leading zeros must keep them. `0x0f3a…`
padded to 64 digits is correct; trimming to 63 gets rejected even though the
number is the same.

**Rabby:** click the account name at the top → *Add an Address* →
*Import Private Key* → paste → *Confirm*.

**MetaMask:** account selector (top centre) → *Add account or hardware
wallet* → *Import account* → type *Private Key* → paste → *Import*.

Address derivation, for reference:
`EIP55(keccak256(uncompressed_public_key)[12:32])`. Note that is **original
Keccak-256**, not NIST SHA3-256.

---

## Solana — Phantom

**Format:** base58 of the **64-byte** secret key, i.e. `seed ‖ public_key`.
This is the form Phantom exports itself, so it round-trips cleanly.

Phantom's help pages document no format at all, which is the largest
documentation gap of the eight wallets here. Two things follow:

- Base58 of the bare 32-byte seed (43–44 characters) is **undocumented**.
  It may work; do not rely on it.
- The JSON byte array `[12,34,…]` is the `solana-keygen` / `id.json` format
  for the Solana CLI, **not** a Phantom input. This tool offers it as a
  secondary format for exactly that purpose.

**Path:** Phantom → *I Already Have a Wallet* → *Import Private Key* → name
the account → **select the Solana network** → paste → *Import* → set a
password.

That network selector matters. Phantom is multichain and the same field means
different things per network — hex for Ethereum, WIF for Bitcoin, base58 for
Solana. Get it wrong and you import an unrelated address.

Address: `base58(public_key)`. No version byte, no checksum.

> Phantom dropped Sui support. Do not route Sui recovery through it.

---

## Aptos — Pontem

**Primary format:** `0x` + 64 hex. This is what Pontem's documentation
describes ("an alphanumeric string starting with 0x").

**Secondary format:** AIP-80 prefixed — `ed25519-priv-0x…`. This is the
standardised Aptos form and the SDKs and CLI accept it. Pontem is closed
source, so whether *it* does is unverified. **Try the plain hex first.**

**Path:** Pontem → account avatar → *Add account* → *Import an Account* →
paste → confirm.

### The rotated-key caveat

An Aptos account's address equals its authentication key **only if the key has
never been rotated**. After a rotation the address stays put while the key
changes. So a `mismatch` status on an Aptos wallet does *not* prove the key is
wrong — it may well be the current signing key for that account.

Check the account's `OriginatingAddress` / account resource on an explorer
before concluding anything.

Authentication key schemes this tool checks against:

- legacy Ed25519: `sha3_256(public_key ‖ 0x00)`
- unified SingleKey: `sha3_256(bcs(AnyPublicKey) ‖ 0x02)`

The BCS layout for the second is inferred rather than confirmed, so several
variants are tried and a match on any is accepted.

---

## Sui — Suiet

**Format:** bech32, `suiprivkey1…`, exactly 70 characters, all lowercase.

Per SIP-15 the payload is 33 bytes: a 1-byte scheme flag followed by the
32-byte key. Flags are Ed25519 `0x00`, secp256k1 `0x01`, secp256r1 `0x02`.

Two details worth internalising:

- It is plain **bech32**, not bech32m. Encoding with bech32m produces a
  string that still starts `suiprivkey1` and fails checksum validation inside
  the wallet.
- The flag byte is **inside the address hash** —
  `0x` + hex of `blake2b_256(flag ‖ public_key)`. So the same 32 bytes give a
  different Sui address under Ed25519 than under secp256k1. This is also what
  lets the tool tell a Sui address from an Aptos one despite identical shapes.

Hex import is deprecated ecosystem-wide and may already be rejected. This
tool emits bech32 as primary and marks hex as legacy. To convert manually:
`sui keytool convert <HEX>`.

**Path:** Suiet → *I already have a wallet* → paste the private key. For an
extra account: account menu → *Import private key*.

> The Suiet repository is no longer public, so current hex acceptance could
> not be verified from source.

---

## Stellar — Freighter

**Format:** StrKey secret seed — `S` + 55 characters, 56 total. Stellar never
accepts hex, and never a `0x` prefix.

The encoding, in full, because it is easy to get subtly wrong:

1. version byte `0x90` = `(18 << 3) | 0` — key type 18 (private key),
   algorithm 0 (Ed25519). Renders as a leading `S`.
2. payload: the raw 32-byte Ed25519 seed.
3. checksum: CRC-16/XMODEM over `version ‖ payload`, appended
   **little-endian** (low byte first).
4. RFC 4648 base32, alphabet `A–Z2–7`, **no padding**.

35 bytes is exactly 280 bits = 56 base32 characters, so a correct StrKey never
carries a `=`. Appending the checksum big-endian produces a 56-character
string that Freighter rejects with a generic error — a miserable thing to
debug, which is why this tool round-trip-asserts every StrKey before emitting
it.

Public keys use version byte `0x30` and render as `G…`.

**Path:** unlock Freighter → avatar menu (top right) → *Import a Stellar
secret key* → paste → enter your Freighter password → tick the
acknowledgement → *Import*.

> Freighter **cannot recover an imported secret key from its recovery
> phrase**, and says so during import. Keep the backup file until the funds
> have actually moved.

---

## Polkadot — Talisman

**There is no paste-able format.** Talisman's private-key import field is
limited to Ethereum and Solana; Substrate accounts arrive only via mnemonic,
Ledger, Polkadot Vault QR, or a **polkadot-js JSON keystore**.

So the flow is a file:

```bash
s70 keystore backup.json --wallet 5 --out polkadot-keystore.json
```

You will be asked for a password — Talisman asks for the same one on import.

**Path:** Talisman → *Add account* → *Import* → *Import from Polkadot.js* →
select the file → enter the password.

### Keystore structure

```
{
  "encoded": base64( salt(32) ‖ N(u32 LE) ‖ p(u32 LE) ‖ r(u32 LE)
                     ‖ nonce(24) ‖ secretbox_output ),
  "encoding": { "content": ["pkcs8","ed25519"],
                "type": ["scrypt","xsalsa20-poly1305"],
                "version": "3" },
  "address": "<ss58>",
  "meta": { "name": "…", "whenCreated": <ms> }
}
```

The encrypted plaintext is polkadot-js's own framing:
`PKCS8_HEADER(16) ‖ secretKey(64) ‖ PKCS8_DIVIDER(5) ‖ publicKey(32)`.

Two things are easy to get wrong and both produce a file that imports as the
**wrong account** rather than failing loudly:

- `secretKey` is the **64-byte** libsodium form (`seed ‖ public_key`), not the
  32-byte seed.
- `N` must be exactly **32768**. polkadot-js hard-checks
  `N == 32768 && p == 1 && r == 8` when reading a keystore. This is not a
  tunable.

### The sr25519 limitation

Substrate accounts are usually **sr25519**. This tool only handles **Ed25519**
Substrate accounts, because sr25519 has no implementation in its dependency
set and its keystore form needs the 64-byte *expanded* key rather than the
32-byte mini-secret.

Detection is by address: if the Ed25519 public key derived from the recovered
key reproduces the recorded SS58 address, it is an Ed25519 account. If it does
not, it is almost certainly sr25519 — and the tool refuses to write a
keystore rather than producing one that imports a different address.

SS58 note: the same public key renders differently per network prefix
(Polkadot 0, Kusama 2, generic 42). Compare public keys, not address strings.

---

## XRPL — Gem Wallet

**Read this before anything else.** XRPL has a hard structural limit that no
tool can work around.

Every XRPL wallet — Gem Wallet, Xaman/Xumm, Crossmark — imports one of:

- a **family seed**: `s…` (29 chars, secp256k1) or `sEd…` (31 chars, Ed25519)
- a mnemonic
- secret numbers (8 groups of 6 digits)

All three encode the **same 16 bytes of entropy**. The account's 32-byte
private key is *derived* from that entropy by a one-way function.

So:

| What the backup holds | Can you import it? |
|---|---|
| 16 bytes of entropy | **Yes** — this tool encodes both family-seed forms |
| 32-byte derived private key | **No wallet on earth can import it** |

If it is a derived key, your options are:

1. **Sign offline with this tool.** `s70 inspect` + `s70 sign` build and sign
   an `AccountDelete` that sweeps the entire balance. This works because
   xrpl-py's low-level signing accepts a private key directly, bypassing the
   `Wallet.from_seed` path.
2. **`SetRegularKey`** — use the key as a regular key on an account you still
   control.

**Path (if you do have a seed):** Gem Wallet → wallet icon → **+** → confirm
password → *Import a new wallet* → *Seed* → paste.

### The algorithm checkbox

Gem Wallet has an explicit secp256k1 checkbox. With it unchecked, xrpl.js
infers the algorithm from the prefix: `sEd…` → Ed25519, anything else →
secp256k1.

This matters because **the same 16-byte seed produces two different accounts**
depending on the algorithm. This tool emits both family-seed forms; pick the
one whose address matches your account, and check the address the wallet
shows after import.

Address derivation: `AccountID = RIPEMD160(SHA256(public_key))`, then
base58check with version byte `0x00` and XRPL's own base58 alphabet
(`rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz` — a different
permutation from Bitcoin's). The public key is 33 bytes: compressed
secp256k1, or `0xED ‖ public_key` for Ed25519.

---

## Canton — Console Wallet

**No confirmed import path exists.** This is the weakest-supported chain here
and the tool does not pretend otherwise.

Console Wallet's documented import is *"Party ID + Seed Phrase"*. Its store
listing mentions key import/export, but no key encoding is published
anywhere, and the extension is closed source. `consolewallet.io` blocks
automated fetches, so even that much is second-hand.

What this tool gives you, for whoever operates your Canton participant node:

- **base64 of the raw 32 bytes** — matches what Digital Asset's external-party
  tutorial produces (`openssl genpkey -algorithm ed25519`, raw key, base64)
- **PKCS#8 PEM** — standard, but note Canton nodes store keys as **protobuf**,
  not PEM, so importing this into a node directly fails with
  *"Protocol message contained an invalid tag"*
- **raw hex**

### Why Canton keys show as `unverifiable`

A Canton party id is `<hint>::<fingerprint>`, where the fingerprint is a hash
of the signing public key computed inside Canton with a "hash purpose" domain
separator over a protobuf serialisation. That construction is not published in
a form that can be reproduced and verified offline.

The tool computes candidate fingerprints (raw key, DER SPKI, and a range of
purpose prefixes) and reports a match as a bonus — but **a mismatch proves
nothing**. Canton key integrity therefore rests on the `original_sha256`
check and on the plaintext being a well-formed Ed25519 key.

---

## Unsupported chains

Anything outside the eight above — Radix (`account_rdx1…`), for instance — is
**skipped with a warning**. The address is shown in the inventory marked
`unsupported` and nothing is decrypted.

To get the raw key bytes anyway:

```bash
s70 list backup.json --include-unsupported
s70 tui backup.json --include-unsupported
```

You get the decrypted key and its SHA-256 verification, but no address
verification and no wallet-specific guidance — the tool does not know how to
derive that chain's address, so it cannot prove the key is the right one.
