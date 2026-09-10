# Backup format reference

What this tool reads, how it decrypts it, and how it decides a key is
genuine.

---

## File schema

```json
{
  "wallet_provider": "CrypDefi",
  "recovery_key": "<base64 DER RSA private key>",
  "keys": [
    {
      "key_name": "Treasury EVM",
      "shares": [
        {
          "metadata": {
            "address": "0x6cdd10c0…",
            "chain": "evm",
            "curve": "secp256k1",
            "public_key": "…"
          },
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

### Field reference

| Field | Required | Notes |
|---|---|---|
| `wallet_provider` | no | Display only. |
| `recovery_key` | no* | base64 DER (PKCS#8) RSA private key. A PEM block is also accepted. |
| `keys[]` | **yes** | One entry per wallet key. |
| `keys[].key_name` | no | Display name. Falls back to `<unnamed>`. |
| `keys[].shares[]` | **yes** | One or more encrypted shares. |
| `…metadata.address` | no | The cross-check. Without it, verification is SHA-256 only. |
| `…metadata.chain` | no | If present, narrows chain detection. Still has to pass the address check. |
| `…metadata.curve` | no | Advisory. |
| `…metadata.public_key` | no | Advisory. |
| `…encryption.ciphersuite` | no | Expected `RSA-4096-OAEP-SHA256`. A mismatch is recovered from, not fatal. |
| `…encryption.ciphertext` | **yes** | base64 RSA-OAEP ciphertext. |
| `…encryption.original_sha256` | no | base64 (or hex) SHA-256 of the plaintext. |

\* Either `recovery_key` must be present, or `--recovery-key` must point at
the key file. The backup private key is yours, not the provider's; the
provider only ever held the corresponding public key.

---

## Decryption

RSA-OAEP, as in the original `recover_wallets.py`:

```
plaintext = RSA_OAEP_Decrypt(
    ciphertext,
    private_key,
    mgf       = MGF1(SHA-256),
    algorithm = SHA-256,
    label     = None,
)
```

### Why several hash combinations are tried

If the declared ciphersuite does not work, the tool tries, in order:

| Label | Message digest | MGF1 |
|---|---|---|
| `OAEP-SHA256` | SHA-256 | SHA-256 |
| `OAEP-SHA1` | SHA-1 | SHA-1 |
| `OAEP-SHA384` | SHA-384 | SHA-384 |
| `OAEP-SHA512` | SHA-512 | SHA-512 |
| `OAEP-SHA256-MGF1-SHA1` | SHA-256 | SHA-1 |

This is safe rather than sloppy, because **OAEP decoding is itself an
integrity check**. A wrong hash choice fails the padding check and raises; it
does not return plausible-but-wrong plaintext. `original_sha256` then confirms
the result independently.

The attempt order puts the declared ciphersuite first, and the UI reports
which variant actually worked and whether it disagreed with the label.

### Ciphertext length

Checked up front against the recovery key's modulus size. A share whose
ciphertext is not exactly `key_size / 8` bytes was encrypted to a different
backup public key, and the tool says so rather than reporting an opaque
padding failure.

---

## Plaintext encodings

The ciphersuite says how the key was *encrypted*, not how it was *encoded*.
Several shapes occur in practice, because different chains' key types get
marshalled differently by whatever produced the backup.

| Length | Shape | Curve |
|---|---|---|
| 32 | raw scalar / Ed25519 seed | **ambiguous** |
| 48 | PKCS#8 Ed25519 (`302e020100300506032b657004220420` + 32 bytes) | Ed25519 |
| 64 | `seed ‖ public_key` (libsodium / Go `ed25519.PrivateKey`) | Ed25519 |
| 16 | XRPL family-seed entropy | ambiguous |
| 33 | `0x00` + 32 bytes (big-integer zero pad) | ambiguous |
| varies | DER PKCS#8 / SEC1 EC private key | from the OID |
| varies | ASCII hex or base64 of any of the above | recursed |

### The 32-byte ambiguity, and why it is not guessed

The same 32 bytes are a valid Ed25519 seed **and** a valid secp256k1 scalar.
There is no way to tell from the bytes.

So the parser returns a **candidate per curve** and lets address matching
decide. This is why the address check is load-bearing rather than
decorative — it is not merely validating a result, it is *choosing* one.

For a 64-byte plaintext the embedded public key is checked against the one
derived from the seed, and a disagreement is a hard error rather than a
warning: it means the plaintext is not what it appears to be.

---

## Verification

Two independent checks.

### 1. SHA-256

```
base64(sha256(plaintext)) == encryption.original_sha256
```

Hex is also accepted, for robustness. Absent field → status `no hash in
backup`, which is reported rather than silently treated as a pass.

### 2. Address re-derivation

```
private key ──▶ public key ──▶ address ──▶ compare to metadata.address
```

Per-chain derivations:

| Chain | Public key | Address |
|---|---|---|
| EVM | secp256k1 X‖Y (64 B) | `EIP55(keccak256(pub)[12:32])` |
| Solana | Ed25519 (32 B) | `base58(pub)` |
| Aptos | Ed25519 (32 B) | `sha3_256(pub ‖ 0x00)`, plus SingleKey variants |
| Sui | Ed25519 (32 B) | `blake2b_256(flag ‖ pub)` |
| Stellar | Ed25519 (32 B) | StrKey `G…`, version `0x30` |
| Polkadot | Ed25519 (32 B) | `base58(prefix ‖ pub ‖ blake2b_512("SS58PRE" ‖ prefix ‖ pub)[:2])` |
| XRPL | compressed secp256k1, or `0xED ‖ pub` | base58check-XRPL(`0x00 ‖ ripemd160(sha256(pub))`) |
| Canton | Ed25519 (32 B) | **not reproducible offline** |

Several chains return **multiple candidates** and a match on any one counts:

- Aptos: legacy plus two SingleKey BCS variants (the BCS layout is inferred).
- Polkadot: prefixes 0, 2 and 42.
- Canton: raw key, DER SPKI, and a range of hash-purpose prefixes — all
  speculative.

### Two things the address check does beyond validating

**It resolves shape collisions.** Aptos and Sui addresses are both `0x` + 64
hex. Solana and Polkadot are both base58. No regex can separate them;
derivation can. (Solana decodes to exactly 32 bytes with no checksum, SS58 to
35 with one — that narrows it, but derivation is what confirms it.)

**It proves the decryption.** Successful OAEP unpadding tells you the
ciphertext was well-formed. A matching address tells you the plaintext is the
key for that account.

---

## Status values

| Status | Meaning | Action |
|---|---|---|
| `verified` | Both checks passed. | Use it. |
| `unverifiable` | Chain identified but its address cannot be recomputed offline (Canton only). | Rests on SHA-256 alone. |
| `mismatch` | Checked and wrong. | Investigate before using. Rotated Aptos key? sr25519 Polkadot account? |
| `ambiguous` | Shape matched several chains, key reproduced none. | The key is probably not for this address. |
| `unsupported` | No supported chain matches the address format. | Skipped. `--include-unsupported` to decrypt anyway. |
| `no-address` | Backup recorded no address. | SHA-256 only. |

---

## The batch-backup format (not supported)

A different CrypDefi backup format exists and this tool deliberately does not
read it. The loader detects it and explains why rather than failing
obscurely.

```json
[
  {
    "encrypted_key": "<hex>",
    "timestamp": "…",
    "wallet_address": "…",
    "wallet_public_key": "<hex>"
  }
]
```

`encrypted_key` is **hex**, not base64, and decodes to an ECIES envelope:

```
offset 0      : uint64 big-endian  = L, length of the ephemeral public key blob
offset 8      : L bytes            = DER SubjectPublicKeyInfo of the ephemeral key
offset 8+L    : 16 bytes           = AES-GCM IV
offset 24+L   : N bytes            = ciphertext
last 16 bytes :                     = GCM tag
```

Observed in the wild with `L = 44` and OID `1.3.101.110` — **X25519**. Note
that the published spec describes ECIES over secp256k1, P-256, P-384 or P-521
with a *raw* 65-byte uncompressed point and no length prefix, so the real
output and the documentation disagree on both curve and framing.

Decryption would be: X25519 ECDH against the client's backup private key,
HKDF-SHA256 to a 16-byte AES key, then AES-128-GCM. Two reasons it is out of
scope here:

1. The HKDF salt and info parameters are unspecified, so they would have to
   be discovered by trial. (Feasible — the GCM tag is an unambiguous oracle —
   but it is guesswork all the same.)
2. There is **no `recovery_key` in the file**. The ephemeral public key
   belongs to the sender; decryption needs the recipient's X25519 private
   key, which is held separately.

If you need that format, it is a separate implementation, not a flag on this
one.
