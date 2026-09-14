# Your backup file

What is in the Station70 backup file, and what the tool needs from it.

You don't need any of this to use the tool. Read it if a wallet shows a status
you want explained, or if you want to know whether your file is complete.

---

## What the file contains

One JSON file, holding two things:

- **your wallet keys**, each encrypted, and
- **the recovery key** that decrypts them.

That is why there is no passphrase and no second file to hunt down. It also
means anyone who has this file has your keys — keep it offline, and delete it
when you are done.

```json
{
  "recovery_key": "<the key that decrypts everything below>",
  "keys": [
    {
      "key_name": "Treasury EVM",
      "key_type": "ECDSA_SECP256k1",
      "shares": [
        {
          "metadata": { "address": "0x…", "chain_id": "ch-60" },
          "encryption": {
            "ciphertext": "<your encrypted private key>",
            "original_sha256": "<checksum of that private key>"
          }
        }
      ]
    }
  ]
}
```

---

## What happens if a field is missing

| Field | If it is missing |
|---|---|
| `recovery_key` | Nothing can be decrypted. The file is truncated, or is not a Station70 backup. |
| `ciphertext` | That one wallet cannot be recovered. |
| `original_sha256` | The key still decrypts; the tool just cannot checksum it. |
| `address` | The key still decrypts; the tool cannot confirm which account it opens. |
| `chain_id` | The chain is worked out from the address shape instead. Aptos and Sui look identical, so they are separated by deriving both and seeing which matches. |
| `key_type` | The tool derives both curves and keeps whichever matches your address. |
| `key_name` | The wallet is listed as `<unnamed>`. |

Only `recovery_key` and `ciphertext` are essential. Miss anything else and you
lose a cross-check, which the tool reports on screen rather than hiding.

---

## What the tool does with it

1. **Decrypts** each wallet key, using the recovery key from the file itself.
2. **Reads the key.** Station70 stores keys in several different shapes
   depending on the chain; all of them are handled.
3. **Checks it twice** — the checksum in the backup must match, and the address
   derived from the key must equal the address in the backup.

The last check is the one that matters: it proves the key really opens the
account shown beside it.

Two details, in case a file of yours looks unusual:

- **`original_sha256` may be base64 or hex.** Both are accepted.
- **The file records the key it was encrypted to.** The tool compares it with
  the `recovery_key` inside the file before decrypting anything, so a spliced
  or edited backup says so once rather than failing on every wallet.
- **The encryption is RSA-OAEP, and the digest is not always SHA-256.**
  `ciphersuite` says which it should be, but the tool tries SHA-256, SHA-1,
  SHA-384, SHA-512 and SHA-256-with-MGF1-SHA-1 in turn, starting with whatever
  the file declares. Trying several is safe: OAEP padding is self-validating,
  so a wrong digest fails to decrypt rather than returning wrong bytes.

---

## Statuses you may see

| Status | What it means | What to do |
|---|---|---|
| `verified` | Both checks passed. | Use the key. |
| `sha-256 only` | Key is good and the checksum matched, but this tool has no address derivation for that chain (Radix). | Import it, then check the address in your wallet before moving funds. |
| `no address` | Your backup recorded no address to compare against. | As above. |
| `ambiguous` | The address could belong to several chains, and the key matched none of them. | Don't send funds to it until a wallet confirms the address. |
| `mismatch` | The check ran and the key opens a *different* address. | Stop — see [mismatch in the README](../README.md#troubleshooting); on Aptos, Polkadot and Canton there are known, harmless causes. |
| `HASH MISMATCH` | The checksum failed — the decrypted bytes are not the key that was backed up. | Don't use that key. |

Only `verified` proves the key opens the account. Everything else means the
proof is missing, for one reason or another, and the tool names the reason.

Error messages and what to do about them:
[README troubleshooting](../README.md#troubleshooting).
