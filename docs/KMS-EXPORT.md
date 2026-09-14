# Exporting a key to AWS KMS

This is the route for keys no wallet extension will take — XRPL above all —
and for anywhere you'd rather not put a private key in a browser.

You import the key into AWS KMS once. After that KMS holds it and signs with
it, using whatever tooling you prefer.

Both curves in the backup are supported, so every wallet in it can go this
route:

| Your key | KMS key spec | Signing algorithm | `--message-type` |
|---|---|---|---|
| secp256k1 | `ECC_SECG_P256K1` | `ECDSA_SHA_256` | `RAW` or `DIGEST` |
| Ed25519 | `ECC_NIST_EDWARDS25519` | `ED25519_SHA_512` | `RAW` |

`s70 kms-prepare` tells you which one each wallet needs, without decrypting
anything.

---

## Read this first

**It is one-way.** KMS will never give the key back. Once imported you cannot
export it, and neither can anyone else — which is the point, but it means the
backup file is still your only copy of the key itself. Keep it until the funds
have actually moved.

**Ed25519 in KMS is recent.** If `create-key` rejects
`--key-spec ECC_NIST_EDWARDS25519`, your region does not have it yet. The blob
this tool writes stays valid for whenever it does.

**Use `ED25519_SHA_512` with `MessageType:RAW`, not `ED25519_PH_SHA_512`.**
The first is PureEdDSA, which is what Solana, Stellar, Aptos and Sui verify.
The second is HashEdDSA, and KMS re-hashes what you send it — no chain here
accepts the result. The two are not interchangeable and KMS will not warn you.

**secp256k1 signatures need post-processing.** `aws kms sign` returns a
DER-encoded ECDSA signature with no recovery id, and does not guarantee
low-S. EVM, Bitcoin and XRPL all want a compact 64-byte signature, so you must
parse the DER, normalise S into the lower half of the curve order, and recover
`v` by trying both. Any KMS signing library does this; a raw `aws kms sign`
does not. If that sounds like work you don't want, import into a wallet
extension instead.

---

## The four steps

Two machines. The offline one has your backup and never gets a network
connection; the online one has your AWS credentials and never sees a key.

```
  ONLINE                        OFFLINE                       ONLINE
  create-key                    s70 kms-export                import-key-material
  get-parameters-for-import ──▶ (wraps the key)          ──▶  get-public-key
       │  import-parameters.json         │  EncryptedKeyMaterial.bin
       │                                 │  ImportToken.bin
       └────────── USB stick ────────────┴───────── USB stick ─────────▶
```

`s70 kms-prepare` prints steps 1 and 2 filled in for your actual wallets — pass
`--wallet` and it names that wallet in the key description too. What follows is
the same thing explained.

### 1. Find out what you need (offline, decrypts nothing)

```bash
s70 kms-prepare backup.json --wallet 27 --region eu-west-1
```

### 2. Create an empty KMS key (online)

```bash
aws kms create-key \
  --key-spec ECC_SECG_P256K1 \
  --key-usage SIGN_VERIFY \
  --origin EXTERNAL \
  --description "s70 recovered tert" \
  --region eu-west-1
```

`--origin EXTERNAL` means the key starts with no key material and can never be
switched to generating its own. Note the `KeyId`.

### 3. Download the import parameters (online)

```bash
aws kms get-parameters-for-import \
  --key-id <key-id> \
  --wrapping-algorithm RSA_AES_KEY_WRAP_SHA_256 \
  --wrapping-key-spec RSA_4096 \
  --region eu-west-1 > import-parameters.json
```

Two things about this file:

- The `PublicKey` and `ImportToken` are an **indivisible pair** and expire
  together after **24 hours**. Never mix them with another download's — the
  result is a blob KMS rejects with an unhelpful error, and another 24 hours
  gone.
- The wrapping algorithm you chose here is **not recorded in the response**.
  `s70 kms-export` has to be told the same one, or it defaults to
  `RSA_AES_KEY_WRAP_SHA_256` and says that it assumed it.

Carry `import-parameters.json` to the offline machine.

### 4. Wrap the key (offline)

```bash
s70 kms-export \
  --backup backup.json \
  --wallet 27 \
  --params import-parameters.json \
  --out EncryptedKeyMaterial.bin
```

`--params` also accepts the AWS console's import-parameters download — either
the `.zip` or the folder you unzipped it into. That form carries a `README.txt`
naming the wrapping algorithm, so the tool reads it rather than assuming.

This writes **two** files, side by side:

- `EncryptedKeyMaterial.bin` — your key, wrapped. Encrypted to AWS's own HSM
  public key, so it is useless to anyone else.
- `ImportToken.bin` — the import token from `import-parameters.json`, decoded
  to the raw bytes `--import-token` needs. It is public, not secret.

Carry **both** across, into the same directory. `--import-key-material` needs
the pair, and pairing a blob with a token from a different download is the
most common way this fails.

`kms-export` prints the remaining commands, filled in and ready to paste. It
also prints a SHA-256 fingerprint of the public key — **keep that**, step 6
needs it.

### 5. Import it (online)

Run this from the directory holding the two files:

```bash
aws kms import-key-material \
  --key-id <key-id> \
  --encrypted-key-material fileb://EncryptedKeyMaterial.bin \
  --import-token fileb://ImportToken.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE \
  --region eu-west-1
```

Use `--write-import-token PATH` on step 4 if you want the token somewhere
else; it is written either way.

### 6. Check it landed on the right key (online)

**Do this before you rely on the key.**

```bash
aws kms get-public-key --key-id <key-id> --region eu-west-1 \
  --query PublicKey --output text | base64 -d | openssl dgst -sha256
```

That must print the fingerprint `s70 kms-export` gave you. The tool computed it
from the private key in your backup, before anything was wrapped, so a match
proves KMS is holding the key for the account you meant.

If it differs, the material went to the wrong key. Disable that KMS key and
work out what happened — do not sign with it.

---

## When it goes wrong

| What you see | What it means |
|---|---|
| `InvalidCiphertextException` on import | Wrong wrapping algorithm, or the public key and import token came from different downloads. Re-run step 3 and redo 4–5 with a matching pair. |
| `ExpiredImportTokenException` | The 24 hours ran out. Re-run step 3; the key itself is fine and still pending import. |
| `IncorrectKeyMaterialException` | The material does not match the key spec — an Ed25519 key against an `ECC_SECG_P256K1` KMS key, or vice versa. Check `s70 kms-prepare`. |
| `create-key` rejects the key spec | For Ed25519, the region does not offer it yet. For secp256k1, your AWS CLI may be old enough to want `--customer-master-key-spec`. |
| `s70 kms-export` warns about expiry | Its own clock said the parameters look stale. It still wrote a correct blob. If the import then fails, re-run step 3. |
| `refusing to overwrite an existing file` | Deliberate. Move or delete the old blob; each import needs a freshly wrapped one anyway. |
| `already exists and holds a different import token` | An `ImportToken.bin` from an earlier download is sitting where this one would go. Move it aside — pairing it with this wrapping key gives a blob KMS rejects. |
| `No such file or directory: 'ImportToken.bin'` | You are running the import from a different directory than the two files. `cd` to them, or give full paths. |

---

## How the wrapping works

The key is wrapped exactly as AWS specifies: a fresh 32-byte AES key, the
private key as unencrypted PKCS#8 DER wrapped with AES-KWP (RFC 5649), that
AES key encrypted to the RSA wrapping key with OAEP, and the two concatenated
with the AES key first.

This happens offline, with no `boto3` and no network code. Your AWS
credentials are never involved, and the unencrypted PKCS#8 DER is never
written anywhere — the only thing that leaves is ciphertext.

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
