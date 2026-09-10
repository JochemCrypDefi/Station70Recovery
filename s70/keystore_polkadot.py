"""polkadot-js v3 keystore writer, for importing into Talisman.

Talisman cannot import a raw Substrate private key, so this is the only way
to get a recovered Ed25519 Substrate account into it. The file is imported
via *Add account -> Import -> Import from Polkadot.js*.

The keystore is encrypted. polkadot-js does define an unencrypted form
(``encoding.type == ["none"]``), but Talisman rejects it on import, so the
password is required rather than optional.

File layout::

    {
      "encoded": base64( salt(32) || N(u32 LE) || p(u32 LE) || r(u32 LE)
                         || nonce(24) || secretbox_output ),
      "encoding": { "content": ["pkcs8", "ed25519"],
                    "type": ["scrypt", "xsalsa20-poly1305"],
                    "version": "3" },
      "address": "<ss58>",
      "meta": { "name": "...", "whenCreated": <ms> }
    }

The encrypted plaintext is polkadot-js's own PKCS#8-ish framing::

    PKCS8_HEADER(16) || secretKey(64) || PKCS8_DIVIDER(5) || publicKey(32)

Two details are easy to get wrong and both produce a file that imports as the
*wrong account* rather than failing loudly:

* ``secretKey`` is the **64-byte** libsodium form (seed || public key), not
  the 32-byte seed.
* ``N`` must be exactly 32768. polkadot-js hard-checks ``N == 32768 &&
  p == 1 && r == 8`` when reading a keystore and rejects anything else, so
  this is not a tunable in practice.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import nacl.secret

from s70.codecs import ss58
from s70.errors import S70Error
from s70.keymaterial import ed25519_public_from_seed

#: polkadot-js constants. The header carries the Ed25519 OID (1.3.101.112)
#: and is used verbatim for both ed25519 and sr25519 keystores.
PKCS8_HEADER = bytes([48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32])
PKCS8_DIVIDER = bytes([161, 35, 3, 33, 0])

#: polkadot-js validates these exact values on import.
SCRYPT_N = 1 << 15
SCRYPT_P = 1
SCRYPT_R = 8

#: scrypt needs N * r * 128 bytes = 32 MiB here. Python's default maxmem is
#: right on that boundary, so ask for headroom explicitly.
_SCRYPT_MAXMEM = 64 * 1024 * 1024

NONCE_BYTES = 24
SALT_BYTES = 32


def build_keystore(
    seed: bytes,
    password: str,
    name: str,
    *,
    ss58_prefix: int = ss58.PREFIX_POLKADOT,
    scrypt_n: int = SCRYPT_N,
) -> dict[str, Any]:
    """Build an encrypted polkadot-js v3 keystore for an Ed25519 account."""
    if len(seed) != 32:
        raise S70Error(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    if not password:
        raise S70Error(
            "a keystore password is required -- Talisman will ask for it on import"
        )

    public_key = ed25519_public_from_seed(seed)
    secret_key = seed + public_key  # libsodium's 64-byte secret key

    plaintext = PKCS8_HEADER + secret_key + PKCS8_DIVIDER + public_key

    salt = os.urandom(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=scrypt_n,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=nacl.secret.SecretBox.KEY_SIZE,
        maxmem=_SCRYPT_MAXMEM,
    )

    nonce = os.urandom(NONCE_BYTES)
    box = nacl.secret.SecretBox(derived)
    # .ciphertext is the libsodium secretbox output (16-byte MAC || ciphertext);
    # the nonce is stored separately, so do not use the combined form.
    encrypted = box.encrypt(plaintext, nonce).ciphertext

    encoded = (
        salt
        + scrypt_n.to_bytes(4, "little")
        + SCRYPT_P.to_bytes(4, "little")
        + SCRYPT_R.to_bytes(4, "little")
        + nonce
        + encrypted
    )

    return {
        "encoded": base64.b64encode(encoded).decode("ascii"),
        "encoding": {
            "content": ["pkcs8", "ed25519"],
            "type": ["scrypt", "xsalsa20-poly1305"],
            "version": "3",
        },
        "address": ss58.encode(public_key, ss58_prefix),
        "meta": {
            "name": name,
            "whenCreated": int(time.time() * 1000),
        },
    }


def write_keystore(
    path: str | Path,
    seed: bytes,
    password: str,
    name: str,
    *,
    ss58_prefix: int = ss58.PREFIX_POLKADOT,
) -> Path:
    """Write the keystore with owner-only permissions.

    ``O_CREAT | O_EXCL`` with mode ``0600`` in a single call: the file never
    exists at umask permissions, and an existing file (or a symlink planted at
    the path) is refused rather than followed.
    """
    path = Path(path).expanduser()
    document = build_keystore(seed, password, name, ss58_prefix=ss58_prefix)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise S70Error(f"refusing to overwrite an existing file: {path}") from None
    except OSError as exc:
        raise S70Error(f"could not create {path}: {exc}") from exc

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
    except OSError as exc:
        raise S70Error(f"could not write {path}: {exc}") from exc
    return path
