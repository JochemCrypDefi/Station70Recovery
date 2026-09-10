"""Rendering a recovered key in the exact form a browser extension accepts.

This is the heart of phase 1. Four of the eight chains here sit on Ed25519,
and every one of them wants a *different* string built from the same 32 bytes:

======  ==========  ================================================
chain   wallet      string
======  ==========  ================================================
Solana  Phantom     base58(seed || public key)          -- 64 bytes
Stellar Freighter   StrKey ``S...``                     -- 32 bytes
Sui     Suiet       bech32 ``suiprivkey1...``           -- flag || 32
Aptos   Pontem      ``0x`` + 64 hex                     -- 32 bytes
======  ==========  ================================================

So the format is keyed off the target wallet, never off the curve.

Two chains genuinely cannot take a raw key and the guide says so rather than
offering a string that will be rejected: Polkadot (Talisman needs a keystore
file) and XRPL (extensions import a 16-byte family seed, which cannot be
derived back from the private key this backup holds).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from s70.chains import ChainSpec
from s70.chains import sui as sui_chain
from s70.codecs import b58, bech32, strkey
from s70.keymaterial import CURVE_ED25519, CURVE_SECP256K1, KeyMaterial

SUI_PRIVATE_KEY_HRP = "suiprivkey"
AIP80_ED25519_PREFIX = "ed25519-priv-"
AIP80_SECP256K1_PREFIX = "secp256k1-priv-"


@dataclass
class ImportFormat:
    """One string the user can paste (or a file they can write)."""

    label: str
    value: str
    primary: bool = True
    sensitive: bool = True
    note: str = ""

    def __repr__(self) -> str:  # keep key material out of tracebacks and logs
        return f"<ImportFormat {self.label!r} len={len(self.value)}>"

    __str__ = __repr__


@dataclass
class ImportGuide:
    """Everything needed to get one key into one extension."""

    chain_id: str
    chain_label: str
    wallet: str
    ui_path: list[str] = field(default_factory=list)
    formats: list[ImportFormat] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Set when no paste-able import path exists. The formats, if any, are
    #: informational only.
    blocked: str | None = None
    #: Set when the import path is a file this tool must write.
    writes_file: str | None = None

    def __repr__(self) -> str:
        return f"<ImportGuide {self.chain_id} -> {self.wallet}, {len(self.formats)} formats>"


# --------------------------------------------------------------------------
# per-chain builders
# --------------------------------------------------------------------------


def _pkcs8_pem(seed: bytes) -> str:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _evm(key: KeyMaterial) -> ImportGuide:
    scalar = key.scalar.reveal()
    return ImportGuide(
        chain_id="evm",
        chain_label="EVM",
        wallet="Rabby / MetaMask",
        ui_path=[
            "Rabby: click the account name at the top -> Add an Address -> Import Private Key",
            "MetaMask: account selector -> Add account or hardware wallet -> Import account -> Private Key",
        ],
        formats=[
            ImportFormat(
                label="Private key (hex)",
                value="0x" + scalar.hex(),
                note="",
            )
        ],
        warnings=[
            "If this key was compromised rather than merely lost, a sweeper bot may be "
            "watching the address -- do not send it gas.",
        ],
    )


def _solana(key: KeyMaterial) -> ImportGuide:
    seed = key.scalar.reveal()
    secret64 = seed + key.public_key
    return ImportGuide(
        chain_id="solana",
        chain_label="Solana",
        wallet="Phantom",
        ui_path=[
            "Phantom -> I Already Have a Wallet -> Import Private Key",
            "Name the account, then select the Solana network before pasting",
        ],
        formats=[
            ImportFormat(
                label="Private key (base58, 64-byte secret)",
                value=b58.encode(secret64),
                note="Phantom exports this same form, so it round-trips.",
            ),
            ImportFormat(
                label="Keypair JSON array (solana-keygen / id.json)",
                value=json.dumps(list(secret64)),
                primary=False,
                note=(
                    "For the Solana CLI, not Phantom. Save as id.json and use "
                    "`solana --keypair id.json`."
                ),
            ),
        ],
        warnings=[
            "Phantom is multichain: select the Solana network before pasting.",
        ],
    )


def _aptos(key: KeyMaterial) -> ImportGuide:
    scalar = key.scalar.reveal()
    hex_key = "0x" + scalar.hex()
    prefix = (
        AIP80_ED25519_PREFIX if key.curve == CURVE_ED25519 else AIP80_SECP256K1_PREFIX
    )
    return ImportGuide(
        chain_id="aptos",
        chain_label="Aptos",
        wallet="Petra",
        ui_path=[
            "Petra -> account avatar (top left) -> Add Account -> Import Private Key",
            "Paste the key and confirm",
        ],
        formats=[
            ImportFormat(
                label="Private key (hex)",
                value=hex_key,
                note="Try this one first.",
            ),
            ImportFormat(
                label="AIP-80 prefixed key",
                value=prefix + hex_key,
                primary=False,
                note="Fallback if the plain hex is rejected.",
            ),
        ],
        warnings=[],
    )


def _sui(key: KeyMaterial) -> ImportGuide:
    scalar = key.scalar.reveal()
    if key.curve == CURVE_ED25519:
        flag = sui_chain.FLAG_ED25519
    elif key.curve == CURVE_SECP256K1:
        flag = sui_chain.FLAG_SECP256K1
    else:  # pragma: no cover - guarded upstream
        flag = sui_chain.FLAG_ED25519

    bech32_key = bech32.encode_bytes(SUI_PRIVATE_KEY_HRP, bytes([flag]) + scalar)
    return ImportGuide(
        chain_id="sui",
        chain_label="Sui",
        wallet="Suiet",
        ui_path=[
            "Suiet -> I already have a wallet -> paste private key",
            "Or, for an extra account: account menu -> Import private key",
        ],
        formats=[
            ImportFormat(
                label="Private key (bech32, SIP-15)",
                value=bech32_key,
                note="",
            ),
            ImportFormat(
                label="Private key (legacy hex)",
                value=scalar.hex(),
                primary=False,
                note="Deprecated; may be rejected.",
            ),
        ],
        warnings=[
            "Use Suiet or Slush -- Phantom dropped Sui support.",
        ],
    )


def _stellar(key: KeyMaterial) -> ImportGuide:
    seed = key.scalar.reveal()
    return ImportGuide(
        chain_id="stellar",
        chain_label="Stellar",
        wallet="Freighter",
        ui_path=[
            "Freighter -> unlock -> avatar menu (top right) -> Import a Stellar secret key",
            "Paste the S... key, enter your Freighter password, tick the acknowledgement",
        ],
        formats=[
            ImportFormat(
                label="Secret key (StrKey)",
                value=strkey.encode_ed25519_secret_seed(seed),
                note="",
            )
        ],
        warnings=[
            "Freighter cannot recover an imported key from its recovery phrase -- keep "
            "this backup until the funds have moved.",
        ],
    )


def _polkadot(key: KeyMaterial) -> ImportGuide:
    scalar = key.scalar.reveal()
    return ImportGuide(
        chain_id="polkadot",
        chain_label="Polkadot",
        wallet="Talisman",
        ui_path=[
            "Press k here to write the keystore file",
            "Talisman -> Add account -> Import -> Import from Polkadot.js",
            "Select the file this tool wrote (no password: it is unencrypted)",
        ],
        formats=[
            ImportFormat(
                label="Raw seed (hex)",
                value="0x" + scalar.hex(),
                primary=False,
                note="For polkadot-js CLI tooling.",
            )
        ],
        warnings=[],
        blocked=(
            "Talisman does not support importing a raw private key for Substrate accounts. "
            "Write a polkadot-js keystore file instead."
        ),
        writes_file="polkadot-js v3 keystore (.json)",
    )


def _xrpl(key: KeyMaterial) -> ImportGuide:
    """XRPL keys in this backup are raw private keys, not family seeds.

    No browser extension imports a raw XRPL private key -- Gem Wallet, Xaman
    and Crossmark all want a 16-byte family seed, and the seed-to-key
    derivation is one-way, so it cannot be worked backwards. The route off
    these accounts is the offline signing flow, not an extension.
    """
    scalar = key.scalar.reveal()
    return ImportGuide(
        chain_id="xrpl",
        chain_label="XRPL",
        wallet="(offline signing only)",
        formats=[
            ImportFormat(
                label="Private key (hex)",
                value=scalar.hex(),
                note=(
                    "Accepted by xrpl-py's low-level signing, which takes a private key "
                    "directly. Not importable into any wallet extension."
                ),
            ),
            ImportFormat(
                label="Private key (hex, 0x-prefixed)",
                value="0x" + scalar.hex(),
                primary=False,
            ),
        ],
        blocked=(
            "No XRPL wallet extension can import this key. Gem Wallet, Xaman/Xumm and "
            "Crossmark all import a 16-byte family seed (or the mnemonic that encodes "
            "it), and this backup holds the derived private key -- the derivation is "
            "one-way. Use the offline signing flow instead: `s70 inspect` then "
            "`s70 sign` build and sign an AccountDelete that sweeps the whole balance."
        ),
    )


def _canton(key: KeyMaterial) -> ImportGuide:
    seed = key.scalar.reveal()
    return ImportGuide(
        chain_id="canton",
        chain_label="Canton",
        wallet="Console Wallet",
        ui_path=[
            "Console Wallet's documented import is 'Party ID + Seed Phrase', which does "
            "not accept any of the encodings below.",
        ],
        formats=[
            ImportFormat(
                label="Raw private key (base64)",
                value=base64.b64encode(seed).decode("ascii"),
                note=(
                    "Matches what Digital Asset's external-party tutorial produces with "
                    "`openssl genpkey -algorithm ed25519` piped to base64."
                ),
            ),
            ImportFormat(
                label="PKCS#8 PEM",
                value=_pkcs8_pem(seed),
                primary=False,
                note=(
                    "Standard PEM. Note that Canton nodes store keys as protobuf, not PEM, "
                    "so importing this directly into a node will fail."
                ),
            ),
            ImportFormat(
                label="Raw private key (hex)",
                value=seed.hex(),
                primary=False,
            ),
        ],
        warnings=[],
        blocked=(
            "No confirmed raw-key import path exists for any Canton browser extension. "
            "Hand these encodings to whoever operates your Canton participant node."
        ),
    )


_BUILDERS = {
    "evm": _evm,
    "solana": _solana,
    "aptos": _aptos,
    "sui": _sui,
    "stellar": _stellar,
    "polkadot": _polkadot,
    "xrpl": _xrpl,
    "canton": _canton,
}


def raw_guide(key: KeyMaterial, chain_label: str = "unrecognised chain") -> ImportGuide:
    """Every encoding of the raw key, for a chain this tool cannot derive.

    The private key is the deliverable regardless of whether the tool knows
    how to build an address for it or which extension would take it. Hand over
    the bytes in the encodings wallets actually ask for and say plainly what
    was and was not checked.
    """
    scalar = key.scalar.reveal()
    formats = [
        ImportFormat(label="Raw private key (0x-prefixed hex)", value="0x" + scalar.hex()),
        ImportFormat(
            label="Raw private key (base64)",
            value=base64.b64encode(scalar).decode("ascii"),
            primary=False,
        ),
    ]
    return ImportGuide(
        chain_id="raw",
        chain_label=chain_label,
        wallet="(no known extension)",
        formats=formats,
        warnings=[
            f"This tool cannot derive a {chain_label} address, so the key below was "
            "NOT cross-checked against the address in the backup. Its integrity rests "
            "on the SHA-256 check alone.",
            "Confirm the address in your wallet after importing, before moving anything.",
        ],
    )


#: Caveats worth showing only when the address check did not pass. Stated
#: unconditionally they are noise; stated here they are the explanation.
_UNVERIFIED_CAVEATS = {
    "aptos": (
        "The address did not match. An Aptos address equals its authentication key "
        "only until the key is rotated, so this key may still control the account."
    ),
    "polkadot": (
        "The address did not match. The account is probably sr25519, which this tool "
        "cannot rebuild -- a keystore written from it would import a different address."
    ),
}


def guide_for(
    chain: ChainSpec | None,
    key: KeyMaterial,
    chain_label: str = "",
    *,
    address_verified: bool = True,
) -> ImportGuide:
    """Build the import guide for one recovered key.

    ``chain`` may be ``None`` -- an unsupported or unidentified chain still
    yields the raw key bytes rather than nothing.
    """
    builder = _BUILDERS.get(chain.id) if chain is not None else None
    if builder is None:
        return raw_guide(key, chain_label or (chain.label if chain else "unrecognised chain"))
    guide = builder(key)
    if not address_verified and chain.id in _UNVERIFIED_CAVEATS:
        guide.warnings.append(_UNVERIFIED_CAVEATS[chain.id])
    return guide
