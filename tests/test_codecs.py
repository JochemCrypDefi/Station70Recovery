"""Codec tests.

These are round-trip and invariant tests rather than fixed test vectors. The
reason is honesty: I could not execute code while writing this tool, so a
hardcoded "expected" string would only record what I *believed* the encoder
produced, and a wrong belief would then be baked into a passing test.

Round-trips and documented invariants (lengths, prefixes, checksum
rejection) catch real bugs without that circularity -- but they cannot prove
an encoder is *correct*, only that it is self-consistent. The only proof that
counts is importing a recovered key into the real wallet and confirming it
shows the address you expect.
"""

from __future__ import annotations

import pytest

from s70.codecs import b58, bech32, hashes, ss58, strkey
from s70.keymaterial import ed25519_public_from_seed

SAMPLE = bytes(range(32))


# --------------------------------------------------------------------------
# base58
# --------------------------------------------------------------------------


def test_base58_round_trip():
    assert b58.decode(b58.encode(SAMPLE)) == SAMPLE


@pytest.mark.parametrize("zeros", [1, 2, 5])
def test_base58_preserves_leading_zeros(zeros):
    payload = b"\x00" * zeros + SAMPLE
    encoded = b58.encode(payload)
    assert encoded.startswith("1" * zeros)
    assert b58.decode(encoded) == payload


def test_base58_empty():
    assert b58.encode(b"") == ""
    assert b58.decode("") == b""


def test_base58_rejects_out_of_alphabet():
    with pytest.raises(ValueError):
        b58.decode("0OIl")


def test_xrpl_alphabet_differs_from_bitcoin():
    assert b58.encode(SAMPLE, b58.XRPL) != b58.encode(SAMPLE, b58.BITCOIN)


def test_base58check_round_trip():
    for alphabet in (b58.BITCOIN, b58.XRPL):
        encoded = b58.encode_check(SAMPLE, alphabet)
        assert b58.decode_check(encoded, alphabet) == SAMPLE


def test_base58check_detects_corruption():
    encoded = list(b58.encode_check(SAMPLE, b58.XRPL))
    # Flip a character to something else in the same alphabet.
    encoded[5] = "r" if encoded[5] != "r" else "p"
    with pytest.raises(ValueError, match="checksum"):
        b58.decode_check("".join(encoded), b58.XRPL)


# --------------------------------------------------------------------------
# Stellar StrKey
# --------------------------------------------------------------------------


def test_strkey_secret_seed_shape():
    encoded = strkey.encode_ed25519_secret_seed(SAMPLE)
    assert len(encoded) == 56
    assert encoded.startswith("S")
    assert "=" not in encoded  # 35 bytes is exactly 56 base32 chars
    assert strkey.decode(strkey.VERSION_ED25519_SECRET_SEED, encoded) == SAMPLE


def test_strkey_public_key_shape():
    encoded = strkey.encode_ed25519_public_key(SAMPLE)
    assert len(encoded) == 56
    assert encoded.startswith("G")
    assert strkey.decode_ed25519_public_key(encoded) == SAMPLE


def test_strkey_version_bytes_are_distinct():
    assert strkey.encode_ed25519_public_key(SAMPLE) != strkey.encode_ed25519_secret_seed(SAMPLE)


def test_strkey_rejects_wrong_version_byte():
    public = strkey.encode_ed25519_public_key(SAMPLE)
    with pytest.raises(ValueError, match="version byte"):
        strkey.decode(strkey.VERSION_ED25519_SECRET_SEED, public)


def test_strkey_rejects_bad_checksum():
    encoded = list(strkey.encode_ed25519_secret_seed(SAMPLE))
    encoded[-1] = "A" if encoded[-1] != "A" else "B"
    with pytest.raises(ValueError):
        strkey.decode(strkey.VERSION_ED25519_SECRET_SEED, "".join(encoded))


def test_strkey_rejects_wrong_length_payload():
    with pytest.raises(ValueError):
        strkey.encode_ed25519_secret_seed(SAMPLE[:16])


# --------------------------------------------------------------------------
# bech32
# --------------------------------------------------------------------------


#: BIP-173 checksum constant. Sui uses this one; 0x2BC830A3 is bech32m, which
#: produces a string that still starts "suiprivkey1" and then fails inside the
#: wallet -- so which constant we emit is worth pinning independently.
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _reference_residue(text: str) -> int:
    """Recompute the BIP-173 polymod residue of a bech32 string from scratch.

    Written out here rather than imported: the point is to check the encoder
    against the spec, not against itself. `s70.codecs.bech32` encodes only, so
    this is the only decoder in the project and it lives in the tests.
    """
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    pos = text.rfind("1")
    hrp, data_part = text[:pos], text[pos + 1 :]
    values = (
        [ord(c) >> 5 for c in hrp]
        + [0]
        + [ord(c) & 31 for c in hrp]
        + [bech32.CHARSET.index(c) for c in data_part]
    )
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def test_suiprivkey_shape():
    encoded = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    # 10 hrp + 1 separator + 53 data + 6 checksum
    assert len(encoded) == 70
    assert encoded.startswith("suiprivkey1")
    assert encoded == encoded.lower()


def test_sui_keys_are_bech32_not_bech32m():
    """The wrong constant yields a string Suiet accepts the shape of and rejects."""
    encoded = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    assert _reference_residue(encoded) == _BECH32_CONST
    assert _reference_residue(encoded) != _BECH32M_CONST


def test_bech32_payload_survives_the_round_trip():
    """Regroup the 5-bit data back to bytes and check it is the key we gave."""
    payload = b"\x00" + SAMPLE
    encoded = bech32.encode_bytes("suiprivkey", payload)
    data = [bech32.CHARSET.index(c) for c in encoded[len("suiprivkey1") :]][:-6]
    acc = bits = 0
    out = bytearray()
    for value in data:
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    assert bytes(out) == payload


def test_sui_flag_byte_changes_the_string():
    ed = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    k1 = bech32.encode_bytes("suiprivkey", b"\x01" + SAMPLE)
    assert ed != k1


def test_bech32_output_is_all_lowercase():
    """Mixed case is invalid bech32, so the encoder must never produce it."""
    encoded = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    assert encoded == encoded.lower()
    assert not any(c.isupper() for c in encoded)


# --------------------------------------------------------------------------
# SS58
# --------------------------------------------------------------------------


def test_ss58_round_trip():
    public = ed25519_public_from_seed(SAMPLE)
    for prefix in ss58.COMMON_PREFIXES:
        address = ss58.encode(public, prefix)
        decoded, recovered_prefix = ss58.decode(address)
        assert decoded == public
        assert recovered_prefix == prefix


def test_ss58_prefix_changes_the_address():
    public = ed25519_public_from_seed(SAMPLE)
    addresses = {ss58.encode(public, prefix) for prefix in ss58.COMMON_PREFIXES}
    assert len(addresses) == len(ss58.COMMON_PREFIXES)


def test_ss58_polkadot_addresses_start_with_one():
    public = ed25519_public_from_seed(SAMPLE)
    assert ss58.encode(public, ss58.PREFIX_POLKADOT).startswith("1")


def test_ss58_rejects_bad_checksum():
    public = ed25519_public_from_seed(SAMPLE)
    address = list(ss58.encode(public, 0))
    address[10] = "A" if address[10] != "A" else "B"
    with pytest.raises(ValueError):
        ss58.decode("".join(address))


def test_ss58_requires_32_bytes():
    with pytest.raises(ValueError):
        ss58.encode(SAMPLE[:16], 0)


# --------------------------------------------------------------------------
# hashes
# --------------------------------------------------------------------------


def test_keccak256_is_not_sha3_256():
    """The single most consequential hash mix-up available.

    Ethereum uses original Keccak; hashlib's ``sha3_256`` is NIST SHA3. They
    differ only in a padding byte, so a mix-up produces a well-formed but
    completely wrong EVM address.
    """
    assert hashes.keccak256(b"") != hashes.sha3_256(b"")


def test_keccak256_empty_string_vector():
    # The one Keccak vector worth hardcoding: it is quoted in the Ethereum
    # yellow paper and in every Solidity tutorial.
    assert (
        hashes.keccak256(b"").hex()
        == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_sha3_256_empty_string_vector():
    assert (
        hashes.sha3_256(b"").hex()
        == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )


def test_ripemd160_is_available():
    """OpenSSL 3 drops RIPEMD160 from hashlib, hence pycryptodome."""
    assert len(hashes.ripemd160(b"abc")) == 20
    assert (
        hashes.ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    )


def test_hash160_length():
    assert len(hashes.hash160(b"whatever")) == 20


def test_crc16_xmodem_known_vector():
    # "123456789" -> 0x31C3 is the standard CRC-16/XMODEM check value.
    assert hashes.crc16_xmodem(b"123456789") == 0x31C3


def test_blake2b_digest_sizes():
    assert len(hashes.blake2b_256(b"x")) == 32
    assert len(hashes.blake2b_512(b"x")) == 64
