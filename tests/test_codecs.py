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
    assert strkey.decode_ed25519_secret_seed(encoded) == SAMPLE


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
        strkey.decode_ed25519_secret_seed(public)


def test_strkey_rejects_bad_checksum():
    encoded = list(strkey.encode_ed25519_secret_seed(SAMPLE))
    encoded[-1] = "A" if encoded[-1] != "A" else "B"
    with pytest.raises(ValueError):
        strkey.decode_ed25519_secret_seed("".join(encoded))


def test_strkey_rejects_wrong_length_payload():
    with pytest.raises(ValueError):
        strkey.encode_ed25519_secret_seed(SAMPLE[:16])


# --------------------------------------------------------------------------
# bech32
# --------------------------------------------------------------------------


def test_suiprivkey_shape():
    encoded = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    # 10 hrp + 1 separator + 53 data + 6 checksum
    assert len(encoded) == 70
    assert encoded.startswith("suiprivkey1")
    assert encoded == encoded.lower()
    hrp, payload = bech32.decode_bytes(encoded)
    assert hrp == "suiprivkey"
    assert payload == b"\x00" + SAMPLE


def test_bech32_and_bech32m_are_not_interchangeable():
    plain = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    variant = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE, bech32m=True)
    assert plain != variant
    # Sui uses plain bech32; decoding it as bech32m must fail.
    with pytest.raises(ValueError, match="checksum"):
        bech32.decode_bytes(plain, bech32m=True)


def test_sui_flag_byte_changes_the_string():
    ed = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    k1 = bech32.encode_bytes("suiprivkey", b"\x01" + SAMPLE)
    assert ed != k1


def test_bech32_rejects_mixed_case():
    encoded = bech32.encode_bytes("suiprivkey", b"\x00" + SAMPLE)
    # Uppercase the HRP, not the last character: the final char is a checksum
    # symbol that may already be a digit, in which case .upper() is a no-op
    # and the string never becomes mixed case at all.
    mixed = encoded[:1].upper() + encoded[1:]
    assert mixed != encoded
    with pytest.raises(ValueError, match="mixed case"):
        bech32.decode(mixed)


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
