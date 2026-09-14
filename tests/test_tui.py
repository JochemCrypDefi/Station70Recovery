"""Tests for the interactive app.

The TUI is the intended way to use this tool, and it is the layer where a
wrong string, a hidden explanation or a file written from an unproved key
actually reaches the user. None of that is visible to tests that stop at the
session layer, so these drive the real app through ``run_test``.

Each test asserts on what a person would see or get: the text of the import
block, the order of the key formats, whether a file appeared on disk.
"""

from __future__ import annotations

import asyncio

import pytest

from s70.tui.app import InventoryScreen, RecoveryApp, WalletScreen


def drive(coro_factory):
    """Run one async app interaction from a synchronous test."""
    return asyncio.run(coro_factory())


async def _open_wallet(app, pilot, name: str) -> WalletScreen:
    """Consent, then open the named wallet and return its screen."""
    await pilot.pause()
    await pilot.press(*"RECOVER")
    await pilot.press("enter")
    await pilot.pause()
    inventory = app.screen
    assert isinstance(inventory, InventoryScreen)
    index = next(i for i, r in enumerate(inventory.records) if r.name == name)
    inventory.query_one("#inventory-table").move_cursor(row=index)
    await pilot.press("enter")
    await pilot.pause()
    assert isinstance(app.screen, WalletScreen), f"{name} did not open"
    return app.screen


@pytest.fixture
def open_wallet(synthetic):
    """Give a test ``open_wallet(name, fn)``, running ``fn(screen, pilot)``."""
    path, _ = synthetic

    def run(name, body):
        async def main():
            app = RecoveryApp(backup_path=str(path))
            async with app.run_test(size=(120, 45)) as pilot:
                screen = await _open_wallet(app, pilot, name)
                return await body(screen, pilot)

        return drive(lambda: main())

    return run


# --------------------------------------------------------------------------
# refusing to write a keystore for an account the key does not open
# --------------------------------------------------------------------------


def test_keystore_is_refused_when_the_address_was_not_proved(open_wallet, tmp_path):
    """The sr25519 case. A keystore here imports somebody else's account."""
    target = tmp_path / "should-not-exist.json"

    async def body(screen, pilot):
        assert not screen.record.address_proved
        assert screen.guide.writes_file, "Polkadot still routes through a keystore"
        await pilot.press("k")
        await pilot.pause()
        # No password dialog: the refusal happens before it.
        assert isinstance(pilot.app.screen, WalletScreen)

    open_wallet("Polkadot Sr25519", body)
    assert not target.exists()


def test_keystore_is_offered_when_the_address_was_proved(open_wallet):
    async def body(screen, pilot):
        assert screen.record.address_proved
        await pilot.press("k")
        await pilot.pause()
        # The password prompt is the next screen, so the write can proceed.
        assert type(pilot.app.screen).__name__ == "KeystorePrompt"
        await pilot.press("escape")
        await pilot.pause()

    open_wallet("Polkadot Main", body)


def test_polkadot_instructions_ask_for_a_password(open_wallet):
    """The keystore is encrypted and Talisman demands the password."""

    async def body(screen, pilot):
        text = screen._import_text().lower()
        assert "password" in text
        assert "unencrypted" not in text, "the keystore is encrypted"

    open_wallet("Polkadot Main", body)


# --------------------------------------------------------------------------
# saying why there is no import path
# --------------------------------------------------------------------------


def test_xrpl_screen_explains_itself_instead_of_saying_not_available(open_wallet):
    """The reason no wallet takes this key is the whole answer for XRPL."""

    async def body(screen, pilot):
        text = screen._import_text()
        assert "Not available." not in text
        assert "family seed" in text
        assert "kms" in text.lower(), "must point at the route that does work"

    open_wallet("XRPL Main", body)


# --------------------------------------------------------------------------
# which string to paste
# --------------------------------------------------------------------------


def test_the_format_the_wallet_wants_comes_first_and_is_marked(open_wallet):
    """Stellar rejects hex outright, so leading with hex is actively wrong."""

    async def body(screen, pilot):
        first_label, first_value, _ = screen.entries[0]
        assert first_value.startswith("S"), "the StrKey secret must lead"
        assert "paste this one" in first_label
        # The raw hex is still available, just not first.
        assert any(not v.startswith("S") for _, v, _ in screen.entries)

    open_wallet("Stellar Main", body)


def test_no_paste_marker_when_nothing_can_be_pasted(open_wallet):
    async def body(screen, pilot):
        assert not any("paste this one" in label for label, _, _ in screen.entries)

    open_wallet("XRPL Main", body)


def test_deduplication_keeps_the_label_that_explains_the_string(open_wallet):
    """XRPL's bare hex carries a warning note. The generic entry carries none."""

    async def body(screen, pilot):
        raw = screen.record.key.scalar.reveal().hex()
        matching = [(l, n) for l, v, n in screen.entries if v == raw]
        assert len(matching) == 1, "the same string must not appear twice"
        label, note = matching[0]
        assert "not importable" in note.lower(), (
            "the builder's note explaining this string was dropped by dedupe"
        )

    open_wallet("XRPL Main", body)


# --------------------------------------------------------------------------
# what the screen says about how much was proved
# --------------------------------------------------------------------------


def test_unproved_key_carries_a_note_saying_so(open_wallet):
    async def body(screen, pilot):
        assert not screen.record.address_proved
        assert any("NOT proved" in w for w in screen.guide.warnings)

    open_wallet("Polkadot Sr25519", body)


def test_key_is_hidden_until_r_is_pressed(open_wallet):
    async def body(screen, pilot):
        secret = screen.record.key.scalar.reveal().hex()
        block = screen.query_one("#secret-block")
        assert secret not in str(block.render())
        await pilot.press("r")
        await pilot.pause()
        assert secret in str(screen.query_one("#secret-block").render())

    open_wallet("Stellar Main", body)
