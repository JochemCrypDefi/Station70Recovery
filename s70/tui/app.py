"""The TUI.

Three screens: a consent gate, an inventory, and a per-wallet detail screen.

**Alternate screen buffer.** Textual runs on it, so nothing rendered here is
added to the terminal's primary scrollback.

**Everything is verified up front.** Opening the file decrypts and checks every
wallet, then immediately discards the key material, keeping only the verdicts.
A single RSA-4096 decrypt per wallet is fast enough to do inline, and knowing
the state of the whole backup before you touch anything is worth more than a
lazier startup. The key for one wallet is decrypted again, on its own, when you
open it.

**Masked until asked.** A key is rendered only after you press ``r``.
"""

from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static

from s70 import backup as backup_mod
from s70 import security, txn, wallets
from s70.chains import Status
from s70.errors import S70Error
from s70.session import RecoverySession, WalletRecord

CONSENT_PHRASE = "RECOVER"

STATUS_MARKUP = {
    "verified": "[green]verified[/]",
    "unverifiable": "[yellow]unverifiable[/]",
    "mismatch": "[red]mismatch[/]",
    "ambiguous": "[yellow]ambiguous[/]",
    "unsupported": "[dim]sha-256 only[/]",
    "no-address": "[yellow]no address[/]",
    "error": "[red]error[/]",
    "HASH MISMATCH": "[bold red]HASH MISMATCH[/]",
    "not recovered": "[dim]-[/]",
}


# --------------------------------------------------------------------------
# consent gate
# --------------------------------------------------------------------------


class ConsentScreen(Screen):
    """Nothing is decrypted until the user types the confirmation phrase."""

    BINDINGS = [Binding("escape", "app.quit", "Quit")]

    def __init__(self, session: RecoverySession) -> None:
        super().__init__()
        self.session = session

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="consent-body"):
            yield Static(
                f"Provider     : {escape(self.session.backup.wallet_provider)}\n"
                f"Backup file  : {escape(self.session.backup.path.name)}\n"
                f"Wallets      : {self.session.backup.share_count}\n"
                f"Recovery key : {self.session.recovery_key_label}",
                classes="panel",
            )
            yield Static(
                "This is a disaster-recovery tool.\n\n"
                "It decrypts the private keys in this backup so you can move the funds "
                "to a new, secure wallet. That is the whole purpose. Once a key has "
                "been recovered here, treat the account it controls as spent: move "
                "everything off it and do not keep funds attached to these keys.",
                classes="caution",
            )
            yield Label(f"Type {CONSENT_PHRASE} and press enter:", classes="heading")
            yield Input(placeholder=CONSENT_PHRASE, id="consent-input")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#consent-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.value.strip() == CONSENT_PHRASE:
            # Decrypt and check everything, then drop the keys. Blocking: the
            # whole point is that the inventory is complete when it appears.
            self.session.recover_all(forget_keys=True)
            self.app.switch_screen(InventoryScreen(self.session))
        else:
            self.notify(f"Type {CONSENT_PHRASE} exactly.", severity="warning")


# --------------------------------------------------------------------------
# inventory
# --------------------------------------------------------------------------


def _sort_key(record: WalletRecord) -> tuple[str, str]:
    return (record.chain_label.lower(), record.name.lower())


class InventoryScreen(Screen):
    """Every wallet, already verified, sorted by chain then name."""

    BINDINGS = [
        # priority: DataTable binds `enter` to its own select_cursor, which
        # would otherwise consume the key before this screen ever sees it.
        Binding("enter", "open", "Open", priority=True),
        Binding("escape", "app.quit", "Quit"),
    ]

    def __init__(self, session: RecoverySession) -> None:
        super().__init__()
        self.session = session
        self.records = sorted(session.records, key=_sort_key)

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="inventory-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#inventory-table", DataTable)
        table.add_columns("Chain", "Name", "Address", "SHA-256", "Address check")
        self.refresh_rows()
        table.focus()

    def refresh_rows(self) -> None:
        table = self.query_one("#inventory-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for record in self.records:
            if record.integrity_result is True:
                integrity = "[green]pass[/]"
            elif record.integrity_result is None:
                integrity = "[yellow]no hash[/]"
            else:
                integrity = "[bold red]FAIL[/]"
            table.add_row(
                escape(record.chain_label),
                escape(record.name),
                escape(security.mask(record.address or "<none>", 10)),
                integrity,
                STATUS_MARKUP.get(record.status_label, escape(record.status_label)),
            )
        if cursor is not None and 0 <= cursor < len(self.records):
            table.move_cursor(row=cursor)

    def action_open(self) -> None:
        row = self.query_one("#inventory-table", DataTable).cursor_row
        if row is None or not 0 <= row < len(self.records):
            return
        record = self.records[row]

        # Verification discarded the key material; decrypt this one again.
        self.session.recover(record)
        if record.error:
            self.notify(record.error, severity="error", timeout=15)
            return
        if record.key is None:
            detail = (
                record.identification.detail
                if record.identification
                else "no key material was recovered"
            )
            self.notify(detail, severity="error", timeout=15)
            return
        self.app.push_screen(WalletScreen(self.session, record))


# --------------------------------------------------------------------------
# one wallet
# --------------------------------------------------------------------------


class WalletScreen(Screen):
    """One wallet: the key, how to import it, and how to sweep it."""

    BINDINGS = [
        Binding("r", "toggle_reveal", "Reveal / hide"),
        Binding("k", "write_keystore", "Write keystore"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, session: RecoverySession, record: WalletRecord) -> None:
        super().__init__()
        self.session = session
        self.record = record
        self.revealed = False
        self.guide = wallets.guide_for(
            record.chain,
            record.key,
            record.chain_label,
            address_verified=record.verified_for_signing,
        )
        # (label, value, note) -- the raw bytes first, then the encodings the
        # extensions actually ask for. Deduplicated by value: several chains
        # hand back bare hex as their import format too, and showing the same
        # string twice under two names invites pasting the wrong one.
        self.entries: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        candidates = [("Raw private key (hex)", record.key.scalar.reveal().hex(), "")]
        candidates += [(f.label, f.value, f.note) for f in self.guide.formats]
        for label, value, note in candidates:
            if value in seen:
                continue
            seen.add(value)
            self.entries.append((label, value, note))

    # -- layout -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        record = self.record
        yield Header()
        with VerticalScroll():
            yield Static(
                f"Wallet        : {escape(record.name)}\n"
                f"Chain         : {escape(record.chain_label)}\n"
                f"Address       : {escape(record.address or '<none>')}\n"
                f"Decrypted     : {escape(record.key.describe())}\n"
                f"SHA-256       : {record.integrity_label}\n"
                f"Address check : {escape(record.verdict_detail or record.status_label)}",
                classes="panel" if record.fully_verified else "caution",
            )

            yield Label("Private key", classes="heading")
            yield Static("", id="secret-block")

            yield Label("How to import", classes="heading")
            yield Static(self._import_text(), classes="muted")

            signing = self._signing_text()
            if signing:
                yield Label("Move the funds out", classes="heading")
                yield Static(signing, classes="muted")

            if self.guide.warnings:
                yield Label("Notes", classes="heading")
                yield Static(
                    "\n".join(f"  - {escape(w)}" for w in self.guide.warnings),
                    classes="muted",
                )
        yield Footer()

    def on_mount(self) -> None:
        self._render_secret()

    def _import_text(self) -> str:
        if self.guide.writes_file:
            return "\n".join(f"  {escape(step)}" for step in self.guide.ui_path)
        if self.guide.blocked or not self.guide.ui_path:
            return "  Not available."
        return f"  Into {escape(self.guide.wallet)}:\n" + "\n".join(
            f"    {escape(step)}" for step in self.guide.ui_path
        )

    def _signing_text(self) -> str:
        chain = self.record.chain
        if chain is None or chain.id not in txn.SUPPORTED:
            return ""
        if not self.record.verified_for_signing:
            return (
                "  This key was not proved to control the address above, so it is not "
                "safe to sign a sweep with it."
            )
        return (
            f"  This tool can build and sign a transaction that sweeps this account.\n"
            f"  It never submits one -- you get a signed blob and the command to send it.\n\n"
            f"  On an online machine (no keys involved):\n"
            f"    s70 inspect --chain {chain.id} \\\n"
            f"      --source {escape(self.record.address or '<address>')} \\\n"
            f"      --destination <YOUR_SAFE_ADDRESS> --out job.json\n\n"
            f"  Then, back here, offline:\n"
            f"    s70 sign --job job.json --backup {escape(self.session.backup.path.name)}\n\n"
            f"  The job names this account, so sign finds the right wallet itself."
        )

    # -- reveal -----------------------------------------------------------

    def _render_secret(self) -> None:
        widget = self.query_one("#secret-block", Static)
        if not self.revealed:
            widget.update(
                Text(
                    "\n".join(
                        f"  {label}: {len(value)} characters hidden"
                        for label, value, _ in self.entries
                    )
                    + "\n\n  press r to reveal"
                )
            )
            widget.remove_class("revealed")
            return

        body = Text()
        for index, (label, value, note) in enumerate(self.entries):
            if index:
                body.append("\n")
            body.append(f"  {label}\n", style="bold")
            body.append(f"  {value}\n")
            if note:
                body.append(f"  {note}\n", style="dim")
        widget.update(body)
        widget.add_class("revealed")

    def action_toggle_reveal(self) -> None:
        self.revealed = not self.revealed
        self._render_secret()

    def on_screen_suspend(self) -> None:
        # Re-render, not just re-flag: a modal on top of this screen does not
        # cover it, so the key would otherwise stay on display underneath.
        self.revealed = False
        self._render_secret()

    # -- keystore ---------------------------------------------------------

    def action_write_keystore(self) -> None:
        if not self.guide.writes_file:
            self.notify("this chain does not use a keystore file", severity="warning")
            return
        self.app.push_screen(KeystorePrompt(), self._write_keystore)

    def _write_keystore(self, result: tuple[str, str] | None) -> None:
        if not result:
            return
        path_text, password = result
        from s70 import keystore_polkadot
        from s70.chains.polkadot import SPEC as polkadot_spec

        prefix = 0
        try:
            prefix = polkadot_spec.prefix_of(self.record.address or "")
        except Exception:  # noqa: BLE001 - default to the Polkadot prefix
            pass

        try:
            path = keystore_polkadot.write_keystore(
                path_text,
                self.record.key.scalar.reveal(),
                password,
                self.record.name or "Recovered account",
                ss58_prefix=prefix,
            )
        except (S70Error, OSError) as exc:
            self.notify(str(exc), severity="error", timeout=15)
            return

        self.notify(
            f"wrote {path} (mode 0600). Talisman -> Add account -> Import -> "
            "Import from Polkadot.js, then enter the password you just chose.",
            severity="information",
            timeout=25,
        )

    # -- teardown ---------------------------------------------------------

    def action_back(self) -> None:
        # Drop the key material and the rendered copies of it together --
        # forgetting the record alone would leave every format alive here.
        self.session.forget(self.record)
        self.entries = []
        self.guide.formats = []
        self.dismiss()


class KeystorePrompt(ModalScreen[tuple[str, str] | None]):
    """Ask for a keystore path and the password Talisman will require."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="keystore-dialog", classes="panel"):
            yield Label("Write keystore to", classes="heading")
            yield Input(value="polkadot-keystore.json", id="keystore-path")
            yield Label("Password (Talisman asks for this on import)", classes="heading")
            yield Input(password=True, id="keystore-password")
            yield Label("Confirm password", classes="heading")
            yield Input(password=True, id="keystore-confirm")
            yield Static(
                "enter to move between fields, enter on the last one to write. "
                "escape cancels.",
                classes="muted",
            )

    def on_mount(self) -> None:
        self.query_one("#keystore-path", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter walks the fields, so the whole dialog works without a mouse.
        order = ["#keystore-path", "#keystore-password", "#keystore-confirm"]
        current = f"#{event.input.id}"
        if current != order[-1]:
            self.query_one(order[order.index(current) + 1], Input).focus()
            return

        path = self.query_one("#keystore-path", Input).value.strip()
        password = self.query_one("#keystore-password", Input).value
        confirm = self.query_one("#keystore-confirm", Input).value

        if not path:
            self.notify("a path is required", severity="warning")
            return
        if not password:
            self.notify("a password is required -- Talisman will ask for it", severity="warning")
            return
        if password != confirm:
            self.notify("passwords do not match", severity="warning")
            return
        self.dismiss((path, password))


# --------------------------------------------------------------------------
# app
# --------------------------------------------------------------------------


class RecoveryApp(App):
    """S70 Recovery."""

    CSS_PATH = "app.tcss"
    TITLE = "S70 Recovery"

    #: Textual's command palette offers "Save screenshot", which writes an SVG
    #: of the current screen -- a revealed private key -- to disk. The whole
    #: argument for the alternate screen buffer is that nothing here persists.
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        # Textual captures the mouse, so the terminal's own select-and-copy
        # does not work here -- selection is Textual's, and so copying has to
        # be too. Nothing is bound to this by default.
        Binding("ctrl+c", "copy_selection", "Copy selection", priority=True),
    ]

    def __init__(self, backup_path: str) -> None:
        super().__init__()
        self.backup_path = backup_path
        self.session: RecoverySession | None = None

    def action_copy_selection(self) -> None:
        """Copy the mouse selection to the system clipboard.

        This is a real widening of the threat model: the clipboard is a
        global, unauthenticated channel, and over SSH this travels as OSC 52
        to the *local* machine. It is here because being unable to get a key
        out of the tool by any means but retyping it is worse.
        """
        text = self.screen.get_selected_text()
        if not text:
            self.notify(
                "nothing selected -- click and drag over the text first",
                severity="warning",
            )
            return
        self.copy_to_clipboard(text)
        self.notify(f"copied {len(text)} characters to the clipboard")

    def on_mount(self) -> None:
        try:
            parsed = backup_mod.load(self.backup_path)
            self.session = RecoverySession.open(parsed)
        except (S70Error, UnicodeDecodeError, OSError) as exc:
            # Nothing to show. Fail on stderr with a non-zero status rather
            # than presenting an empty UI.
            self.exit(return_code=1, message=f"error: {exc}")
            return

        self.sub_title = f"{parsed.wallet_provider} -- {parsed.share_count} wallets"
        self.push_screen(ConsentScreen(self.session))
