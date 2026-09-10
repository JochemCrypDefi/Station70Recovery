"""Command-line interface.

The TUI is the intended way to use this tool; the CLI exists for the things a
TUI is bad at -- scripted verification, writing job files, and running in CI
where nobody is watching.

No CLI command displays a private key. ``verify`` decrypts every key to check
it and shows none of them; revealing a key is the TUI's job, because the TUI
runs on the alternate screen buffer and a terminal's scrollback is not
something this tool can clean up after.
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from s70 import backup as backup_mod
from s70 import chains, security, txn, wallets
from s70.errors import S70Error
from s70.session import RecoverySession, WalletRecord

console = Console(stderr=False)
error_console = Console(stderr=True)

STATUS_STYLES = {
    "verified": "green",
    "unverifiable": "yellow",
    "mismatch": "red",
    "ambiguous": "yellow",
    "unsupported": "dim",
    "no-address": "yellow",
    "skipped": "dim",
    "error": "red",
    "HASH MISMATCH": "bold red",
    "not recovered": "dim",
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _open_session(args) -> RecoverySession:
    return RecoverySession.open(backup_mod.load(args.backup))


def _select(session: RecoverySession, selector: str) -> WalletRecord:
    """Resolve a wallet by index or by a substring of its name or address."""
    if selector.isdigit():
        index = int(selector)
        if not 0 <= index < len(session.records):
            raise S70Error(
                f"no wallet at index {index}; the backup has {len(session.records)} "
                "(run `s70 list` to see them)"
            )
        return session.records[index]

    needle = selector.lower()
    matches = [
        record
        for record in session.records
        if needle in record.name.lower() or needle in (record.address or "").lower()
    ]
    if not matches:
        raise S70Error(f"no wallet matches {selector!r}. Run `s70 list` to see them.")
    if len(matches) > 1:
        names = ", ".join(f"[{r.share.index}] {r.name}" for r in matches)
        raise S70Error(f"{selector!r} matches several wallets: {names}. Use the index.")
    return matches[0]


def _select_by_address(session: RecoverySession, address: str) -> WalletRecord:
    """Find the wallet a job file is for, by its recorded address.

    Exact match, case-insensitively: an address is not a search term, and a
    substring match here would be a way to sign with the wrong account.
    """
    needle = address.strip().lower()
    matches = [r for r in session.records if (r.address or "").lower() == needle]
    if not matches:
        raise S70Error(
            f"no wallet in this backup has the address {address}, which is the "
            "source this job is for. Check you opened the right backup file, or "
            "name the wallet explicitly with --wallet."
        )
    if len(matches) > 1:
        indices = ", ".join(str(r.share.index) for r in matches)
        raise S70Error(
            f"{address} appears more than once in this backup (wallets {indices}). "
            "Pick one with --wallet."
        )
    return matches[0]


def _inventory_table(session: RecoverySession, *, title: str) -> Table:
    table = Table(title=title, show_lines=False, header_style="bold")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Name")
    table.add_column("Chain")
    table.add_column("Address")
    table.add_column("SHA-256")
    table.add_column("Address check")

    for record in session.records:
        status = record.status_label
        if record.verdict is None and record.integrity_result is None:
            integrity = "[dim]-[/]"
        elif record.integrity_result is True:
            integrity = "[green]pass[/]"
        elif record.integrity_result is None:
            integrity = "[yellow]no hash[/]"
        else:
            integrity = "[bold red]FAIL[/]"
        table.add_row(
            str(record.share.index),
            escape(record.name),
            escape(record.chain_label),
            escape(security.mask(record.address or "<none>", 10)),
            integrity,
            f"[{STATUS_STYLES.get(status, 'white')}]{status}[/]",
        )
    return table


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_list(args) -> int:
    """Inventory the backup without decrypting anything."""
    session = _open_session(args)
    console.print(
        Panel(
            f"Provider     : {session.backup.wallet_provider}\n"
            f"Backup file  : {session.backup.path}\n"
            f"Wallets      : {session.backup.share_count}\n"
            f"Recovery key : {session.recovery_key_label}",
            title="Backup",
            border_style="cyan",
        )
    )
    console.print(_inventory_table(session, title="Wallets (not yet decrypted)"))

    unsupported = session.unsupported()
    if unsupported:
        console.print()
        error_console.print(
            f"[yellow]note:[/] {len(unsupported)} wallet(s) are on chains this tool "
            "cannot derive an address for. Their keys are still recovered in full; "
            "what they lose is the address cross-check:"
        )
        for record in unsupported:
            error_console.print(
                f"  [{record.share.index}] {escape(record.name)} -- "
                f"{escape(record.address or '<none>')} ({escape(record.chain_label)})"
            )
    return 0


def cmd_verify(args) -> int:
    """Decrypt every key and check it, without displaying any key material."""
    session = _open_session(args)
    console.print(f"Decrypting {session.backup.share_count} wallet(s)...")
    # forget_keys: this command reports verdicts and never displays a key, so
    # there is no reason to keep the key material after each check.
    stats = session.recover_all(forget_keys=True)

    console.print(_inventory_table(session, title="Verification results"))

    for record in session.records:
        if record.error:
            error_console.print(f"[red]![/] [{record.share.index}] {record.name}: {record.error}")
        elif record.status_label in ("mismatch", "ambiguous", "HASH MISMATCH"):
            error_console.print(
                f"[yellow]?[/] [{record.share.index}] {record.name}: {record.verdict_detail}"
            )

    console.print()
    console.print(
        f"verified [green]{stats.verified}[/]   "
        f"unverifiable [yellow]{stats.unverifiable}[/]   "
        f"sha-256 only [cyan]{stats.sha_only}[/]   "
        f"mismatched [red]{stats.mismatched}[/]   "
        f"failed [red]{stats.failed}[/]"
    )
    return 1 if (stats.failed or stats.mismatched) else 0


def cmd_inspect(args) -> int:
    """Online phase: read chain state and write a job file."""
    kwargs = {}
    if args.rpc_url:
        kwargs["rpc_url"] = args.rpc_url
    if args.tx_bytes:
        kwargs["tx_bytes"] = args.tx_bytes

    job = txn.inspect(args.chain, args.source, args.destination, **kwargs)
    path = job.write(args.out)

    console.print(Panel("\n".join(job.plan) or "(nothing to do)", title="Plan", border_style="cyan"))

    table = Table(title="Assets", header_style="bold")
    table.add_column("Symbol")
    table.add_column("Amount", justify="right")
    table.add_column("Identifier", style="dim")
    table.add_column("Note")
    for asset in job.assets:
        table.add_row(
            asset.symbol,
            asset.amount,
            security.mask(asset.identifier, 12),
            f"[red]{asset.blocked}[/]" if asset.blocked else "",
        )
    console.print(table)

    checks = Table(title="Preconditions", header_style="bold")
    checks.add_column("Check")
    checks.add_column("Result")
    checks.add_column("Detail", style="dim")
    for precondition in job.preconditions:
        style = "green" if precondition.satisfied else ("red" if precondition.blocking else "yellow")
        checks.add_row(
            precondition.name,
            f"[{style}]{precondition.symbol}[/]",
            precondition.detail,
        )
    console.print(checks)

    for warning in job.warnings:
        error_console.print(f"[yellow]note:[/] {warning}")

    console.print()
    console.print(f"[green]wrote[/] {path}")
    if job.ready:
        console.print(f"Next: s70 sign --job {path} --backup <backup.json>")
    else:
        error_console.print(
            "[red]This job is not ready to sign.[/] Resolve the blocked preconditions "
            "above and re-run inspect."
        )
    return 0 if job.ready else 1


def cmd_sign(args) -> int:
    """Offline phase: sign a job file. Opens no sockets."""
    job = txn.TransferJob.read(args.job)

    stale = job.staleness_warning
    if stale:
        error_console.print(f"[yellow]warning:[/] {stale}")

    session = _open_session(args)
    if args.wallet:
        record = _select(session, args.wallet)
    else:
        # The job already names the account it is for. Selecting the wallet by
        # hand is a chance to pick the wrong one, and every signer would then
        # refuse anyway -- so resolve it from the job and say which one it is.
        record = _select_by_address(session, job.source_address)
        console.print(
            f"Signing as [{record.share.index}] {escape(record.name)} "
            f"({escape(record.chain_label)}), matched on the job's source address."
        )
    record = session.recover(record)

    if record.error:
        error_console.print(f"[red]error:[/] {record.error}")
        return 1

    key = record.key
    if key is None:
        error_console.print("[red]error:[/] this wallet's key could not be identified")
        return 1

    kwargs = {}
    if args.tx_bytes:
        kwargs["tx_bytes"] = args.tx_bytes

    bundle = txn.sign(job, key, **kwargs)

    console.print(
        Panel("\n".join(bundle.summary), title="What this signs", border_style="yellow")
    )

    for index, blob in enumerate(bundle.blobs, start=1):
        console.print()
        console.print(f"[bold]Blob {index}/{len(bundle.blobs)}[/] ({bundle.encoding})")
        console.print(blob, markup=False, highlight=False)

    console.print()
    console.print("[bold]Submit with[/]")
    console.print(bundle.submit_command, markup=False, highlight=False)
    for note in bundle.submit_notes:
        console.print(f"  - {note}")
    if bundle.expires_note:
        error_console.print(f"[yellow]expiry:[/] {bundle.expires_note}")

    if args.out:
        path = bundle.write(args.out)
        console.print(f"\n[green]wrote[/] {path}")

    console.print(
        "\n[bold]This tool did not submit anything.[/] Nothing has moved on chain yet."
    )
    return 0


def cmd_tui(args) -> int:
    """Launch the TUI."""
    from s70.tui.app import RecoveryApp

    RecoveryApp(backup_path=args.backup).run()
    return 0


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s70",
        description="Recover CrypDefi wallet backup keys and prepare transfers.",
        epilog="Run `s70 tui <backup.json>` for the interactive interface.",
    )
    subparsers = parser.add_subparsers(dest="command")

    def add_backup_args(sub, *, positional: bool = True) -> None:
        if positional:
            sub.add_argument("backup", help="path to the backup JSON file")
        else:
            # `sign` already takes --job, so a bare positional path would be
            # ambiguous to read on the command line.
            sub.add_argument(
                "--backup", required=True, help="path to the backup JSON file"
            )

    tui = subparsers.add_parser("tui", help="interactive interface (recommended)")
    add_backup_args(tui)
    tui.set_defaults(func=cmd_tui)

    listing = subparsers.add_parser("list", help="inventory the backup without decrypting")
    add_backup_args(listing)
    listing.set_defaults(func=cmd_list)

    verify = subparsers.add_parser(
        "verify", help="decrypt and check every key, displaying none of them"
    )
    add_backup_args(verify)
    verify.set_defaults(func=cmd_verify)

    inspect = subparsers.add_parser(
        "inspect", help="ONLINE: read chain state and write a job file (no keys loaded)"
    )
    inspect.add_argument("--chain", required=True, choices=sorted(txn.SUPPORTED))
    inspect.add_argument("--source", required=True, help="the compromised/abandoned address")
    inspect.add_argument("--destination", required=True, help="the safe address to sweep to")
    inspect.add_argument("--out", required=True, help="output path for the job file")
    inspect.add_argument("--rpc-url", help="override the default RPC endpoint")
    inspect.add_argument("--tx-bytes", help="Sui only: base64 unsigned transaction bytes")
    inspect.set_defaults(func=cmd_inspect)

    sign = subparsers.add_parser(
        "sign", help="OFFLINE: sign a job file. Never submits."
    )
    add_backup_args(sign, positional=False)
    sign.add_argument("--job", required=True, help="job file from `s70 inspect`")
    sign.add_argument(
        "--wallet",
        help="index, name, or address substring. Defaults to the wallet whose "
        "address matches the job's source.",
    )
    sign.add_argument("--out", help="also write the signed bundle to this path")
    sign.add_argument("--tx-bytes", help="Sui only: base64 unsigned transaction bytes")
    sign.set_defaults(func=cmd_sign)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except S70Error as exc:
        error_console.print(f"[red]error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        error_console.print("\n[dim]interrupted[/]")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
