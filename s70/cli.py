"""Command-line interface.

The TUI is the intended way to use this tool; the CLI exists for the things a
TUI is bad at -- scripted verification, exporting to KMS, and running where
nobody is watching.

**No CLI command displays a private key.** ``verify`` decrypts every key to
check it and shows none of them, and ``kms-export`` decrypts one key but emits
only ciphertext, a public key and a list of commands. Revealing a key is the
TUI's job, because the TUI runs on the alternate screen buffer and a terminal's
scrollback is not something this tool can clean up after.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from s70 import backup as backup_mod
from s70 import kms, security
from s70.errors import S70Error
from s70.session import RecoverySession, WalletRecord

console = Console(stderr=False)
error_console = Console(stderr=True)

#: One style per status. The set of keys is exactly :class:`s70.chains.Status`
#: plus the three non-verdict states a record can be in, and it is mirrored by
#: ``STATUS_MARKUP`` in the TUI so a status never reads two ways.
STATUS_STYLES = {
    "verified": "green",
    "mismatch": "red",
    "ambiguous": "yellow",
    "sha-256 only": "cyan",
    "no address": "yellow",
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
        index = record.share.index
        if record.error:
            error_console.print(f"[red]![/] [{index}] {record.name}: {record.error}")
        elif record.integrity_result is False:
            # Report the check that actually failed. `verdict_detail` describes
            # the *address* check, which may well have passed, and printing it
            # here once read as reassurance next to a red HASH MISMATCH.
            error_console.print(
                f"[bold red]![/] [{index}] {record.name}: the decrypted key does not "
                "match the SHA-256 checksum recorded in the backup. Do not import or "
                "export this key; the ciphertext is damaged."
            )
        elif record.status_label in ("mismatch", "ambiguous"):
            error_console.print(f"[yellow]?[/] [{index}] {record.name}: {record.verdict_detail}")
        if record.scheme_warning:
            error_console.print(f"[yellow]note:[/] [{index}] {record.name}: {record.scheme_warning}")

    console.print()
    console.print(
        f"verified [green]{stats.verified}[/]   "
        f"sha-256 only [cyan]{stats.sha_only}[/]   "
        f"wrong address [red]{stats.mismatched}[/]   "
        f"hash mismatch [bold red]{stats.hash_mismatch}[/]   "
        f"failed [red]{stats.failed}[/]"
    )
    return 1 if (stats.failed or stats.mismatched or stats.hash_mismatch) else 0


def cmd_kms_prepare(args) -> int:
    """Say which KMS key spec each wallet needs. Decrypts nothing.

    The curve is stated in the backup's ``key_type`` field, and the curve is
    all that determines the key spec -- so this runs before any key is touched,
    which is the right order: you have to create the KMS key and fetch its
    import parameters before ``kms-export`` has anything to work with.
    """
    session = _open_session(args)
    records = [_select(session, args.wallet)] if args.wallet else session.records

    table = Table(title="KMS key spec per wallet", header_style="bold")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Name")
    table.add_column("Chain")
    table.add_column("Curve")
    table.add_column("KMS key spec")

    unknown: list[WalletRecord] = []
    for record in records:
        curve = record.entry.declared_curve
        try:
            profile = kms.profile_for_curve(curve) if curve else None
        except S70Error:
            profile = None
        if profile is None:
            unknown.append(record)
        table.add_row(
            str(record.share.index),
            escape(record.name),
            escape(record.chain_label),
            escape(curve or "not stated"),
            profile.key_spec if profile else "[yellow]run kms-export to find out[/]",
        )
    console.print(table)

    if unknown:
        error_console.print(
            f"[yellow]note:[/] {len(unknown)} wallet(s) do not state a curve in the "
            "backup. Their key spec is decided by the decrypted key, so run "
            "`s70 kms-export` for those and it will tell you before it wraps anything."
        )

    # The commands only differ by key spec, so show each distinct one once
    # rather than repeating an identical block 34 times.
    seen: set[str] = set()
    for record in records:
        curve = record.entry.declared_curve
        if not curve:
            continue
        try:
            profile = kms.profile_for_curve(curve)
        except S70Error:
            continue
        if profile.key_spec in seen:
            continue
        seen.add(profile.key_spec)
        # Name the wallet only when one was asked for: with several wallets
        # sharing a key spec, a single block is printed for all of them and
        # naming one of them in it would be wrong.
        steps = kms.key_spec_steps(
            profile,
            region=args.region,
            wallet_name=record.name if args.wallet else "",
        )
        console.print()
        console.print(
            kms.KmsGuide(steps=steps).render(),
            markup=False,
            highlight=False,
            # soft_wrap: rich would otherwise insert real newlines to fit the
            # terminal, breaking these commands mid-token. A command you cannot
            # copy is no use, and the prose is already wrapped by render().
            soft_wrap=True,
        )

    console.print()
    console.print(
        "Then, on this machine:  s70 kms-export --backup <backup.json> "
        "--wallet <n> --params import-parameters.json --out EncryptedKeyMaterial.bin"
    )
    return 0


def cmd_kms_export(args) -> int:
    """Wrap one recovered key as KMS importable key material. Opens no sockets."""
    params = kms.load_import_parameters(
        args.params, wrapping_algorithm=args.wrapping_algorithm
    )

    valid_to = (
        params.parameters_valid_to.isoformat()
        if params.parameters_valid_to
        else "not stated"
    )
    console.print(
        Panel(
            f"Source           : {params.source}\n"
            f"Wrapping key     : RSA-{params.rsa_key_size}\n"
            f"Wrapping algo    : {params.wrapping_algorithm} "
            f"(from {params.algorithm_source})\n"
            f"KMS key          : {params.key_id or '<not stated>'}\n"
            f"Valid to         : {valid_to}\n"
            f"Import token     : {len(params.import_token or b'')} bytes",
            title="KMS import parameters",
            border_style="cyan",
        )
    )
    # The guide repeats these at the end, where the user will still be looking
    # when they act on them. Printing them here as well only taught the reader
    # that the second copy is redundant.
    # Where the import token will go. The generated `import-key-material`
    # command needs it as raw bytes beside the blob, so it is written on every
    # run rather than on request -- the command used to name a file that only
    # existed if you had thought to ask for it.
    token_path = (
        Path(args.write_import_token).expanduser()
        if args.write_import_token
        else Path(args.out).expanduser().parent / kms.CONSOLE_TOKEN_NAME
    )
    # Check before wrapping: a collision found afterwards leaves a blob behind.
    kms.check_import_token_destination(token_path, params)

    session = _open_session(args)
    record = session.recover(_select(session, args.wallet))

    if record.error:
        error_console.print(f"[red]error:[/] {record.error}")
        return 1
    if record.key is None:
        error_console.print("[red]error:[/] this wallet's key could not be identified")
        return 1

    console.print(
        f"Wrapping [{record.share.index}] {escape(record.name)} "
        f"({escape(record.chain_label)}, {escape(record.key.curve)})"
    )
    if not record.address_proved:
        error_console.print(
            f"[yellow]warning:[/] this key was not proved to control "
            f"{escape(record.address or '<no address>')} -- {escape(record.verdict_detail)}. "
            "The key itself is intact; confirm with the public-key check below before "
            "you rely on the KMS key."
        )
    if record.scheme_warning:
        error_console.print(f"[yellow]warning:[/] {escape(record.scheme_warning)}")

    try:
        result = kms.write_encrypted_key_material(
            args.out, record.key, params, key_spec=args.key_spec
        )
    finally:
        # The key is not needed past the wrap, and this command would otherwise
        # sit on one for the length of a long printout.
        session.forget(record)

    written_token = (
        kms.write_import_token(token_path, params)
        if params.import_token is not None
        else None
    )
    if written_token is None:
        error_console.print(
            "[yellow]warning:[/] these import parameters carry no import token, so "
            "one could not be written. `import-key-material` needs the ImportToken "
            "from the same download as the wrapping public key -- supply it yourself."
        )

    console.print()
    console.print(
        kms.build_guide(
            result, params, key_id=args.key_id, token_path=written_token
        ).render(),
        # markup=False is load-bearing: ARNs and the JSON braces in these
        # commands would otherwise be eaten by rich's markup parser.
        # soft_wrap keeps rich from breaking a command mid-token.
        markup=False,
        highlight=False,
        soft_wrap=True,
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
        description=(
            "Recover wallet keys from a Station70 backup, show them in importable "
            "form, and export them to AWS KMS."
        ),
        epilog="Run `s70 tui <backup.json>` for the interactive interface.",
    )
    subparsers = parser.add_subparsers(dest="command")

    def add_backup_args(sub, *, positional: bool = True) -> None:
        if positional:
            sub.add_argument("backup", help="path to the backup JSON file")
        else:
            # `kms-export` already takes --params and --out, so a bare
            # positional path would be ambiguous to read on the command line.
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

    prepare = subparsers.add_parser(
        "kms-prepare",
        help="which AWS KMS key spec each wallet needs, and how to create it",
        description=(
            "Run this first. It decrypts nothing -- the curve comes from the backup's "
            "key_type field -- and prints the `aws kms create-key` and "
            "`get-parameters-for-import` commands you need to run online before "
            "`kms-export` has anything to wrap."
        ),
    )
    add_backup_args(prepare)
    prepare.add_argument(
        "--wallet", help="index, name, or address substring. Default: every wallet."
    )
    prepare.add_argument("--region", help="fill this AWS region into the commands")
    prepare.set_defaults(func=cmd_kms_prepare)

    export = subparsers.add_parser(
        "kms-export",
        help="OFFLINE: wrap one key as AWS KMS importable key material",
        description=(
            "Wraps one recovered private key for `aws kms import-key-material`. Opens "
            "no sockets and displays no key material -- the blob it writes is "
            "encrypted to AWS's HSM public key."
        ),
    )
    add_backup_args(export, positional=False)
    export.add_argument(
        "--wallet", required=True, help="index, name, or address substring"
    )
    export.add_argument(
        "--params",
        required=True,
        help="KMS import parameters: the console download (folder or zip), or the "
        "JSON from `aws kms get-parameters-for-import`",
    )
    export.add_argument(
        "--out",
        default="EncryptedKeyMaterial.bin",
        help="where to write the wrapped blob (default: %(default)s)",
    )
    # Both of these default to None rather than to their real defaults: the
    # wrapping algorithm may come from the bundle's README, and the key spec
    # from the key's curve, and an argparse default would silently pre-empt
    # either -- or trigger a spurious conflict error against the README.
    export.add_argument(
        "--wrapping-algorithm",
        default=None,
        choices=list(kms.WRAPPING_ALGORITHMS),
        help="the algorithm the import parameters were fetched with. Read from the "
        f"console download's README.txt when present, else {kms.DEFAULT_WRAPPING_ALGORITHM}.",
    )
    export.add_argument(
        "--key-spec",
        default=None,
        choices=[kms.KEYSPEC_SECP256K1, kms.KEYSPEC_ED25519],
        help="assert the KMS key spec. Refused if it contradicts the key's curve; "
        "omit it and the curve decides.",
    )
    export.add_argument(
        "--key-id", help="KMS key id or ARN, to fill into the printed commands"
    )
    export.add_argument(
        "--write-import-token",
        metavar="PATH",
        help="write the decoded import token here instead of beside --out. It is "
        "written either way: `import-key-material` needs it as raw bytes, and the "
        "printed command points at it.",
    )
    export.set_defaults(func=cmd_kms_export)

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
