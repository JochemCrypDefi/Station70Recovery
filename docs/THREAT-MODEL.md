# Staying safe

A private key is a bearer instrument: anyone who sees it once controls the
funds, permanently and irreversibly. This page is what the tool does to limit
who can see yours, what it cannot do, and how to run a recovery safely.

---

## How to run a recovery

1. **Use a clean machine, offline.** Freshly imaged if possible, full-disk
   encryption, no browsing on it. Nothing this tool does needs a network
   connection, so it should not have one.
2. **Check the backup before revealing anything.** `s70 list` and
   `s70 verify` tell you the file is sound and every key decrypts, without
   putting a key on screen.
3. **Do one wallet at a time.** Recover it, import it, confirm the wallet
   shows the address you expected, then move on to the next.
4. **Always confirm the address after importing.** It is the only proof you
   pasted the right key into the right field.
5. **Keep the backup file until the funds have actually moved.** Freighter in
   particular cannot recover an imported key from its recovery phrase.
6. **Destroy the leftovers afterwards** — keystore files and the copy of the
   backup on the recovery machine. A disk wipe beats deleting files. The
   wrapped KMS blob is ciphertext and does not need destroying, but there is
   no reason to keep a used one either.
7. **Treat every recovered key as burned.** It has been on a general-purpose
   OS and on a screen. Move the assets to a fresh key you generated yourself,
   never to an address this tool has shown a key for.

---

## What the tool does to protect you

**Nothing is decrypted until you consent.** Typing `RECOVER` is the gate. Past
it, the app decrypts and checks every wallet at once — that is what makes the
inventory complete and accurate the moment it appears — and then immediately
discards the key material, keeping only the verdicts. `s70 list` decrypts
nothing at all, so you can inspect a backup without passing the gate.

**Keys are discarded as soon as they have been used.** The bulk check above
drops each key the instant its verdict is recorded. Opening a wallet decrypts
that one key again, on its own, and leaving the screen drops it again.
`s70 verify` does the same for every wallet in turn.

**Keys stay off your terminal scrollback.** The TUI draws on the alternate
screen buffer, so what it shows is not added to your scrollback and is gone
when you quit. No command-line command prints a key at all.

**Keys are hidden until you press `r`,** and hide themselves again when you
leave the screen or a dialog opens on top of it.

**Screenshots are disabled.** The TUI's command palette is switched off,
because it offers a "save screenshot" action that would write a picture of a
revealed key to disk.

**Keys don't leak into error messages.** Key material is wrapped so that a
crash, a log line or a stray `print` shows `<Secret bytes len=32>` rather than
your key.

**No command takes a key as an argument,** so nothing lands in your shell
history.

**The tool refuses obvious mistakes.** Before wrapping a key for KMS it
rebuilds the public key from the private one and refuses if it does not match
what was recovered, and it refuses a `--key-spec` that contradicts the key's
curve. The same 32 bytes are a valid key on both curves and derive unrelated
addresses, so that check is the difference between a KMS key you control and a
KMS key for an account nobody owns. It also refuses to write a Polkadot
keystore from a key that did not reproduce the recorded address, because that
file would import somebody else's account.

**One thing decides what counts as proved.** A key is "proved" only when it
re-derived the address recorded beside it. Every caveat, warning and refusal
reads that one answer, so a check that could not be run is never quietly
treated as a check that passed.

**The tool opens no sockets.** There is no network code in it at all, so it
cannot leak a key over the wire and cannot act on your accounts. Its whole job
ends at handing you the key, or handing KMS the key.

**The KMS blob is safe to carry.** What `kms-export` writes is encrypted to
AWS's HSM public key, so it can cross an untrusted USB stick without exposing
anything. The tool never writes the *unencrypted* PKCS#8 key material to disk
at all — there is deliberately no option to.

---

## What it cannot protect you from

**A compromised computer.** A keylogger, a malicious browser extension, an
infected shell profile or memory-scraping malware all defeat everything above,
and no program can prevent that from the inside. This is why the clean machine
is the first step and not the last.

**Anyone who can see your screen.** Hiding keys until you press `r` helps
against a screen share you forgot about. It does nothing against a camera or
a person behind you.

**The clipboard, if you use it.** `ctrl+c` copies your mouse selection,
because being unable to get a key out without retyping it is worse. But the
clipboard is readable by every program running as you, clipboard managers save
history to disk, and over SSH the copy travels through your terminal to the
local machine. Prefer reading the key off the screen. If you do copy one,
paste it once and copy something harmless afterwards.

**Traces left in memory.** The tool overwrites what it can, but Python keeps
copies it cannot reach, and those may reach swap, a hibernation image or a
crash dump. It is a real reduction of the window, not a guarantee. Encrypted
swap — or no swap — closes the gap.

**A compromise that already happened.** If the key was stolen rather than
merely stranded, recovering it does not undo that. A bot may be watching the
address and will take any gas you send to fund a rescue. And if the *seed
phrase* leaked, every address derived from it on every chain is hostile
forever — approvals can be revoked, the address cannot be saved.

**Knowing what an account holds.** The tool never reads chain state, so it
cannot tell you. Do not assume an address is empty because you can't see
anything: on EVM chains nothing can reliably enumerate every token an address
holds — ERC-20 has no reverse index, and LP, staked, vesting, locked and
bridged positions are invisible to a naive scan. Import the key into a wallet
with a portfolio view and look properly.

**What happens after the key reaches KMS.** The key is then governed by your
AWS account's IAM policy and CloudTrail, not by anything here. Importing is
one-way: KMS will never export it again. And a raw `aws kms sign` on a
secp256k1 key returns DER with no recovery id and no low-S normalisation,
which several chains reject — a correctness trap in whatever signs on top of
KMS. See [KMS-EXPORT.md](KMS-EXPORT.md).

---

## Before trusting it with real money

Run the test suite:

```bash
pip install pytest
pytest -q
```

The tests prove the tool is self-consistent. They cannot prove an address
derivation matches what a chain actually does — a subtly wrong derivation
would be consistently wrong and the tests would still pass.

So the check that counts is the cheap one: **recover one key, import it, and
confirm the wallet shows the address you expected.** Do that before moving
anything of value.
