# Threat model

What this tool defends against, what it does not, and why each design
decision is the way it is.

---

## What we are protecting

A wallet private key is a **bearer instrument**. Anyone who observes it, once,
controls the funds — permanently, irreversibly, with no revocation and no
recovery. That asymmetry drives everything below: a mitigation that reduces
exposure from "leaked forever" to "leaked briefly" is not a small improvement,
it is the whole game.

---

## In scope

### Accidental persistence

The realistic failure mode for a tool like this is not an attacker. It is the
key ending up somewhere durable by accident.

| Vector | Mitigation |
|---|---|
| Terminal scrollback | The TUI runs on the alternate screen buffer, which is not added to primary scrollback and is cleared on exit. `s70 reveal` writes to the primary buffer and so requires `--unsafe-print`. |
| Clipboard managers | **No clipboard support for private keys at all.** See below. |
| Tracebacks and log lines | Key material is wrapped in `Secret`, whose `__repr__`/`__str__`/`__format__` render `<Secret bytes len=32>`. `ImportFormat.__repr__` and `ImportGuide.__repr__` are overridden the same way. |
| Files | Nothing is written unless you ask. `.gitignore` excludes `*.json`, `*.pem`, `*.key`, `keystore-*`, `job-*`, `signed-*`. Written keystores get `0600` where the OS supports it. |
| Screenshots and screen sharing | Keys are masked by default and re-mask after 90 seconds. Everything up to the reveal is safe to demo. |
| Shell history | No command takes a key as an argument. |

### Over-exposure within a session

Decryption is **lazy and per-wallet**. Consequences:

- Opening the inventory decrypts nothing.
- Recovering one wallet does not touch the others.
- Leaving a reveal screen calls `session.forget()`, dropping the key while
  keeping the verdict — so the inventory still shows what was established
  without holding the thing that established it.
- `s70 verify` and the TUI's *verify all* run with `forget_keys=True`: they
  produce 23 verdicts without ending up holding 23 private keys.

The TUI's status bar shows a live **keys in memory** count.

### Wrong-target mistakes

Catastrophic and entirely preventable:

- **Wrong chain for the destination.** `s70 inspect` refuses a destination
  that is not a well-formed address on the source's chain.
- **Wrong key for the account.** Every signer re-derives the address from the
  key and refuses to sign if it does not match the job's source.
- **Wrong format for the wallet.** Formats are keyed off the *target wallet*,
  never the curve, because four Ed25519 chains want four incompatible
  strings from identical bytes.
- **Wrong curve.** A 32-byte plaintext is valid on both curves; the tool
  offers both candidates and lets the address decide rather than guessing.

### Silent incorrectness

The failure that worries me most is not a crash — it is a plausible, wrong
answer. Specific defences:

- **StrKey round-trips before emission.** A checksum appended big-endian
  instead of little-endian yields a 56-character string that looks perfect
  and fails inside Freighter. `strkey.encode()` decodes its own output and
  raises rather than emit a suspect key.
- **Solana transactions round-trip before emission.**
  `VersionedTransaction.from_bytes(bytes(tx)) == tx`.
- **Keccak-256 is not SHA3-256.** They differ only in a padding byte, and a
  mix-up produces a well-formed but completely wrong EVM address. There is an
  explicit test asserting they differ, plus the known empty-string vector.
- **64-byte plaintext consistency.** The embedded public key must match the
  one derived from the seed, or it is a hard error.
- **`unverifiable` is distinct from `verified`.** Canton cannot be checked,
  and the tool says "cannot check" rather than quietly passing.

### Dependency surface

Fewer moving parts near a private key. The core needs five packages, chosen
so the set can be vendored as wheels onto an air-gapped machine, and all the
address/key encodings — base58, bech32, StrKey, SS58 — are implemented here
in dependency-free, readable Python rather than pulled from elsewhere.

The heavy chain SDKs are an **optional** extra, imported lazily, and needed
only for phase 2. There is no Sui SDK at all: its signing scheme is short and
stable enough to implement directly, and the `sui` CLI does the building.

---

## Out of scope

Stated plainly, because a security document that implies more coverage than
it has is worse than none.

### A compromised operating system

A keylogger, a malicious extension with clipboard access, an infected shell
profile, a hypervisor, memory-scraping malware — none of this is defended
against and none of it can be, from inside a Python process. **Run recovery on
a machine you trust**, ideally a freshly imaged one that has never browsed
the web.

### Memory forensics

`security.zeroize()` does a best-effort overwrite of a `bytearray`. It does
nothing for the immutable `bytes` objects the cryptography stack returns:
CPython keeps those alive until garbage collection, they may have been copied
during a realloc, and they may have been paged to swap or captured in a
hibernation image or core dump.

Treat memory hygiene here as a genuine but partial reduction of the window,
not a guarantee. If you need better, use a machine with encrypted swap, or
disable swap for the duration.

### Shoulder surfing and recording

Masking and the re-mask timer help. They do not help against a camera, an
active screen share, or a colleague behind you. The consent gate warns; it
cannot enforce.

### The compromise that already happened

If the key was **stolen** rather than merely stranded, recovery does not
undo that. Two consequences the UI states directly:

- A sweeper bot may be watching the address and will take any gas you send it
  to fund a rescue transaction. Land the fee and the sweep in the same
  transaction where the chain allows it.
- If the *seed phrase* was compromised, every derived address on every chain
  is permanently hostile. Revoking approvals does not help. There is no
  recovering an address in that state — only racing it.

### Completeness of asset discovery

This is why EVM transaction building is deliberately absent.

ERC-20 has **no reverse index**. You cannot ask "which tokens does address X
hold?", only "what is X's balance of token T?" for a T you already know.
Discovering the T-set means indexing `Transfer` logs across every chain's
full history. Wallets paper over this with curated token lists that cover a
few dozen tokens per chain. LP positions, staked and vesting and locked
balances, bridged assets, NFTs, and unclaimed airdrops are each a separate
discovery problem.

A sweep that looks complete but is not is worse than no sweep, because it
retires your attention. So for EVM the tool points you at Rabby's
multi-chain portfolio view, revoke.cash, and block explorers' token-holdings
tabs — explorers index all `Transfer` logs, which is the closest thing to
ground truth available.

The same caveat applies in smaller form elsewhere and is surfaced per chain:
if the Aptos indexer is unreachable, `inspect` warns that only native APT
will be swept rather than reporting an empty wallet.

---

## Specific decisions, and why

### No clipboard for private keys

The system clipboard is a **global, unauthenticated IPC channel**. Any process
running as your user can poll it; on X11, any window can. Browsers read it on
paste events and some read it on focus. Clipboard managers — KDE Klipper,
Windows Clipboard History, macOS third-party tools — persist contents to
disk, often unencrypted, sometimes synced to a cloud account.

Textual's `copy_to_clipboard()` uses **OSC 52**, which is worse in a specific
way: it exfiltrates *through the terminal*, so a compromised or logging
terminal emulator, tmux server, or SSH session sees the plaintext. Over SSH
the secret crosses a network boundary as an escape sequence. It also silently
fails in GNOME Terminal, Konsole and macOS Terminal.app, which means a
"copied!" toast that copied nothing.

So: private keys are read off the screen and typed, or written to a file you
control. Signed transaction blobs are a different matter — they are headed for
a public mempool anyway — and clipboard for those would be reasonable.

### The tool never submits

Submission is the irreversible step. Separating it means:

- you can decode the transaction and read it before it is real
- a bug in this tool cannot move funds on its own
- the signing machine never needs a network connection

Every `SignedBundle` carries the submission command and a pointer to a
decoder. Use them. Sui's own guidance is worth repeating for every chain here:
never blind-sign opaque bytes.

### Two-phase inspect/sign

None of these chains can build a valid transaction fully offline — every one
needs at least a sequence number. Rather than pretend otherwise, the split is
explicit: `inspect` is online with **no keys loaded**, `sign` holds keys and
**opens no sockets**. Job files contain only public data, so carrying one on a
USB stick leaks nothing.

### A typed consent phrase

Typing `RECOVER` is not security theatre against an attacker — an attacker
types it too. It is a deliberate speed bump against *you*, on a tool whose
entire purpose is to put bearer instruments on a screen. It also gives the
warnings a place to be read.

---

## Recommended operating procedure

1. **Prove the tool works first.** `s70 selftest --cross-check`, then
   `pytest`. This code has never been executed by its author (see the README's
   *Testing status*).
2. **Use a clean machine.** Freshly imaged, full-disk encryption, no browsing.
   Air-gapped if you can — but note Solana's 60–90 second blockhash window
   makes a walk-between-machines flow impossible for that chain specifically.
3. **Inventory before decrypting.** `s70 list` and `s70 verify` tell you the
   backup is sound without displaying anything.
4. **Recover one wallet at a time.** Import it, confirm the wallet shows the
   address you expect, move the funds, then move on. Do not decrypt
   everything up front.
5. **Verify the address after every import.** This is the only end-to-end
   proof that you pasted the right string into the right field.
6. **Keep the backup until the funds have moved.** Freighter in particular
   cannot recover an imported secret key from its recovery phrase.
7. **Destroy the artefacts afterwards.** Keystore files, job files, signed
   bundles, and the backup copy on the recovery machine. Prefer a full disk
   wipe to file deletion.
8. **Treat every recovered key as burned.** It has been on a general-purpose
   OS and on a screen. Move the assets to a fresh key you generated yourself
   — not to an address this tool ever displayed a key for.
