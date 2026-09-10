"""Phase 2: preparing and signing asset-transfer transactions.

This package never submits anything. It builds, it signs, it hands you a blob
and the command to submit it. That boundary is deliberate: submission is the
irreversible step, and it should be a decision you make while looking at a
decoded transaction, not a side effect of running a recovery tool.

Chain coverage is uneven on purpose:

========  ==================================================================
chain     what phase 2 does
========  ==================================================================
Solana    sweeps SPL tokens then native SOL
Aptos     sweeps fungible assets then native APT
Stellar   full teardown then ``account_merge``
XRPL      trustline teardown then ``AccountDelete``
Sui       signs unsigned bytes produced by the ``sui`` CLI
EVM       nothing -- asset discovery cannot be made complete; see evm.py
Polkadot  nothing -- import the keystore into Talisman and transfer there
Canton    nothing -- needs a participant node, not a client-side sweep
========  ==================================================================
"""

from __future__ import annotations

from typing import Any, Protocol

from s70.errors import S70Error, UnsupportedChainError
from s70.keymaterial import KeyMaterial
from s70.txn import aptos_tx, solana_tx, stellar_tx, sui_tx, xrpl_tx
from s70.txn.job import Asset, Precondition, SignedBundle, TransferJob


class ChainTransfer(Protocol):
    CHAIN_ID: str

    def inspect(self, source: str, destination: str, **kwargs: Any) -> TransferJob: ...

    def sign(self, job: TransferJob, key: KeyMaterial, **kwargs: Any) -> SignedBundle: ...


_MODULES = {
    solana_tx.CHAIN_ID: solana_tx,
    aptos_tx.CHAIN_ID: aptos_tx,
    stellar_tx.CHAIN_ID: stellar_tx,
    xrpl_tx.CHAIN_ID: xrpl_tx,
    sui_tx.CHAIN_ID: sui_tx,
}

#: Chains phase 2 can handle, for UI gating.
SUPPORTED = tuple(_MODULES)


def module_for(chain_id: str):
    """Return the transfer module for ``chain_id``, or raise."""
    module = _MODULES.get(chain_id)
    if module is None:
        from s70 import chains

        spec = chains.by_id(chain_id)
        if spec is not None and spec.signing_note:
            raise UnsupportedChainError(f"{spec.label}: {spec.signing_note}")
        raise UnsupportedChainError(
            f"phase 2 does not support {chain_id!r}. Supported: {', '.join(SUPPORTED)}"
        )
    return module


def inspect(chain_id: str, source: str, destination: str, **kwargs: Any) -> TransferJob:
    """Run the online read phase for one chain."""
    _validate_destination(chain_id, destination)
    return module_for(chain_id).inspect(source, destination, **kwargs)


def sign(job: TransferJob, key: KeyMaterial, **kwargs: Any) -> SignedBundle:
    """Run the offline signing phase for a job file."""
    module = module_for(job.chain)

    # Re-check the destination here, not just in `inspect`. The job file
    # crosses the air gap on removable media and carries no integrity
    # protection, so the address it names at signing time is not necessarily
    # the one that was validated when it was written.
    _validate_destination(job.chain, job.destination_address)

    if not job.ready:
        failures = "\n  ".join(
            f"{p.name}: {p.detail}" for p in job.blocking_failures
        )
        raise S70Error(
            "this job has unmet preconditions and the transaction would fail on chain:\n  "
            + failures
            + "\n\nFix them, then re-run `s70 inspect`."
        )

    return module.sign(job, key, **kwargs)


def _validate_destination(chain_id: str, destination: str) -> None:
    """Refuse a destination that is not an address on the expected chain.

    Cheap, and it catches the genuinely catastrophic paste error of sending to
    a well-formed address on the wrong chain.
    """
    from s70 import chains

    spec = chains.by_id(chain_id)
    if spec is None:
        return
    if not spec.matches_shape(destination):
        raise S70Error(
            f"{destination!r} is not a valid {spec.label} address. Refusing to build a "
            "transaction to it -- double-check you pasted the right destination."
        )


__all__ = [
    "SUPPORTED",
    "Asset",
    "Precondition",
    "SignedBundle",
    "TransferJob",
    "inspect",
    "module_for",
    "sign",
]
