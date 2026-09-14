"""Guard rails for handling key material in a terminal application.

None of this makes the tool *safe* -- a process holding a private key on a
general-purpose OS is exposed to anything running as the same user. What it
does is remove the easy, avoidable leaks:

* secrets that end up in a traceback or a log line via ``repr()``
* secrets that end up in terminal scrollback and get screenshotted
* secrets that end up in a clipboard manager's on-disk history

"""

from __future__ import annotations

import ctypes


class Secret:
    """A bytes wrapper that refuses to reveal itself through ``repr``/``str``.

    The single most common way a tool like this leaks is an exception whose
    traceback includes a frame's locals, or a stray ``print(x)`` during
    debugging. Wrapping key material means those paths render
    ``<Secret bytes len=32>`` instead of the key.

    Use :meth:`reveal` at exactly the point of use and never store the result.
    """

    __slots__ = ("_value", "_label")

    def __init__(self, value: bytes, label: str = "bytes") -> None:
        self._value = bytes(value)
        self._label = label

    def reveal(self) -> bytes:
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            # Not constant-time; these are local comparisons of already-known
            # values, not an authentication check.
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __repr__(self) -> str:
        return f"<Secret {self._label} len={len(self._value)}>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)


def zeroize(buffer: bytearray) -> None:
    """Best-effort overwrite of a mutable buffer.

    This genuinely helps for a ``bytearray`` we control. It does *nothing* for
    the immutable ``bytes`` that most of the cryptography stack hands back --
    CPython will keep those alive until the GC gets to them, and they may have
    been copied during a realloc. Treat memory hygiene here as a nice-to-have,
    not a guarantee.
    """
    if not buffer:
        return
    try:
        ctypes.memset((ctypes.c_char * len(buffer)).from_buffer(buffer), 0, len(buffer))
    except (TypeError, ValueError):
        for i in range(len(buffer)):
            buffer[i] = 0


def mask(text: str, keep: int = 6) -> str:
    """Render a long string as ``head…tail`` for safe display in a list."""
    if len(text) <= keep * 2 + 1:
        return text
    return f"{text[:keep]}…{text[-keep:]}"
