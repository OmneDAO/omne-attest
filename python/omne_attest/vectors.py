"""The test vectors, shipped with the package.

These are AMD's real Milan certificate chain and a real attestation report
produced by a rented confidential VM — not our hardware. That is what makes
them usable as vectors: the report carries that machine's CHIP_ID and launch
measurement. See ``README.md`` alongside this module for provenance.

The Rust crate and this package are held to the *same bytes*; a test asserts
the two copies are byte-identical whenever both trees are present.
"""

from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent / "vectors"

#: The pinned AMD Milan root, SHA-256 of its DER. Regenerate it yourself:
#: download the Milan ARK from AMD's KDS and hash it. The point of a pin is
#: that you do not take ours on trust.
ARK_SHA256 = bytes.fromhex(
    "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd"
)


def _read(name: str) -> bytes:
    return (_DIR / name).read_bytes()


def attestation() -> bytes:
    """A real 1,184-byte SEV-SNP ``ATTESTATION_REPORT``."""
    return _read("attestation.bin")


def vcek() -> bytes:
    """The VCEK certificate (DER) for that chip at that TCB, from AMD's KDS."""
    return _read("kds_vcek.der")


def ask() -> bytes:
    """AMD's Milan ASK — the intermediate (DER)."""
    return _read("milan_ask.der")


def ark() -> bytes:
    """AMD's Milan ARK — the root (DER)."""
    return _read("milan_ark.der")


def path(name: str) -> Path:
    """The on-disk path of a shipped vector, for tools that want a file."""
    return _DIR / name
