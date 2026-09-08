"""omne-attest — verify an AMD SEV-SNP attestation report, in pure Python.

This is the Python half of `omne-attest <https://crates.io/crates/omne-attest>`_.
The Rust crate is the reference implementation; this package is a port that is
held to the same vectors — AMD's real Milan chain and a real 1,184-byte
attestation report captured from confidential silicon, shipped in
``omne_attest.vectors`` so the suite runs anywhere the package installs.

    >>> from omne_attest import Policy, Report, vectors, verify
    >>> report = Report.parse(vectors.attestation())
    >>> report.version
    5

Verifying end to end needs the chain and the pinned root::

    verify(
        vectors.attestation(), vectors.vcek(), vectors.ask(), vectors.ark(),
        vectors.ARK_SHA256,
        Policy(measurement=expected_image, report_data=expected_binding,
               max_vmpl=0, reject_debug=True),
    )

What this does not decide is whether to trust AMD. It pins the root you supply
and tells you exactly which check failed.
"""

from . import vectors
from .snp import (
    OID_BL_SPL,
    OID_HW_ID,
    OID_SNP_SPL,
    OID_TEE_SPL,
    OID_UCODE_SPL,
    POLICY_DEBUG,
    REPORT_LEN,
    SIGNED_LEN,
    Fail,
    FailKind,
    Policy,
    Report,
    Tcb,
    verify,
    verify_chain,
)

__version__ = "0.1.0"

__all__ = [
    "Fail",
    "FailKind",
    "OID_BL_SPL",
    "OID_HW_ID",
    "OID_SNP_SPL",
    "OID_TEE_SPL",
    "OID_UCODE_SPL",
    "POLICY_DEBUG",
    "Policy",
    "REPORT_LEN",
    "Report",
    "SIGNED_LEN",
    "Tcb",
    "vectors",
    "verify",
    "verify_chain",
    "__version__",
]
