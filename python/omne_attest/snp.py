"""AMD SEV-SNP attestation reports — parse + verify, in pure Python.

A port of the Rust crate's ``snp`` module, checked against the same vectors.
The report is the 1,184-byte ``ATTESTATION_REPORT`` of the SEV-SNP ABI
(versions 2-5; real AMD silicon reports v5). Its first 0x2A0 bytes are signed
(ECDSA P-384 / SHA-384) by the chip's **VCEK** — a per-chip, per-TCB key whose
certificate AMD's Key Distribution Service issues, chained VCEK <- ASK <- ARK
(RSASSA-PSS, SHA-384, 4096-bit). Verifying a report therefore means:

  1. parse the fixed layout;
  2. ECDSA-P384 verify ``report[..0x2A0]`` under the VCEK's public key;
  3. verify the chain VCEK <- ASK <- ARK against a pinned ARK;
  4. check the VCEK is the right one for this report: its hwID extension
     equals the report's CHIP_ID and its TCB-component extensions equal the
     report's REPORTED_TCB (otherwise a valid signature from some other
     chip's key would pass);
  5. apply the relying party's policy: expected measurement, report_data
     binding, TCB floors, VMPL, debug bit.

What this module does NOT decide: whether to trust AMD. It pins the ARK the
caller supplies and says exactly which check failed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

REPORT_LEN = 0x4A0
SIGNED_LEN = 0x2A0

# AMD VCEK certificate extension OIDs (VCEK Certificate and KDS Interface
# Specification): the TCB component SPLs and the hardware id.
OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
OID_HW_ID = "1.3.6.1.4.1.3704.1.4"

#: Debug bit in the guest policy (bit 19): a debug-enabled guest is not confidential.
POLICY_DEBUG = 1 << 19


class FailKind(Enum):
    """Which leg of verification failed. One member per Rust ``Fail`` variant."""

    LENGTH = "length"
    VERSION = "version"
    SIGNATURE_ALGO = "signature_algo"
    REPORT_SIGNATURE = "report_signature"
    VCEK_PARSE = "vcek_parse"
    VCEK_KEY_TYPE = "vcek_key_type"
    CHAIN_SIGNATURE = "chain_signature"
    ARK_NOT_PINNED = "ark_not_pinned"
    CHIP_ID_MISMATCH = "chip_id_mismatch"
    TCB_MISMATCH = "tcb_mismatch"
    MEASUREMENT = "measurement"
    REPORT_DATA = "report_data"
    VMPL = "vmpl"
    DEBUG_ENABLED = "debug_enabled"
    TCB_BELOW_FLOOR = "tcb_below_floor"
    MISSING_EXTENSION = "missing_extension"


class Fail(Exception):
    """A named verification failure — ``kind`` says which leg, in order."""

    def __init__(self, kind: FailKind, **detail):
        self.kind = kind
        self.detail = detail
        super().__init__(self._message())

    def _message(self) -> str:
        k, d = self.kind, self.detail
        if k is FailKind.LENGTH:
            return f"attestation report is {d['length']} bytes, expected {REPORT_LEN}"
        if k is FailKind.VERSION:
            return f"unsupported report version {d['version']} (supported: 2..=5)"
        if k is FailKind.SIGNATURE_ALGO:
            return (
                f"unsupported signature algorithm {d['algo']} "
                "(1 = ECDSA P-384/SHA-384)"
            )
        if k is FailKind.REPORT_SIGNATURE:
            return "the report's signature does not verify under the VCEK"
        if k is FailKind.VCEK_PARSE:
            return f"certificate does not parse: {d['error']}"
        if k is FailKind.VCEK_KEY_TYPE:
            return "the VCEK's public key is not a P-384 key"
        if k is FailKind.CHAIN_SIGNATURE:
            return f"certificate chain broken at: {d['leg']}"
        if k is FailKind.ARK_NOT_PINNED:
            return "the supplied root does not match the pinned ARK hash"
        if k is FailKind.CHIP_ID_MISMATCH:
            return "the VCEK belongs to a different chip than the report"
        if k is FailKind.TCB_MISMATCH:
            return (
                "the VCEK was issued at a different TCB than the report claims "
                f"(report {d['report']}, cert {d['cert']})"
            )
        if k is FailKind.MEASUREMENT:
            return "launch measurement is not the expected image"
        if k is FailKind.REPORT_DATA:
            return "report_data is not bound to the expected rental, nonce and key"
        if k is FailKind.VMPL:
            return f"guest is at VMPL {d['vmpl']}, above the accepted level"
        if k is FailKind.DEBUG_ENABLED:
            return "the guest policy allows debug: it is not confidential"
        if k is FailKind.TCB_BELOW_FLOOR:
            return f"platform TCB {d['have']} is below the required floor {d['floor']}"
        if k is FailKind.MISSING_EXTENSION:
            return f"the VCEK is missing required AMD extension {d['oid']}"
        return str(k)


@dataclass(frozen=True, order=True)
class Tcb:
    """A TCB_VERSION: byte 0 boot loader, byte 1 TEE, byte 6 SNP firmware, byte 7 microcode."""

    boot_loader: int
    tee: int
    snp: int
    microcode: int

    @classmethod
    def from_u64_le(cls, raw: bytes) -> "Tcb":
        return cls(boot_loader=raw[0], tee=raw[1], snp=raw[6], microcode=raw[7])

    def meets(self, floor: "Tcb") -> bool:
        """Every component at or above the floor."""
        return (
            self.boot_loader >= floor.boot_loader
            and self.tee >= floor.tee
            and self.snp >= floor.snp
            and self.microcode >= floor.microcode
        )


@dataclass(frozen=True)
class Policy:
    """The relying party's policy — what a buyer accepts."""

    measurement: Optional[bytes] = None
    report_data: Optional[bytes] = None
    tcb_floor: Optional[Tcb] = None
    max_vmpl: int = 0
    reject_debug: bool = True


class Report:
    """A parsed attestation report. Construct with :meth:`parse`."""

    __slots__ = (
        "version", "guest_svn", "policy", "family_id", "image_id", "vmpl",
        "signature_algo", "current_tcb", "platform_info", "report_data",
        "measurement", "host_data", "id_key_digest", "author_key_digest",
        "report_id", "reported_tcb", "chip_id", "committed_tcb", "launch_tcb",
        "sig_r", "sig_s", "raw",
    )

    @classmethod
    def parse(cls, b: bytes) -> "Report":
        if len(b) != REPORT_LEN:
            raise Fail(FailKind.LENGTH, length=len(b))

        def u32_at(o: int) -> int:
            return int.from_bytes(b[o : o + 4], "little")

        def u64_at(o: int) -> int:
            return int.from_bytes(b[o : o + 8], "little")

        version = u32_at(0)
        # v2..=5: the signed region (first 0x2A0) and every field we read sit at
        # stable offsets across these versions — newer versions added data in
        # previously-reserved bytes. The SIGNATURE over [0..0x2A0] is the real
        # gate; a wrong offset would fail it. GCP's real silicon reports v5.
        if not 2 <= version <= 5:
            raise Fail(FailKind.VERSION, version=version)
        signature_algo = u32_at(0x34)
        if signature_algo != 1:  # 1 = ECDSA P-384 with SHA-384
            raise Fail(FailKind.SIGNATURE_ALGO, algo=signature_algo)

        r = cls.__new__(cls)
        r.version = version
        r.guest_svn = u32_at(4)
        r.policy = u64_at(8)
        r.family_id = b[0x10:0x20]
        r.image_id = b[0x20:0x30]
        r.vmpl = u32_at(0x30)
        r.signature_algo = signature_algo
        r.current_tcb = Tcb.from_u64_le(b[0x38:0x40])
        r.platform_info = u64_at(0x40)
        r.report_data = b[0x50:0x90]
        r.measurement = b[0x90:0xC0]
        r.host_data = b[0xC0:0xE0]
        r.id_key_digest = b[0xE0:0x110]
        r.author_key_digest = b[0x110:0x140]
        r.report_id = b[0x140:0x160]
        r.reported_tcb = Tcb.from_u64_le(b[0x180:0x188])
        r.chip_id = b[0x1A0:0x1E0]
        r.committed_tcb = Tcb.from_u64_le(b[0x1E0:0x1E8])
        r.launch_tcb = Tcb.from_u64_le(b[0x1F0:0x1F8])
        # r and s are little-endian 72-byte fields; P-384 scalars are 48 bytes
        r.sig_r = bytes(reversed(b[0x2A0 : 0x2A0 + 48]))
        r.sig_s = bytes(reversed(b[0x2E8 : 0x2E8 + 48]))
        r.raw = bytes(b)
        return r

    def verify_signature(self, vcek_der: bytes) -> None:
        """Step 2: the report's own signature under the VCEK public key (DER cert)."""
        cert = _load_cert(vcek_der)
        pub = cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(
            pub.curve, ec.SECP384R1
        ):
            raise Fail(FailKind.VCEK_KEY_TYPE)
        sig = encode_dss_signature(
            int.from_bytes(self.sig_r, "big"), int.from_bytes(self.sig_s, "big")
        )
        digest = hashlib.sha384(self.raw[:SIGNED_LEN]).digest()
        try:
            pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA384())))
        except InvalidSignature:
            raise Fail(FailKind.REPORT_SIGNATURE) from None

    def verify_vcek_binding(self, vcek_der: bytes) -> None:
        """Step 4: the VCEK must be THIS chip's key at THIS TCB."""
        cert = _load_cert(vcek_der)
        # hwID: OCTET STRING (DER) holding the 64-byte chip id
        if _der_octet_or_raw(_ext_bytes(cert, OID_HW_ID)) != self.chip_id:
            raise Fail(FailKind.CHIP_ID_MISMATCH)
        # SPLs: DER INTEGERs
        cert_tcb = Tcb(
            boot_loader=_der_int_u8(_ext_bytes(cert, OID_BL_SPL)),
            tee=_der_int_u8(_ext_bytes(cert, OID_TEE_SPL)),
            snp=_der_int_u8(_ext_bytes(cert, OID_SNP_SPL)),
            microcode=_der_int_u8(_ext_bytes(cert, OID_UCODE_SPL)),
        )
        if cert_tcb != self.reported_tcb:
            raise Fail(FailKind.TCB_MISMATCH, report=self.reported_tcb, cert=cert_tcb)

    def check_policy(self, p: Policy) -> None:
        if p.measurement is not None and p.measurement != self.measurement:
            raise Fail(FailKind.MEASUREMENT)
        if p.report_data is not None and p.report_data != self.report_data:
            raise Fail(FailKind.REPORT_DATA)
        if self.vmpl > p.max_vmpl:
            raise Fail(FailKind.VMPL, vmpl=self.vmpl)
        if p.reject_debug and self.policy & POLICY_DEBUG != 0:
            raise Fail(FailKind.DEBUG_ENABLED)
        if p.tcb_floor is not None and not self.reported_tcb.meets(p.tcb_floor):
            raise Fail(
                FailKind.TCB_BELOW_FLOOR, have=self.reported_tcb, floor=p.tcb_floor
            )

    def __repr__(self) -> str:
        return (
            f"Report(version={self.version}, vmpl={self.vmpl}, "
            f"reported_tcb={self.reported_tcb}, "
            f"measurement={self.measurement.hex()[:16]}...)"
        )


def _load_cert(der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except Exception as e:
        raise Fail(FailKind.VCEK_PARSE, error=str(e)) from None


def _ext_bytes(cert: x509.Certificate, oid: str) -> bytes:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
    except x509.ExtensionNotFound:
        raise Fail(FailKind.MISSING_EXTENSION, oid=oid) from None
    value = ext.value
    if isinstance(value, x509.UnrecognizedExtension):
        return value.value
    return value.public_bytes()


def _der_octet_or_raw(v: bytes) -> bytes:
    """An extension value is DER: 0x04 len bytes (short or long form)."""
    if v[:1] == b"\x04":
        body = _der_body(v)
        if body is not None:
            return body
    return v


def _der_body(v: bytes) -> Optional[bytes]:
    if len(v) < 2:
        return None
    n = v[1]
    if n < 0x80:
        return v[2 : 2 + n] if len(v) >= 2 + n else None
    count = n & 0x7F
    if count == 0 or len(v) < 2 + count:
        return None
    length = int.from_bytes(v[2 : 2 + count], "big")
    start = 2 + count
    return v[start : start + length] if len(v) >= start + length else None


def _der_int_u8(v: bytes) -> int:
    """0x02 len value...: take the last byte (SPLs are < 256)."""
    if v[:1] == b"\x02" and len(v) >= 3:
        return v[-1]
    return v[-1] if v else 0


def verify_chain(
    vcek_der: bytes, ask_der: bytes, ark_der: bytes, pinned_ark_sha256: bytes
) -> None:
    """Step 3: VCEK <- ASK <- ARK, ARK pinned by SHA-256 of its DER. RSASSA-PSS/SHA-384."""
    if hashlib.sha256(ark_der).digest() != pinned_ark_sha256:
        raise Fail(FailKind.ARK_NOT_PINNED)
    ark = _load_cert(ark_der)
    ask = _load_cert(ask_der)
    vcek = _load_cert(vcek_der)
    _rsa_pss_verify_cert(ark, ark, "ARK self-signature")
    _rsa_pss_verify_cert(ask, ark, "ASK by ARK")
    _rsa_pss_verify_cert(vcek, ask, "VCEK by ASK")


def _rsa_pss_verify_cert(
    subject: x509.Certificate, issuer: x509.Certificate, leg: str
) -> None:
    pub = issuer.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise Fail(FailKind.CHAIN_SIGNATURE, leg=leg)
    try:
        pub.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
            hashes.SHA384(),
        )
    except InvalidSignature:
        raise Fail(FailKind.CHAIN_SIGNATURE, leg=leg) from None


def verify(
    report: bytes,
    vcek_der: bytes,
    ask_der: bytes,
    ark_der: bytes,
    pinned_ark_sha256: bytes,
    policy: Policy,
) -> Report:
    """The whole verification, in order, first failure named.

    Raises :class:`Fail` on the first leg that does not hold.
    """
    r = Report.parse(report)
    r.verify_signature(vcek_der)
    verify_chain(vcek_der, ask_der, ark_der, pinned_ark_sha256)
    r.verify_vcek_binding(vcek_der)
    r.check_policy(policy)
    return r
