"""Every leg of SEV-SNP verification, and a named failure for each.

The Rust crate's suite is the reference; these mirror it leg for leg against
the same vectors, so a divergence between the two implementations shows up as
a test failure rather than as a surprise in production. One negative per
member of :class:`FailKind`.
"""

import datetime
import hashlib
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from omne_attest import (
    POLICY_DEBUG,
    REPORT_LEN,
    SIGNED_LEN,
    Fail,
    FailKind,
    Policy,
    Report,
    Tcb,
    vectors,
    verify,
    verify_chain,
)
from omne_attest.snp import OID_HW_ID

REPORT = vectors.attestation()
VCEK = vectors.vcek()
ASK = vectors.ask()
ARK = vectors.ark()
ARK_SHA256 = vectors.ARK_SHA256


def mutated(at: int, xor: int) -> bytes:
    """A copy of the vector with one byte replaced, so a leg can be failed in
    isolation without disturbing the others."""
    b = bytearray(REPORT)
    b[at] ^= xor
    return bytes(b)


def parsed() -> Report:
    return Report.parse(REPORT)


def permissive(r: Report) -> Policy:
    """A policy that accepts the vector exactly as it is, so each negative test
    can move one thing and nothing else."""
    return Policy(
        measurement=r.measurement,
        report_data=r.report_data,
        tcb_floor=r.reported_tcb,
        max_vmpl=r.vmpl,
        reject_debug=False,
    )


def failure(fn, *args, **kwargs) -> Fail:
    with pytest.raises(Fail) as e:
        fn(*args, **kwargs)
    return e.value


# ------------------------------------------------------------- the happy path


def test_the_real_report_verifies_end_to_end_against_amds_chain():
    r = parsed()
    out = verify(REPORT, VCEK, ASK, ARK, ARK_SHA256, permissive(r))
    assert out.measurement == r.measurement
    assert out.chip_id == r.chip_id


def test_the_pinned_root_is_the_ark_we_ship():
    assert hashlib.sha256(ARK).digest() == ARK_SHA256


def test_the_vectors_are_the_same_bytes_the_rust_crate_asserts_on():
    """The two implementations must be held to one set of vectors, not two."""
    rust = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "snp"
    if not rust.is_dir():
        pytest.skip("the Rust tree is not present (installed package)")
    for name in ("attestation.bin", "kds_vcek.der", "milan_ask.der", "milan_ark.der"):
        assert (rust / name).read_bytes() == vectors.path(name).read_bytes(), name


def test_parse_reads_the_fields_at_the_abi_offsets():
    r = parsed()
    assert 2 <= r.version <= 5
    assert r.signature_algo == 1
    assert len(r.report_data) == 64
    assert len(r.measurement) == 48
    assert len(r.chip_id) == 64
    assert len(r.sig_r) == 48 and len(r.sig_s) == 48
    assert len(r.raw) == REPORT_LEN


# ------------------------------------------------------------------- parsing


def test_a_report_of_the_wrong_length_fails_by_length():
    f = failure(Report.parse, REPORT[:-1])
    assert f.kind is FailKind.LENGTH
    assert f.detail["length"] == REPORT_LEN - 1


def test_an_unsupported_version_fails_by_version_not_by_signature():
    b = bytearray(REPORT)
    b[0:4] = (6).to_bytes(4, "little")
    assert failure(Report.parse, bytes(b)).kind is FailKind.VERSION


def test_every_supported_version_still_parses():
    for v in (2, 3, 4, 5):
        b = bytearray(REPORT)
        b[0:4] = v.to_bytes(4, "little")
        assert Report.parse(bytes(b)).version == v


def test_an_unknown_signature_algorithm_is_refused_before_any_crypto():
    b = bytearray(REPORT)
    b[0x34:0x38] = (2).to_bytes(4, "little")
    f = failure(Report.parse, bytes(b))
    assert f.kind is FailKind.SIGNATURE_ALGO and f.detail["algo"] == 2


# --------------------------------------------------------- the report's signature


def test_a_single_flipped_bit_in_the_signed_region_fails_the_report_signature():
    r = Report.parse(mutated(0x100, 0x01))  # inside [0, SIGNED_LEN)
    assert 0x100 < SIGNED_LEN
    assert failure(r.verify_signature, VCEK).kind is FailKind.REPORT_SIGNATURE


def test_a_tampered_signature_fails_the_report_signature():
    r = Report.parse(mutated(0x2A0, 0x01))
    assert failure(r.verify_signature, VCEK).kind is FailKind.REPORT_SIGNATURE


def test_a_report_signed_by_some_other_key_does_not_verify_under_this_vcek():
    other = _self_signed_p384()
    assert failure(parsed().verify_signature, other).kind is FailKind.REPORT_SIGNATURE


def test_a_malformed_certificate_fails_by_parse_and_says_so():
    f = failure(parsed().verify_signature, b"junk")
    assert f.kind is FailKind.VCEK_PARSE
    assert "does not parse" in str(f)


def test_a_certificate_whose_key_is_not_p384_is_refused_by_key_type():
    # the ASK is RSA — a real certificate, the wrong kind of key
    assert failure(parsed().verify_signature, ASK).kind is FailKind.VCEK_KEY_TYPE


# ----------------------------------------------------------------- the chain


def test_an_unpinned_root_is_refused_before_the_chain_is_walked():
    wrong = bytearray(ARK_SHA256)
    wrong[0] ^= 1
    f = failure(verify_chain, VCEK, ASK, ARK, bytes(wrong))
    assert f.kind is FailKind.ARK_NOT_PINNED


def test_a_root_that_is_not_self_signed_fails_at_the_ark():
    # pass the ASK where the ARK belongs, pinned to its own hash so the pin passes
    f = failure(verify_chain, VCEK, ASK, ASK, hashlib.sha256(ASK).digest())
    assert f.kind is FailKind.CHAIN_SIGNATURE
    assert f.detail["leg"] == "ARK self-signature"


def test_an_intermediate_not_issued_by_the_root_fails_at_the_ask():
    f = failure(verify_chain, VCEK, VCEK, ARK, ARK_SHA256)
    assert f.kind is FailKind.CHAIN_SIGNATURE
    assert f.detail["leg"] == "ASK by ARK"


def test_a_leaf_not_issued_by_the_intermediate_fails_at_the_vcek():
    f = failure(verify_chain, ASK, ASK, ARK, ARK_SHA256)
    assert f.kind is FailKind.CHAIN_SIGNATURE
    assert f.detail["leg"] == "VCEK by ASK"


def test_garbage_in_the_chain_fails_by_parse():
    f = failure(verify_chain, VCEK, b"junk", ARK, ARK_SHA256)
    assert f.kind is FailKind.VCEK_PARSE


# ------------------------------------------------------- binding to this chip


def test_the_unmutated_report_binds_to_its_own_vcek():
    parsed().verify_vcek_binding(VCEK)  # does not raise


def test_a_vcek_for_a_different_chip_is_refused():
    r = Report.parse(mutated(0x1A0, 0xFF))  # CHIP_ID
    assert failure(r.verify_vcek_binding, VCEK).kind is FailKind.CHIP_ID_MISMATCH


def test_a_vcek_issued_at_a_different_tcb_is_refused():
    r = Report.parse(mutated(0x180, 0xFF))  # REPORTED_TCB, boot loader byte
    f = failure(r.verify_vcek_binding, VCEK)
    assert f.kind is FailKind.TCB_MISMATCH
    assert f.detail["report"] != f.detail["cert"]


def test_a_certificate_without_amds_extensions_is_refused_by_name():
    f = failure(parsed().verify_vcek_binding, ARK)  # a real cert, no AMD OIDs
    assert f.kind is FailKind.MISSING_EXTENSION
    assert f.detail["oid"] == OID_HW_ID
    assert OID_HW_ID in str(f)


# ---------------------------------------------------------------- the policy


def test_a_different_image_is_refused_by_measurement():
    r = parsed()
    p = Policy(measurement=bytes(48), max_vmpl=r.vmpl, reject_debug=False)
    assert failure(r.check_policy, p).kind is FailKind.MEASUREMENT


def test_a_report_not_bound_to_this_nonce_is_refused_by_report_data():
    r = parsed()
    p = Policy(report_data=bytes(64), max_vmpl=r.vmpl, reject_debug=False)
    assert failure(r.check_policy, p).kind is FailKind.REPORT_DATA


def test_a_guest_above_the_accepted_privilege_level_is_refused():
    b = bytearray(REPORT)
    b[0x30:0x34] = (3).to_bytes(4, "little")
    r = Report.parse(bytes(b))
    f = failure(r.check_policy, Policy(max_vmpl=0, reject_debug=False))
    assert f.kind is FailKind.VMPL and f.detail["vmpl"] == 3


def test_a_debug_enabled_guest_is_not_confidential_and_is_refused():
    b = bytearray(REPORT)
    policy_bits = int.from_bytes(b[8:16], "little") | POLICY_DEBUG
    b[8:16] = policy_bits.to_bytes(8, "little")
    r = Report.parse(bytes(b))
    p = Policy(max_vmpl=r.vmpl, reject_debug=True)
    assert failure(r.check_policy, p).kind is FailKind.DEBUG_ENABLED


def test_a_platform_below_the_tcb_floor_is_refused_and_names_both_sides():
    r = parsed()
    floor = Tcb(
        boot_loader=r.reported_tcb.boot_loader + 1,
        tee=r.reported_tcb.tee,
        snp=r.reported_tcb.snp,
        microcode=r.reported_tcb.microcode,
    )
    f = failure(
        r.check_policy, Policy(tcb_floor=floor, max_vmpl=r.vmpl, reject_debug=False)
    )
    assert f.kind is FailKind.TCB_BELOW_FLOOR
    assert f.detail["have"] == r.reported_tcb and f.detail["floor"] == floor


def test_tcb_meets_compares_every_component():
    base = Tcb(3, 0, 20, 209)
    assert base.meets(base)
    assert base.meets(Tcb(2, 0, 20, 209))
    assert not base.meets(Tcb(4, 0, 20, 209))
    assert not base.meets(Tcb(3, 1, 20, 209))
    assert not base.meets(Tcb(3, 0, 21, 209))
    assert not base.meets(Tcb(3, 0, 20, 210))


# ------------------------------------------------------------------- ordering


def test_the_first_failing_leg_is_the_one_reported():
    """Two legs broken at once: the earlier one is the one named."""
    r = parsed()
    broken_policy = Policy(measurement=bytes(48), max_vmpl=r.vmpl, reject_debug=False)
    f = failure(
        verify, mutated(0x100, 0x01), VCEK, ASK, ARK, ARK_SHA256, broken_policy
    )
    # the signature is checked before the policy, so that is what we hear about
    assert f.kind is FailKind.REPORT_SIGNATURE


def test_every_failure_says_which_leg_failed_in_words():
    seen = {
        FailKind.LENGTH: Fail(FailKind.LENGTH, length=1),
        FailKind.VERSION: Fail(FailKind.VERSION, version=9),
        FailKind.SIGNATURE_ALGO: Fail(FailKind.SIGNATURE_ALGO, algo=9),
        FailKind.REPORT_SIGNATURE: Fail(FailKind.REPORT_SIGNATURE),
        FailKind.VCEK_PARSE: Fail(FailKind.VCEK_PARSE, error="x"),
        FailKind.VCEK_KEY_TYPE: Fail(FailKind.VCEK_KEY_TYPE),
        FailKind.CHAIN_SIGNATURE: Fail(FailKind.CHAIN_SIGNATURE, leg="ASK by ARK"),
        FailKind.ARK_NOT_PINNED: Fail(FailKind.ARK_NOT_PINNED),
        FailKind.CHIP_ID_MISMATCH: Fail(FailKind.CHIP_ID_MISMATCH),
        FailKind.TCB_MISMATCH: Fail(
            FailKind.TCB_MISMATCH, report=Tcb(1, 1, 1, 1), cert=Tcb(2, 2, 2, 2)
        ),
        FailKind.MEASUREMENT: Fail(FailKind.MEASUREMENT),
        FailKind.REPORT_DATA: Fail(FailKind.REPORT_DATA),
        FailKind.VMPL: Fail(FailKind.VMPL, vmpl=3),
        FailKind.DEBUG_ENABLED: Fail(FailKind.DEBUG_ENABLED),
        FailKind.TCB_BELOW_FLOOR: Fail(
            FailKind.TCB_BELOW_FLOOR, have=Tcb(1, 1, 1, 1), floor=Tcb(2, 2, 2, 2)
        ),
        FailKind.MISSING_EXTENSION: Fail(FailKind.MISSING_EXTENSION, oid=OID_HW_ID),
    }
    assert set(seen) == set(FailKind), "a variant has no message test"
    for kind, f in seen.items():
        assert str(f) and str(f) != str(kind), kind


def _self_signed_p384() -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "not-a-vcek")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
        .sign(key, hashes.SHA384())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ------------------------------------------------------------- the known risk


def test_amds_vcek_still_loads_despite_its_serial_number_of_zero():
    """A canary, not a feature.

    AMD's KDS issues VCEK certificates with serial number 0, which RFC 5280
    forbids. ``cryptography`` currently accepts them with a deprecation
    warning and has said it will raise instead in a future release. When that
    lands this test fails first and says why — rather than the library
    breaking on real hardware with a parse error nobody expects.
    """
    cert = x509.load_der_x509_certificate(VCEK)
    assert cert.serial_number == 0, "AMD changed the serial; revisit the README note"
    parsed().verify_vcek_binding(VCEK)


def test_the_shipped_report_is_debug_enabled_and_a_real_policy_refuses_it():
    """The documented behaviour of the vector, pinned.

    The rented VM we could capture a report from was launched with the debug
    bit set. Every cryptographic leg verifies; the policy leg refuses it, which
    is what that leg is for. The README says so; this keeps the README true.
    """
    r = parsed()
    assert r.policy & POLICY_DEBUG, "the vector changed; the README note is now wrong"
    f = failure(
        verify, REPORT, VCEK, ASK, ARK, ARK_SHA256, Policy(max_vmpl=0, reject_debug=True)
    )
    assert f.kind is FailKind.DEBUG_ENABLED
