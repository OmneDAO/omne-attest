//! Every leg of SEV-SNP verification, and a named failure for each.
//!
//! `snp.rs` shipped with no tests. The module's whole promise is that a
//! verification failure tells you *which* check failed — these tests are what
//! make that promise checkable, one negative per variant of `Fail`.
//!
//! Fixtures are AMD's real Milan chain (ARK/ASK from AMD's KDS, a VCEK issued
//! for a real chip) and a real 1,184-byte attestation report. The report was
//! produced by a rented confidential VM, not by us; see `tests/fixtures/snp/README.md`.

use omne_attest::snp::{self, Fail, Policy, Report, Tcb, POLICY_DEBUG, REPORT_LEN, SIGNED_LEN};

const REPORT: &[u8] = include_bytes!("fixtures/snp/attestation.bin");
const VCEK: &[u8] = include_bytes!("fixtures/snp/kds_vcek.der");
const ASK: &[u8] = include_bytes!("fixtures/snp/milan_ask.der");
const ARK: &[u8] = include_bytes!("fixtures/snp/milan_ark.der");

/// The pinned AMD Milan root, SHA-256 of its DER. Anyone can regenerate this:
/// `sha256sum` the ARK downloaded from AMD's KDS.
const ARK_SHA256: [u8; 32] = [
    0x69, 0xd0, 0x63, 0xb4, 0x53, 0x44, 0xd2, 0x6a, 0x2e, 0x94, 0xe1, 0xf4, 0x21, 0x0d, 0xe4, 0x9e,
    0xf5, 0x55, 0x30, 0x82, 0x87, 0xd4, 0xc1, 0x74, 0x44, 0x5c, 0x95, 0x63, 0x9a, 0x54, 0x0b, 0xcd,
];

/// A copy of the fixture with one byte replaced, so a leg can be failed in
/// isolation without disturbing the others.
fn mutated(at: usize, xor: u8) -> Vec<u8> {
    let mut b = REPORT.to_vec();
    b[at] ^= xor;
    b
}

fn parsed() -> Report {
    Report::parse(REPORT).expect("the fixture parses")
}

/// A policy that accepts the fixture exactly as it is, so each negative test
/// can move one thing and nothing else.
fn permissive(r: &Report) -> Policy {
    Policy {
        measurement: Some(r.measurement),
        report_data: Some(r.report_data),
        tcb_floor: Some(r.reported_tcb),
        max_vmpl: r.vmpl,
        reject_debug: false,
    }
}

// ---------------------------------------------------------------- the happy path

#[test]
fn the_real_report_verifies_end_to_end_against_amds_chain() {
    let r = parsed();
    let out = snp::verify(REPORT, VCEK, ASK, ARK, &ARK_SHA256, &permissive(&r))
        .expect("a real AMD report, a real AMD chain, a pinned real AMD root");
    assert_eq!(out.measurement, r.measurement);
    assert_eq!(out.chip_id, r.chip_id);
}

#[test]
fn the_pinned_root_is_the_ark_we_ship() {
    use sha2::Digest;
    let d: [u8; 32] = sha2::Sha256::digest(ARK).into();
    assert_eq!(
        d, ARK_SHA256,
        "the pin in this test must be the ARK fixture's own hash"
    );
}

#[test]
fn parse_reads_the_fields_at_the_abi_offsets() {
    let r = parsed();
    assert!((2..=5).contains(&r.version));
    assert_eq!(r.signature_algo, 1, "1 = ECDSA P-384 with SHA-384");
    assert_eq!(r.report_data.len(), 64);
    assert_eq!(r.measurement.len(), 48);
    assert_eq!(r.chip_id.len(), 64);
    // the signed prefix is a strict prefix: the signature lives after it
    assert_eq!(SIGNED_LEN, 0x2A0);
    assert_eq!(REPORT_LEN, 0x4A0);
}

// ------------------------------------------------------------------ parse legs

#[test]
fn a_report_of_the_wrong_length_fails_by_length() {
    assert_eq!(
        Report::parse(&REPORT[..REPORT_LEN - 1]).unwrap_err(),
        Fail::Length(REPORT_LEN - 1)
    );
    let mut long = REPORT.to_vec();
    long.push(0);
    assert_eq!(
        Report::parse(&long).unwrap_err(),
        Fail::Length(REPORT_LEN + 1)
    );
    assert_eq!(Report::parse(&[]).unwrap_err(), Fail::Length(0));
}

#[test]
fn an_unsupported_version_fails_by_version_not_by_signature() {
    for v in [0u32, 1, 6, 99] {
        let mut b = REPORT.to_vec();
        b[0..4].copy_from_slice(&v.to_le_bytes());
        assert_eq!(Report::parse(&b).unwrap_err(), Fail::Version(v));
    }
}

#[test]
fn every_supported_version_still_parses() {
    for v in 2u32..=5 {
        let mut b = REPORT.to_vec();
        b[0..4].copy_from_slice(&v.to_le_bytes());
        assert!(
            Report::parse(&b).is_ok(),
            "version {v} is in the supported range"
        );
    }
}

#[test]
fn an_unknown_signature_algorithm_is_refused_before_any_crypto() {
    for algo in [0u32, 2, 7] {
        let mut b = REPORT.to_vec();
        b[0x34..0x38].copy_from_slice(&algo.to_le_bytes());
        assert_eq!(Report::parse(&b).unwrap_err(), Fail::SignatureAlgo(algo));
    }
}

// -------------------------------------------------------------- signature legs

#[test]
fn a_single_flipped_bit_in_the_signed_region_fails_the_report_signature() {
    // one bit, in the middle of the measurement
    let b = mutated(0x90, 0x01);
    let r = Report::parse(&b).unwrap();
    assert_eq!(r.verify_signature(VCEK).unwrap_err(), Fail::ReportSignature);
}

#[test]
fn a_tampered_signature_fails_the_report_signature() {
    let b = mutated(0x2A0, 0xFF); // first byte of r
    let r = Report::parse(&b).unwrap();
    assert_eq!(r.verify_signature(VCEK).unwrap_err(), Fail::ReportSignature);
}

#[test]
fn a_report_signed_by_some_other_key_does_not_verify_under_this_vcek() {
    // the ASK is an RSA certificate: it is not a P-384 verifying key at all
    let r = parsed();
    assert_eq!(r.verify_signature(ASK).unwrap_err(), Fail::VcekKeyType);
}

#[test]
fn a_malformed_certificate_fails_by_parse_and_says_so() {
    let r = parsed();
    match r.verify_signature(b"not a certificate").unwrap_err() {
        Fail::VcekParse(_) => {}
        other => panic!("expected VcekParse, got {other:?}"),
    }
}

// ------------------------------------------------------------------ chain legs

#[test]
fn an_unpinned_root_is_refused_before_the_chain_is_walked() {
    let mut wrong = ARK_SHA256;
    wrong[0] ^= 1;
    assert_eq!(
        snp::verify_chain(VCEK, ASK, ARK, &wrong).unwrap_err(),
        Fail::ArkNotPinned
    );
}

#[test]
fn a_root_that_is_not_self_signed_fails_at_the_ark() {
    use sha2::Digest;
    // pass the ASK where the ARK belongs, pinned to its own hash so the pin
    // check passes and the self-signature check is what fails
    let pin: [u8; 32] = sha2::Sha256::digest(ASK).into();
    assert_eq!(
        snp::verify_chain(VCEK, ASK, ASK, &pin).unwrap_err(),
        Fail::ChainSignature("ARK self-signature")
    );
}

#[test]
fn an_intermediate_not_issued_by_the_root_fails_at_the_ask() {
    // the VCEK is signed by the ASK, not by the ARK
    assert_eq!(
        snp::verify_chain(VCEK, VCEK, ARK, &ARK_SHA256).unwrap_err(),
        Fail::ChainSignature("ASK by ARK")
    );
}

#[test]
fn a_leaf_not_issued_by_the_intermediate_fails_at_the_vcek() {
    // the ASK is signed by the ARK, not by the ASK
    assert_eq!(
        snp::verify_chain(ASK, ASK, ARK, &ARK_SHA256).unwrap_err(),
        Fail::ChainSignature("VCEK by ASK")
    );
}

#[test]
fn garbage_in_the_chain_fails_by_parse() {
    match snp::verify_chain(VCEK, ASK, b"junk", &ARK_SHA256).unwrap_err() {
        Fail::ArkNotPinned => {} // the pin is checked first, and junk does not hash to it
        other => panic!("expected the pin to reject junk first, got {other:?}"),
    }
    use sha2::Digest;
    let pin: [u8; 32] = sha2::Sha256::digest(b"junk").into();
    match snp::verify_chain(VCEK, ASK, b"junk", &pin).unwrap_err() {
        Fail::VcekParse(_) => {}
        other => panic!("expected VcekParse, got {other:?}"),
    }
}

// ------------------------------------------------------- vcek-binding legs
// A valid signature from some *other* chip's key must not pass. These legs are
// exercised directly, because a mutated report would fail its own signature
// first — which is the correct order, and is asserted separately below.

#[test]
fn a_vcek_for_a_different_chip_is_refused() {
    let b = mutated(0x1A0, 0xFF); // first byte of CHIP_ID
    let r = Report::parse(&b).unwrap();
    assert_eq!(
        r.verify_vcek_binding(VCEK).unwrap_err(),
        Fail::ChipIdMismatch
    );
}

#[test]
fn a_vcek_issued_at_a_different_tcb_is_refused() {
    let b = mutated(0x180, 0xFF); // REPORTED_TCB boot-loader SPL
    let r = Report::parse(&b).unwrap();
    match r.verify_vcek_binding(VCEK).unwrap_err() {
        Fail::TcbMismatch { .. } => {}
        other => panic!("expected TcbMismatch, got {other:?}"),
    }
}

#[test]
fn a_certificate_without_amds_extensions_is_refused_by_name() {
    let r = parsed();
    match r.verify_vcek_binding(ASK).unwrap_err() {
        Fail::MissingExtension(oid) => assert!(oid.starts_with("1.3.6.1.4.1.3704.1.")),
        other => panic!("expected MissingExtension, got {other:?}"),
    }
}

#[test]
fn the_unmutated_report_binds_to_its_own_vcek() {
    parsed()
        .verify_vcek_binding(VCEK)
        .expect("the fixture's VCEK is the fixture's chip at its TCB");
}

// ----------------------------------------------------------------- policy legs

#[test]
fn a_different_image_is_refused_by_measurement() {
    let r = parsed();
    let mut p = permissive(&r);
    let mut m = r.measurement;
    m[0] ^= 1;
    p.measurement = Some(m);
    assert_eq!(r.check_policy(&p).unwrap_err(), Fail::Measurement);
}

#[test]
fn a_report_not_bound_to_this_nonce_is_refused_by_report_data() {
    let r = parsed();
    let mut p = permissive(&r);
    let mut d = r.report_data;
    d[0] ^= 1;
    p.report_data = Some(d);
    assert_eq!(r.check_policy(&p).unwrap_err(), Fail::ReportData);
}

#[test]
fn a_guest_above_the_accepted_privilege_level_is_refused() {
    let mut b = REPORT.to_vec();
    b[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // VMPL 1
    let r = Report::parse(&b).unwrap();
    let mut p = permissive(&r);
    p.max_vmpl = 0;
    assert_eq!(r.check_policy(&p).unwrap_err(), Fail::Vmpl(1));
}

#[test]
fn a_debug_enabled_guest_is_not_confidential_and_is_refused() {
    let mut b = REPORT.to_vec();
    let policy = u64::from_le_bytes(b[8..16].try_into().unwrap()) | POLICY_DEBUG;
    b[8..16].copy_from_slice(&policy.to_le_bytes());
    let r = Report::parse(&b).unwrap();
    let mut p = permissive(&r);
    p.reject_debug = true;
    assert_eq!(r.check_policy(&p).unwrap_err(), Fail::DebugEnabled);
    // and is accepted when the relying party says it does not care
    p.reject_debug = false;
    assert!(r.check_policy(&p).is_ok());
}

#[test]
fn a_platform_below_the_tcb_floor_is_refused_and_names_both_sides() {
    let r = parsed();
    let mut p = permissive(&r);
    let floor = Tcb {
        boot_loader: r.reported_tcb.boot_loader.saturating_add(1),
        ..r.reported_tcb
    };
    p.tcb_floor = Some(floor);
    match r.check_policy(&p).unwrap_err() {
        Fail::TcbBelowFloor { have, floor: f } => {
            assert_eq!(have, r.reported_tcb);
            assert_eq!(f, floor);
        }
        other => panic!("expected TcbBelowFloor, got {other:?}"),
    }
}

#[test]
fn tcb_meets_compares_every_component() {
    let base = Tcb {
        boot_loader: 5,
        tee: 5,
        snp: 5,
        microcode: 5,
    };
    assert!(base.meets(&base));
    assert!(base.meets(&Tcb {
        boot_loader: 4,
        tee: 4,
        snp: 4,
        microcode: 4
    }));
    for higher in [
        Tcb {
            boot_loader: 6,
            ..base
        },
        Tcb { tee: 6, ..base },
        Tcb { snp: 6, ..base },
        Tcb {
            microcode: 6,
            ..base
        },
    ] {
        assert!(
            !base.meets(&higher),
            "a single component below the floor must fail"
        );
    }
}

// ------------------------------------------------------------------- ordering

#[test]
fn the_first_failing_leg_is_the_one_reported() {
    let r = parsed();
    // a wrong root AND a wrong measurement: the chain is walked before policy,
    // so the caller learns about the root
    let mut p = permissive(&r);
    let mut m = r.measurement;
    m[0] ^= 1;
    p.measurement = Some(m);
    let mut wrong_pin = ARK_SHA256;
    wrong_pin[0] ^= 1;
    assert_eq!(
        snp::verify(REPORT, VCEK, ASK, ARK, &wrong_pin, &p).unwrap_err(),
        Fail::ArkNotPinned
    );

    // a malformed report is refused before any certificate is touched
    assert_eq!(
        snp::verify(&REPORT[..10], b"junk", b"junk", b"junk", &ARK_SHA256, &p).unwrap_err(),
        Fail::Length(10)
    );
}

// -------------------------------------------------------------- the error type

#[test]
fn every_failure_says_which_leg_failed_in_words() {
    use std::error::Error;
    let cases: Vec<Fail> = vec![
        Fail::Length(7),
        Fail::Version(9),
        Fail::SignatureAlgo(2),
        Fail::ReportSignature,
        Fail::VcekParse("bad tag".into()),
        Fail::VcekKeyType,
        Fail::ChainSignature("ASK by ARK"),
        Fail::ArkNotPinned,
        Fail::ChipIdMismatch,
        Fail::TcbMismatch {
            report: Tcb {
                boot_loader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            cert: Tcb {
                boot_loader: 2,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
        },
        Fail::Measurement,
        Fail::ReportData,
        Fail::Vmpl(2),
        Fail::DebugEnabled,
        Fail::TcbBelowFloor {
            have: Tcb {
                boot_loader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
            floor: Tcb {
                boot_loader: 3,
                tee: 1,
                snp: 1,
                microcode: 1,
            },
        },
        Fail::MissingExtension("1.3.6.1.4.1.3704.1.4"),
    ];
    for c in &cases {
        let msg = c.to_string();
        assert!(
            msg.len() > 12,
            "{c:?} produced an uninformative message: {msg:?}"
        );
        assert!(
            !msg.contains("Fail"),
            "{c:?} leaked the variant name instead of explaining"
        );
        let _: &dyn Error = c; // usable with ? and anyhow
    }
    assert_eq!(
        cases.len(),
        16,
        "one message asserted for every variant of Fail"
    );
}
