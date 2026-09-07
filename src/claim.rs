//! CC-1 — the ATTESTED CLAIM (confidential-compute-2026-08-29.md §2b), in
//! code: what a slice host inside a confidential VM returns at claim, what a
//! buyer checks, and how the buyer's job key reaches the enclave.
//!
//!   buyer → slice : rental id, a fresh 32-byte nonce n              (1)
//!   slice → buyer : report R, ML-KEM encapsulation key ek, chain     (2)
//!                   with R.report_data = H(ctx ‖ rental ‖ n ‖ ek)
//!   buyer         : verifies chain, measurement, binding, TCB, policy (3)
//!   buyer → slice : ct = Encaps(ek) → job key K; job encrypted under K (4)
//!
//! The KEM is ML-KEM-768 (FIPS 203) — the post-quantum peer of the ML-DSA
//! identities; the report's own signature is the vendor's (A-TEE-classical,
//! §2d). `Attester` is the hardware seam: `SnpGuest` asks the SEV-SNP guest
//! driver for a report on Linux; tests use a stub. What no test here can do
//! is produce a fresh REAL report for a chosen nonce — that needs a rented
//! confidential VM and is the one CC-1 leg still owed.
use crate::snp::{self, Fail, Policy, Report};
use crypto_common::{Key, KeyExport};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use sha2::{Digest, Sha512};

pub const CLAIM_CTX: &[u8] = b"omne:attested-claim:v1";
/// ML-KEM-768 encapsulation key length (FIPS 203 §8).
pub const EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const CT_LEN: usize = 1088;

/// `report_data` (64 bytes) = SHA-512(ctx ‖ rental ‖ nonce ‖ ek): binds the
/// report to THIS rental, THIS buyer's freshness, and THIS enclave key.
pub fn binding(rental: &[u8; 32], nonce: &[u8; 32], ek: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(CLAIM_CTX);
    h.update(rental);
    h.update(nonce);
    h.update(ek);
    h.finalize().into()
}

/// The slice's answer to an attested claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedClaim {
    pub report: Vec<u8>,
    pub ek: Vec<u8>,
    pub vcek: Vec<u8>,
    pub ask: Vec<u8>,
    pub ark: Vec<u8>,
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}
fn take<'a>(b: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let n = u32::from_be_bytes(b.get(*at..*at + 4)?.try_into().ok()?) as usize;
    let v = b.get(*at + 4..*at + 4 + n)?;
    *at += 4 + n;
    Some(v)
}

impl AttestedClaim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in [&self.report, &self.ek, &self.vcek, &self.ask, &self.ark] {
            put(&mut out, f);
        }
        out
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut at = 0;
        let report = take(b, &mut at)?.to_vec();
        let ek = take(b, &mut at)?.to_vec();
        let vcek = take(b, &mut at)?.to_vec();
        let ask = take(b, &mut at)?.to_vec();
        let ark = take(b, &mut at)?.to_vec();
        (at == b.len()).then_some(AttestedClaim {
            report,
            ek,
            vcek,
            ask,
            ark,
        })
    }
}

/// The hardware seam: produce an attestation report whose user data is
/// `report_data`. Implemented by the SEV-SNP guest driver on a CVM.
pub trait Attester {
    fn report(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String>;
}

/// `/dev/sev-guest` on a SEV-SNP confidential VM (Linux ≥ 5.19). The ioctl
/// is SNP_GET_REPORT: a request with our 64 bytes of user data and VMPL 0;
/// the response carries a 32-byte message header before the 1,184-byte
/// report. Anything else is an error string, never a fake report.
pub struct SnpGuest;

impl Attester for SnpGuest {
    #[cfg(target_os = "linux")]
    fn report(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        use std::os::unix::io::AsRawFd;
        #[repr(C)]
        struct Req {
            user_data: [u8; 64],
            vmpl: u32,
            rsvd: [u8; 28],
        }
        #[repr(C)]
        struct Resp {
            data: [u8; 4000],
        }
        #[repr(C)]
        struct Ioctl {
            msg_version: u8,
            req_data: u64,
            resp_data: u64,
            exitinfo2: u64,
        }
        const SNP_GET_REPORT: u64 = 0xC020_5300; // _IOWR('S', 0x0, struct snp_guest_request_ioctl)
        unsafe extern "C" {
            fn ioctl(fd: i32, req: u64, ...) -> i32;
        }
        let dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev-guest")
            .map_err(|e| format!("/dev/sev-guest: {e} (not a SEV-SNP guest?)"))?;
        let req = Req {
            user_data: report_data,
            vmpl: 0,
            rsvd: [0; 28],
        };
        let mut resp = Resp { data: [0; 4000] };
        let mut arg = Ioctl {
            msg_version: 1,
            req_data: &req as *const Req as u64,
            resp_data: &mut resp as *mut Resp as u64,
            exitinfo2: 0,
        };
        // SAFETY: the pointers are to live, correctly sized, repr(C) structs for the duration of the call
        let rc = unsafe { ioctl(dev.as_raw_fd(), SNP_GET_REPORT, &mut arg as *mut Ioctl) };
        if rc != 0 {
            return Err(format!(
                "SNP_GET_REPORT failed: rc={rc} exitinfo2={:#x}",
                arg.exitinfo2
            ));
        }
        let status = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(resp.data[4..8].try_into().unwrap()) as usize;
        if status != 0 || size != snp::REPORT_LEN {
            return Err(format!("SNP_GET_REPORT: status={status} size={size}"));
        }
        Ok(resp.data[32..32 + snp::REPORT_LEN].to_vec())
    }
    #[cfg(not(target_os = "linux"))]
    fn report(&self, _report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        Err("SEV-SNP guest reports exist only on Linux confidential VMs".into())
    }
}

/// The slice's side (2): a fresh ML-KEM keypair inside the enclave, a report
/// bound to it, the chain the buyer will verify. Returns the decapsulation
/// key, which never leaves this process.
pub fn respond(
    attester: &dyn Attester,
    rental: &[u8; 32],
    nonce: &[u8; 32],
    chain: (&[u8], &[u8], &[u8]),
) -> Result<(AttestedClaim, DecapsulationKey<MlKem768>), String> {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes().to_vec();
    let report = attester.report(binding(rental, nonce, &ek_bytes))?;
    Ok((
        AttestedClaim {
            report,
            ek: ek_bytes,
            vcek: chain.0.to_vec(),
            ask: chain.1.to_vec(),
            ark: chain.2.to_vec(),
        },
        dk,
    ))
}

/// What a buyer accepts beyond the binding: the image, the platform floor, the root.
#[derive(Debug, Clone)]
pub struct BuyerPolicy {
    pub measurement: [u8; 48],
    pub tcb_floor: snp::Tcb,
    pub ark_sha256: [u8; 32],
    pub reject_debug: bool,
}

/// A claim the buyer has verified: the enclave key it may encapsulate to.
#[derive(Debug, Clone)]
pub struct VerifiedSlice {
    pub report: Report,
    pub ek: Vec<u8>,
}

/// The buyer's side (3): every leg of `snp::verify`, with `report_data`
/// REQUIRED to equal the binding over this rental, this nonce, this ek.
pub fn verify(
    claim: &AttestedClaim,
    rental: &[u8; 32],
    nonce: &[u8; 32],
    policy: &BuyerPolicy,
) -> Result<VerifiedSlice, Fail> {
    if claim.ek.len() != EK_LEN {
        return Err(Fail::ReportData);
    }
    let p = Policy {
        measurement: Some(policy.measurement),
        report_data: Some(binding(rental, nonce, &claim.ek)),
        tcb_floor: Some(policy.tcb_floor),
        max_vmpl: 0,
        reject_debug: policy.reject_debug,
    };
    let report = snp::verify(
        &claim.report,
        &claim.vcek,
        &claim.ask,
        &claim.ark,
        &policy.ark_sha256,
        &p,
    )?;
    Ok(VerifiedSlice {
        report,
        ek: claim.ek.clone(),
    })
}

/// The buyer's side (4): encapsulate a job key to the verified enclave key.
/// Returns (ciphertext for the slice, the 32-byte shared key).
pub fn encapsulate_job_key(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let key = Key::<EncapsulationKey<MlKem768>>::try_from(ek_bytes).map_err(|_| "bad ek length")?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| "invalid ek")?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.to_vec(), ss.into()))
}

/// The slice's side (4): recover the job key.
pub fn decapsulate_job_key(dk: &DecapsulationKey<MlKem768>, ct: &[u8]) -> Result<[u8; 32], String> {
    let ss = dk
        .decapsulate_slice(ct)
        .map_err(|_| "bad ciphertext length")?;
    Ok(ss.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stub that returns a real (fixed) report — its report_data is NOT our
    /// binding, which is exactly what the buyer must catch.
    struct FixtureAttester;
    impl Attester for FixtureAttester {
        fn report(&self, _rd: [u8; 64]) -> Result<Vec<u8>, String> {
            Ok(include_bytes!("../tests/fixtures/snp/attestation.bin").to_vec())
        }
    }
    const VCEK: &[u8] = include_bytes!("../tests/fixtures/snp/kds_vcek.der");
    const ASK: &[u8] = include_bytes!("../tests/fixtures/snp/milan_ask.der");
    const ARK: &[u8] = include_bytes!("../tests/fixtures/snp/milan_ark.der");

    fn ark_pin() -> [u8; 32] {
        sha2::Sha256::digest(ARK).into()
    }

    #[test]
    fn the_job_key_round_trips_through_ml_kem() {
        let (claim, dk) = respond(&FixtureAttester, &[1; 32], &[2; 32], (VCEK, ASK, ARK)).unwrap();
        assert_eq!(claim.ek.len(), EK_LEN);
        let (ct, k_buyer) = encapsulate_job_key(&claim.ek).unwrap();
        assert_eq!(ct.len(), CT_LEN);
        let k_slice = decapsulate_job_key(&dk, &ct).unwrap();
        assert_eq!(k_buyer, k_slice);
        assert!(decapsulate_job_key(&dk, &ct[..CT_LEN - 1]).is_err());
    }

    #[test]
    fn the_claim_encodes_and_decodes() {
        let (claim, _) = respond(&FixtureAttester, &[1; 32], &[2; 32], (VCEK, ASK, ARK)).unwrap();
        let back = AttestedClaim::decode(&claim.encode()).unwrap();
        assert_eq!(back, claim);
        assert!(AttestedClaim::decode(&claim.encode()[..100]).is_none());
    }

    #[test]
    fn a_report_not_bound_to_this_rental_and_nonce_is_refused_at_the_binding_leg() {
        // every leg before the binding passes on the real fixture (chain, chip,
        // TCB); the binding cannot, because no CVM produced this report for us
        let (claim, _) = respond(&FixtureAttester, &[1; 32], &[2; 32], (VCEK, ASK, ARK)).unwrap();
        let r = Report::parse(&claim.report).unwrap();
        let policy = BuyerPolicy {
            measurement: r.measurement,
            tcb_floor: r.reported_tcb,
            ark_sha256: ark_pin(),
            reject_debug: false,
        };
        assert_eq!(
            verify(&claim, &[1; 32], &[2; 32], &policy).err(),
            Some(Fail::ReportData)
        );
        // a wrong root fails before anything else
        let mut bad = policy.clone();
        bad.ark_sha256[0] ^= 1;
        assert_eq!(
            verify(&claim, &[1; 32], &[2; 32], &bad).err(),
            Some(Fail::ArkNotPinned)
        );
    }

    #[test]
    fn binding_changes_with_every_input() {
        let a = binding(&[1; 32], &[2; 32], &[3; 8]);
        assert_ne!(a, binding(&[9; 32], &[2; 32], &[3; 8]));
        assert_ne!(a, binding(&[1; 32], &[9; 32], &[3; 8]));
        assert_ne!(a, binding(&[1; 32], &[2; 32], &[9; 8]));
    }
}
