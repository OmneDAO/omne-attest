//! AMD SEV-SNP attestation reports — parse + verify (CC-0).
//!
//! The report is the 1,184-byte `ATTESTATION_REPORT` of the SEV-SNP ABI
//! (versions 2-5; real AMD silicon reports v5). Its first 0x2A0 bytes are signed (ECDSA P-384 / SHA-384) by
//! the chip's **VCEK** — a per-chip, per-TCB key whose certificate AMD's Key
//! Distribution Service issues, chained VCEK ← ASK ← ARK (RSASSA-PSS,
//! SHA-384, 4096-bit). Verifying a report therefore means:
//!
//!   1. parse the fixed layout (bespoke — it is a format, not a mechanism);
//!   2. ECDSA-P384 verify report[..0x2A0] under the VCEK's public key;
//!   3. verify the chain VCEK ← ASK ← ARK against a pinned ARK;
//!   4. check the VCEK is the right one for this report: its hwID extension
//!      equals the report's CHIP_ID and its TCB-component extensions equal
//!      the report's REPORTED_TCB (otherwise a valid signature from some
//!      other chip's key would pass);
//!   5. apply the relying party's policy: expected measurement, report_data
//!      binding (the buyer's nonce ‖ key), TCB floors, VMPL, debug bit.
//!
//! Cryptography is the standardized primitives as standardized (RustCrypto
//! `p384`, `rsa`, `sha2`); X.509 is parsed by `x509-cert`. What this module
//! does NOT decide: whether to trust AMD (A-TEE, assumed) — it pins the ARK
//! the caller supplies and says exactly which check failed.
//!
//! On post-quantum: ECDSA-P384 and RSA-PSS are AMD's algorithms — the chip
//! signs with them and we VERIFY them; Omne's own signing is ML-DSA and the
//! CC-1 key exchange is ML-KEM. The residual is forward-looking enclave
//! impersonation once a quantum adversary exists (A-TEE-classical,
//! confidential-compute §2d), never retroactive decryption of a job. This
//! module is the only place a vendor algorithm is touched; a PQ-signed
//! report format is an added arm here, not a rewrite elsewhere.
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha384};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

pub const REPORT_LEN: usize = 0x4A0;
pub const SIGNED_LEN: usize = 0x2A0;

/// AMD VCEK certificate extension OIDs (VCEK Certificate and KDS Interface
/// Specification): the TCB component SPLs and the hardware id.
pub const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
pub const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
pub const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
pub const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";
pub const OID_HW_ID: &str = "1.3.6.1.4.1.3704.1.4";

/// A TCB_VERSION: byte 0 boot loader, byte 1 TEE, byte 6 SNP firmware, byte 7 microcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tcb {
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl Tcb {
    fn from_u64_le(raw: [u8; 8]) -> Self {
        Tcb {
            boot_loader: raw[0],
            tee: raw[1],
            snp: raw[6],
            microcode: raw[7],
        }
    }
    /// Every component at or above the floor.
    pub fn meets(&self, floor: &Tcb) -> bool {
        self.boot_loader >= floor.boot_loader
            && self.tee >= floor.tee
            && self.snp >= floor.snp
            && self.microcode >= floor.microcode
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: Tcb,
    pub platform_info: u64,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub reported_tcb: Tcb,
    pub chip_id: [u8; 64],
    pub committed_tcb: Tcb,
    pub launch_tcb: Tcb,
    /// r ‖ s, each 72 bytes little-endian in the ABI (P-384 uses 48).
    pub sig_r: [u8; 48],
    pub sig_s: [u8; 48],
    raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    Length(usize),
    Version(u32),
    SignatureAlgo(u32),
    ReportSignature,
    VcekParse(String),
    VcekKeyType,
    ChainSignature(&'static str),
    ArkNotPinned,
    ChipIdMismatch,
    TcbMismatch { report: Tcb, cert: Tcb },
    Measurement,
    ReportData,
    Vmpl(u32),
    DebugEnabled,
    TcbBelowFloor { have: Tcb, floor: Tcb },
    MissingExtension(&'static str),
}

impl core::fmt::Display for Fail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Fail::Length(n) => write!(f, "attestation report is {n} bytes, expected {REPORT_LEN}"),
            Fail::Version(v) => write!(f, "unsupported report version {v} (supported: 2..=5)"),
            Fail::SignatureAlgo(a) => write!(
                f,
                "unsupported signature algorithm {a} (1 = ECDSA P-384/SHA-384)"
            ),
            Fail::ReportSignature => {
                write!(f, "the report's signature does not verify under the VCEK")
            }
            Fail::VcekParse(e) => write!(f, "certificate does not parse: {e}"),
            Fail::VcekKeyType => write!(f, "the VCEK's public key is not a P-384 key"),
            Fail::ChainSignature(leg) => write!(f, "certificate chain broken at: {leg}"),
            Fail::ArkNotPinned => write!(f, "the supplied root does not match the pinned ARK hash"),
            Fail::ChipIdMismatch => {
                write!(f, "the VCEK belongs to a different chip than the report")
            }
            Fail::TcbMismatch { report, cert } => {
                write!(f, "the VCEK was issued at a different TCB than the report claims (report {report:?}, cert {cert:?})")
            }
            Fail::Measurement => write!(f, "launch measurement is not the expected image"),
            Fail::ReportData => write!(
                f,
                "report_data is not bound to the expected rental, nonce and key"
            ),
            Fail::Vmpl(v) => write!(f, "guest is at VMPL {v}, above the accepted level"),
            Fail::DebugEnabled => {
                write!(f, "the guest policy allows debug: it is not confidential")
            }
            Fail::TcbBelowFloor { have, floor } => {
                write!(
                    f,
                    "platform TCB {have:?} is below the required floor {floor:?}"
                )
            }
            Fail::MissingExtension(oid) => {
                write!(f, "the VCEK is missing required AMD extension {oid}")
            }
        }
    }
}

impl std::error::Error for Fail {}

/// Debug bit in the guest policy (bit 19): a debug-enabled guest is not confidential.
pub const POLICY_DEBUG: u64 = 1 << 19;

impl Report {
    pub fn parse(b: &[u8]) -> Result<Report, Fail> {
        if b.len() != REPORT_LEN {
            return Err(Fail::Length(b.len()));
        }
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let arr8 = |o: usize| -> [u8; 8] { b[o..o + 8].try_into().unwrap() };
        let version = u32_at(0);
        // v2..=5: the signed region (first 0x2A0) and every field we read
        // (report_data, measurement, chip_id, reported_tcb, policy) sit at
        // stable offsets across these versions — newer versions added data in
        // previously-reserved bytes. The SIGNATURE over [0..0x2A0] is the real
        // gate; a wrong offset would fail it. GCP's real silicon reports v5.
        if !(2..=5).contains(&version) {
            return Err(Fail::Version(version));
        }
        let signature_algo = u32_at(0x34);
        if signature_algo != 1 {
            return Err(Fail::SignatureAlgo(signature_algo)); // 1 = ECDSA P-384 with SHA-384
        }
        // r and s are little-endian 72-byte fields; P-384 scalars are 48 bytes
        let mut sig_r = [0u8; 48];
        let mut sig_s = [0u8; 48];
        let r_le = &b[0x2A0..0x2A0 + 48];
        let s_le = &b[0x2E8..0x2E8 + 48];
        for i in 0..48 {
            sig_r[i] = r_le[47 - i];
            sig_s[i] = s_le[47 - i];
        }
        Ok(Report {
            version,
            guest_svn: u32_at(4),
            policy: u64_at(8),
            family_id: b[0x10..0x20].try_into().unwrap(),
            image_id: b[0x20..0x30].try_into().unwrap(),
            vmpl: u32_at(0x30),
            signature_algo,
            current_tcb: Tcb::from_u64_le(arr8(0x38)),
            platform_info: u64_at(0x40),
            report_data: b[0x50..0x90].try_into().unwrap(),
            measurement: b[0x90..0xC0].try_into().unwrap(),
            host_data: b[0xC0..0xE0].try_into().unwrap(),
            id_key_digest: b[0xE0..0x110].try_into().unwrap(),
            author_key_digest: b[0x110..0x140].try_into().unwrap(),
            report_id: b[0x140..0x160].try_into().unwrap(),
            reported_tcb: Tcb::from_u64_le(arr8(0x180)),
            chip_id: b[0x1A0..0x1E0].try_into().unwrap(),
            committed_tcb: Tcb::from_u64_le(arr8(0x1E0)),
            launch_tcb: Tcb::from_u64_le(arr8(0x1F0)),
            sig_r,
            sig_s,
            raw: b.to_vec(),
        })
    }

    /// Step 2: the report's own signature under the VCEK public key (DER cert).
    pub fn verify_signature(&self, vcek_der: &[u8]) -> Result<(), Fail> {
        let cert = Certificate::from_der(vcek_der).map_err(|e| Fail::VcekParse(e.to_string()))?;
        let spki = cert.tbs_certificate.subject_public_key_info;
        let pk_bytes = spki.subject_public_key.raw_bytes();
        let vk =
            p384::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|_| Fail::VcekKeyType)?;
        let mut sig_bytes = [0u8; 96];
        sig_bytes[..48].copy_from_slice(&self.sig_r);
        sig_bytes[48..].copy_from_slice(&self.sig_s);
        let sig =
            p384::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Fail::ReportSignature)?;
        let digest = Sha384::digest(&self.raw[..SIGNED_LEN]);
        vk.verify_prehash(&digest, &sig)
            .map_err(|_| Fail::ReportSignature)
    }

    /// Step 4: the VCEK must be THIS chip's key at THIS TCB.
    pub fn verify_vcek_binding(&self, vcek_der: &[u8]) -> Result<(), Fail> {
        let cert = Certificate::from_der(vcek_der).map_err(|e| Fail::VcekParse(e.to_string()))?;
        let ext = |oid: &'static str| -> Result<Vec<u8>, Fail> {
            let want: x509_cert::spki::ObjectIdentifier = oid.parse().unwrap();
            cert.tbs_certificate
                .extensions
                .as_ref()
                .and_then(|es| es.iter().find(|e| e.extn_id == want))
                .map(|e| e.extn_value.as_bytes().to_vec())
                .ok_or(Fail::MissingExtension(oid))
        };
        // hwID: OCTET STRING (DER) holding the 64-byte chip id
        let hw = ext(OID_HW_ID)?;
        let hw_bytes = der_octet_or_raw(&hw);
        if hw_bytes != self.chip_id {
            return Err(Fail::ChipIdMismatch);
        }
        // SPLs: DER INTEGERs
        let spl = |oid: &'static str| -> Result<u8, Fail> { Ok(der_int_u8(&ext(oid)?)) };
        let cert_tcb = Tcb {
            boot_loader: spl(OID_BL_SPL)?,
            tee: spl(OID_TEE_SPL)?,
            snp: spl(OID_SNP_SPL)?,
            microcode: spl(OID_UCODE_SPL)?,
        };
        if cert_tcb != self.reported_tcb {
            return Err(Fail::TcbMismatch {
                report: self.reported_tcb,
                cert: cert_tcb,
            });
        }
        Ok(())
    }
}

fn der_octet_or_raw(v: &[u8]) -> Vec<u8> {
    // an extension value is DER: 0x04 len bytes (short or long form)
    if v.first() == Some(&0x04) {
        if let Ok(os) = x509_cert::der::asn1::OctetString::from_der(v) {
            return os.as_bytes().to_vec();
        }
    }
    v.to_vec()
}

fn der_int_u8(v: &[u8]) -> u8 {
    // 0x02 len value...: take the last byte (SPLs are < 256)
    if v.first() == Some(&0x02) && v.len() >= 3 {
        return v[v.len() - 1];
    }
    *v.last().unwrap_or(&0)
}

/// Step 3: VCEK ← ASK ← ARK, ARK pinned by SHA-256 of its DER. RSASSA-PSS/SHA-384.
pub fn verify_chain(
    vcek_der: &[u8],
    ask_der: &[u8],
    ark_der: &[u8],
    pinned_ark_sha256: &[u8; 32],
) -> Result<(), Fail> {
    if <[u8; 32]>::from(sha2::Sha256::digest(ark_der)) != *pinned_ark_sha256 {
        return Err(Fail::ArkNotPinned);
    }
    let ark = Certificate::from_der(ark_der).map_err(|e| Fail::VcekParse(e.to_string()))?;
    let ask = Certificate::from_der(ask_der).map_err(|e| Fail::VcekParse(e.to_string()))?;
    let vcek = Certificate::from_der(vcek_der).map_err(|e| Fail::VcekParse(e.to_string()))?;
    rsa_pss_verify_cert(&ark, &ark).map_err(|_| Fail::ChainSignature("ARK self-signature"))?;
    rsa_pss_verify_cert(&ask, &ark).map_err(|_| Fail::ChainSignature("ASK by ARK"))?;
    rsa_pss_verify_cert(&vcek, &ask).map_err(|_| Fail::ChainSignature("VCEK by ASK"))?;
    Ok(())
}

fn rsa_pss_verify_cert(subject: &Certificate, issuer: &Certificate) -> Result<(), ()> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let pk =
        rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes()).map_err(|_| ())?;
    // rsa's PSS wants its own digest-crate generation; use the Sha384 it re-exports
    let vk: VerifyingKey<rsa::sha2::Sha384> = VerifyingKey::new_with_salt_len(pk, 48);
    let tbs = subject.tbs_certificate.to_der().map_err(|_| ())?;
    let sig = Signature::try_from(subject.signature.raw_bytes()).map_err(|_| ())?;
    vk.verify(&tbs, &sig).map_err(|_| ())
}

/// The relying party's policy — what a buyer accepts.
#[derive(Debug, Clone)]
pub struct Policy {
    pub measurement: Option<[u8; 48]>,
    pub report_data: Option<[u8; 64]>,
    pub tcb_floor: Option<Tcb>,
    pub max_vmpl: u32,
    pub reject_debug: bool,
}

impl Report {
    pub fn check_policy(&self, p: &Policy) -> Result<(), Fail> {
        if let Some(m) = p.measurement {
            if m != self.measurement {
                return Err(Fail::Measurement);
            }
        }
        if let Some(d) = p.report_data {
            if d != self.report_data {
                return Err(Fail::ReportData);
            }
        }
        if self.vmpl > p.max_vmpl {
            return Err(Fail::Vmpl(self.vmpl));
        }
        if p.reject_debug && self.policy & POLICY_DEBUG != 0 {
            return Err(Fail::DebugEnabled);
        }
        if let Some(floor) = p.tcb_floor {
            if !self.reported_tcb.meets(&floor) {
                return Err(Fail::TcbBelowFloor {
                    have: self.reported_tcb,
                    floor,
                });
            }
        }
        Ok(())
    }
}

/// The whole verification, in order, first failure named.
pub fn verify(
    report: &[u8],
    vcek_der: &[u8],
    ask_der: &[u8],
    ark_der: &[u8],
    pinned_ark_sha256: &[u8; 32],
    policy: &Policy,
) -> Result<Report, Fail> {
    let r = Report::parse(report)?;
    r.verify_signature(vcek_der)?;
    verify_chain(vcek_der, ask_der, ark_der, pinned_ark_sha256)?;
    r.verify_vcek_binding(vcek_der)?;
    r.check_policy(policy)?;
    Ok(r)
}
