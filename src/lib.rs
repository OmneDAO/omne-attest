//! **Verify an AMD SEV-SNP attestation report against AMD's own key chain —
//! locally, with no oracle and nothing to trust but the root you pin.**
//!
//! This crate is the attestation layer of [Omne](https://omne.foundation), a
//! foundation-level substrate that can be built on. It is published on its own
//! because it is useful on its own: if you rent a confidential VM from anyone,
//! this tells you whether the thing that answered you is really a SEV-SNP
//! enclave running the image you expected.
//!
//! Two layers:
//!
//! - [`snp`] — the report itself. Parse the 1,184-byte `ATTESTATION_REPORT`,
//!   verify its ECDSA-P384 signature under the chip's VCEK, verify
//!   VCEK ← ASK ← ARK against a **pinned** root, check the VCEK really is
//!   this chip's key at this TCB, then apply the relying party's policy.
//!   Every failure is a named variant of [`snp::Fail`] — you are told which
//!   leg failed, never just "invalid".
//!
//! - [`claim`] — the *attested claim*: a report bound to a specific rental, a
//!   specific buyer nonce, and a specific ML-KEM-768 encapsulation key, so a
//!   buyer can send a job key to an enclave it has just verified and to
//!   nothing else. Replay of an old report is refused at the binding leg.
//!
//! ## What this crate does not decide
//!
//! Whether to trust AMD. It pins the root **you** supply and reports exactly
//! which check failed. The chip's own signature is ECDSA-P384 and the chain
//! is RSASSA-PSS — those are AMD's algorithms, not ours; Omne's own
//! signatures are ML-DSA and the job-key exchange here is ML-KEM-768.
//!
//! ## Example
//!
//! ```no_run
//! use omne_attest::{claim, snp};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (bytes, rental, nonce, expected_measurement, ark_pin) =
//! #     (vec![], [0u8; 32], [0u8; 32], [0u8; 48], [0u8; 32]);
//! let c = claim::AttestedClaim::decode(&bytes).ok_or("malformed claim")?;
//! let policy = claim::BuyerPolicy {
//!     measurement: expected_measurement,
//!     tcb_floor: snp::Tcb { boot_loader: 0, tee: 0, snp: 0, microcode: 0 },
//!     ark_sha256: ark_pin,
//!     reject_debug: true,
//! };
//! let verified = claim::verify(&c, &rental, &nonce, &policy)?;
//! let (ciphertext, job_key) = claim::encapsulate_job_key(&verified.ek)?;
//! # Ok(()) }
//! ```

pub mod claim;
pub mod snp;
