# omne-attest

**Verify an AMD SEV-SNP attestation report against AMD's own key chain —
locally, with no oracle, and nothing to trust but the root you pin yourself.**

[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

If you rent a confidential VM from anyone, the question you actually want
answered is: *is the thing that just replied to me really an SEV-SNP enclave,
running the image I expected, on a genuine AMD chip — and is this answer fresh,
or a replay?* This crate answers that, and when the answer is no it tells you
**which check failed**.

It is the attestation layer of [Omne](https://omne.foundation). It is published
separately because it is useful separately: nothing here depends on Omne's
network, and you can check every claim it makes against AMD's published
material without taking our word for anything.

## What it does

**`snp` — the report.** Parse the 1,184-byte `ATTESTATION_REPORT` (ABI versions
2–5), then, in order:

1. verify the report's ECDSA-P384/SHA-384 signature over its signed prefix,
   under the chip's VCEK;
2. verify the certificate chain **VCEK ← ASK ← ARK** (RSASSA-PSS/SHA-384)
   against a root you pin by SHA-256;
3. verify the VCEK is *this chip's* key at *this TCB* — its `hwID` extension
   must equal the report's `CHIP_ID`, and its four TCB-component extensions
   must equal the report's `REPORTED_TCB`. **Without this step a valid
   signature from some other chip's key would pass;**
4. apply your policy: expected measurement, expected `report_data`, TCB floor,
   maximum VMPL, and whether a debug-enabled guest is acceptable.

**`claim` — the attested claim.** A report is only useful if it is *about* the
exchange you are having. `claim` binds one to a rental id, a fresh nonce and an
ML-KEM-768 encapsulation key:

```
report_data = SHA-512( "omne:attested-claim:v1" ‖ rental ‖ nonce ‖ ek )
```

So a buyer verifies the enclave and then encapsulates a job key **to that
enclave and no other**. An old report replayed against a new nonce fails at the
binding leg, by name.

## Use

```toml
[dependencies]
omne-attest = "0.1"
```

```rust
use omne_attest::{claim, snp};

let c = claim::AttestedClaim::decode(&bytes).ok_or("malformed claim")?;

let policy = claim::BuyerPolicy {
    measurement: expected_measurement, // the image you asked for
    tcb_floor,                         // the platform level you accept
    ark_sha256: ark_pin,               // AMD's root, pinned by you
    reject_debug: true,
};

let verified = claim::verify(&c, &rental, &nonce, &policy)?;
let (ciphertext, job_key) = claim::encapsulate_job_key(&verified.ek)?;
```

Every rejection is a named [`snp::Fail`]: `ArkNotPinned`, `ChipIdMismatch`,
`TcbMismatch`, `ReportSignature`, `ChainSignature("ASK by ARK")`, `Measurement`,
`ReportData`, `DebugEnabled`, `TcbBelowFloor`, and the rest. `Fail` implements
`Display` and `std::error::Error`, so `?` and `anyhow` work as you would expect.

## Python

The same verifier is published for Python, as
[`omne-attest` on PyPI](https://pypi.org/project/omne-attest/):

```
pip install omne-attest
```

It is a port, not a binding — no Rust toolchain needed — and it is held to the
**same vectors** this crate asserts on. Both suites read the same four files,
and a test fails if the two copies ever diverge. Source lives in
[`python/`](python/), which has its own README.

The Rust crate is the reference implementation. One difference is worth
knowing: AMD's KDS issues VCEK certificates with serial number `0`, which
RFC 5280 forbids. This crate's X.509 parser does not care; Python's
`cryptography` currently warns and has said it will reject them in a future
release. `python/README.md` names it and a test guards it.

## What it deliberately does not do

- **Decide whether to trust AMD.** You supply the pinned root. Pin the wrong
  one and everything under it verifies happily — so hash AMD's ARK yourself.
- **Fetch certificates.** No network calls. You bring the VCEK, ASK and ARK;
  this crate does not decide where they came from.
- **Second-guess the hardware.** A break of SEV-SNP itself is out of scope.

On post-quantum: the chip signs with ECDSA-P384 and the chain is RSASSA-PSS —
those are **AMD's** algorithms, which we verify rather than choose. The
job-key exchange in `claim` is ML-KEM-768, so a future quantum adversary could
forge an enclave identity but could not retroactively decrypt a job.

## Testing

```
cargo test    # 33 tests
```

The fixtures are real: AMD's Milan ARK and ASK from AMD's Key Distribution
Service, a VCEK issued for a real chip, and a real attestation report produced
by a rented confidential VM (provenance in `tests/fixtures/snp/README.md`).

`tests/snp_legs.rs` has **one negative test per failure mode**, each built by
mutating that real fixture in exactly one place — a wrong root, a leaf not
issued by the intermediate, a VCEK for a different chip, a VCEK issued at a
different TCB, a single flipped bit in the signed region, a debug-enabled
guest, a platform below the floor. The module's promise is that it tells you
which leg failed; those tests are what make the promise checkable.

The pinned Milan ARK used in the tests:

```
69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd
```

Download the ARK from AMD's KDS and hash it. The point of a pin is that you do
not take ours on trust.

## Contributing

`cargo test` and `cargo clippy --all-targets` are clean; please keep them that
way, and add a negative test for any check you add. Commits are signed off
under the [DCO](CONTRIBUTING.md) — there is no CLA, deliberately.

## Licence

Apache-2.0, including its patent grant. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
