# Security

## Reporting

Email **security@omne.foundation**. Please do not open a public issue for
anything that would let an invalid attestation verify.

We will acknowledge within 72 hours and tell you what we intend to do and when.

## What a vulnerability is here

This crate's one job is to reject reports that should be rejected. The
security-relevant class is therefore **anything that makes `verify` return
`Ok` when it should return a `Fail`** — a chain that is not walked, an
extension that is not compared, a signature verified over the wrong bytes, a
policy field that is silently ignored.

Also in scope: a `Fail` that names the wrong leg, because a relying party may
act on it.

## What this crate does not protect against

- **Trusting the wrong root.** You supply the pinned ARK hash. If you pin the
  wrong root, everything below it verifies happily. Pin AMD's, and check the
  hash yourself.
- **A compromised AMD signing key**, or a hardware-level break of SEV-SNP.
  This crate verifies AMD's chain; it does not second-guess AMD.
- **The classical-algorithm horizon.** The chip signs with ECDSA-P384 and the
  chain is RSASSA-PSS — AMD's algorithms. A future quantum adversary could
  forge an enclave's identity. It could not retroactively decrypt a job: the
  job-key exchange in `claim` is ML-KEM-768.
