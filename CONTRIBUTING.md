# Contributing

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by:` line:

```
git commit -s -m "your message"
```

That line is your assertion of the [Developer Certificate of
Origin](https://developercertificate.org/) — that you wrote the contribution,
or have the right to submit it under this project's licence.

**There is no CLA, and there will not be one.** A contributor licence
agreement would let this project be relicensed later; we would rather be
unable to do that. The licence is Apache-2.0 and the practical consequence of
distributed copyright is that it stays that way.

## What a good change looks like here

This crate verifies other people's cryptography. Two rules follow:

1. **A failure must say which leg failed.** Every path that can reject a report
   returns a named [`snp::Fail`] variant, never a bare `false` or a generic
   error. If you add a check, add a variant and a message.
2. **A new check needs a negative test.** `tests/snp_legs.rs` has one test per
   failure mode, built by mutating a real fixture in exactly one place. Follow
   that shape — a check with no test that exercises its failure is a check that
   might not run.

Run `cargo test` and `cargo clippy --all-targets` before opening a pull
request. Both are clean today; please keep them that way.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a
verification bypass.
