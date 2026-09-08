# omne-attest (Python)

Verify an AMD SEV-SNP attestation report: parse it, check its signature,
walk AMD's key chain to a root you pin yourself, confirm the key really
belongs to the chip that produced the report, and apply your policy.

This is the Python half of [`omne-attest`](https://crates.io/crates/omne-attest).
The Rust crate is the reference implementation; this package is a port held to
the **same vectors** — AMD's real Milan chain and a real 1,184-byte attestation
report captured from confidential silicon. Both suites assert on the same
bytes, and a test fails if the two copies ever diverge.

Apache-2.0, patent grant included. Source: <https://github.com/OmneDAO/omne-attest>

## Install

```
pip install omne-attest
```

## Use

```python
from omne_attest import Policy, vectors, verify

# the vectors ship with the package, so this runs with nothing else set up
report = verify(
    vectors.attestation(),
    vectors.vcek(), vectors.ask(), vectors.ark(),
    vectors.ARK_SHA256,
    Policy(max_vmpl=0, reject_debug=False),   # see "the shipped report allows debug"
)
print(report.measurement.hex())
```

With your own report and chain, the only thing that changes is where the bytes
come from — and the policy, which is where you say what you actually accept:

```python
Policy(
    measurement=expected_launch_measurement,  # the image you expect
    report_data=expected_binding,             # your nonce and key, bound in
    tcb_floor=Tcb(boot_loader=3, tee=0, snp=20, microcode=209),
    max_vmpl=0,
    reject_debug=True,
)
```

## The shipped report allows debug

Set `reject_debug=True` on the example above and it fails:

```
Fail: the guest policy allows debug: it is not confidential
```

That is correct, and it is worth seeing. The reference report came from a
**rented** confidential VM whose launch policy has the debug bit (19) set —
guest policy `0x0b0000`. A guest that permits debug can be inspected by the
host, so it is not sealed against the machine's owner, and a production policy
should refuse it. The report is genuine and every cryptographic leg verifies;
what fails is the last leg, policy, which is exactly the leg that is supposed
to catch this.

Use `reject_debug=True` for anything real. The permissive flag here only lets
the shipped vector through so the example runs.

## What a failure tells you

Every leg has a named failure, and the **first** one to fail is the one you
hear about — so a broken verification says which check broke, not just "no".

```python
from omne_attest import Fail, FailKind

try:
    verify(...)
except Fail as f:
    f.kind    # FailKind.CHAIN_SIGNATURE
    str(f)    # "certificate chain broken at: ASK by ARK"
```

The legs, in the order they run: report length and version, signature
algorithm, the report's ECDSA-P384 signature under the VCEK, the chain
VCEK ← ASK ← ARK against your pinned root, the VCEK's binding to this chip
and TCB, then your policy.

## What it does not decide

**Whether to trust AMD.** It pins the root *you* supply. `vectors.ARK_SHA256`
is the SHA-256 of AMD's Milan ARK, and you should regenerate it rather than
take ours: download the ARK from AMD's KDS and hash it. That is the point of a
pin.

It also does not fetch anything. No network calls — you supply the report and
the certificates.

## Known risk: AMD's VCEK serial number

AMD's KDS issues VCEK certificates with **serial number 0**, which RFC 5280
forbids. `cryptography` currently loads them with a deprecation warning and
has stated it will raise instead in a future release. If that lands before
this package works around it, verification of real VCEKs will fail to parse.

This is tracked by a test named for the failure
(`test_amds_vcek_still_loads_despite_its_serial_number_of_zero`), so the suite
breaks loudly and explains itself rather than the library failing on hardware.
The Rust crate is unaffected — its X.509 parser does not enforce this.

## Post-quantum

ECDSA-P384 and RSA-PSS are AMD's algorithms: the chip signs with them and this
package *verifies* them. Omne's own signing is ML-DSA. The residual is
forward-looking enclave impersonation once a quantum adversary exists, never
retroactive decryption of a job.

## Tests

The tests ship in the source distribution, not the wheel, so run them from a
checkout:

```
git clone https://github.com/OmneDAO/omne-attest
cd omne-attest/python
pip install -e '.[test]'
pytest
```

32 tests: the happy path against AMD's real chain, one negative per failure
mode, and the vector-parity check against the Rust crate.
