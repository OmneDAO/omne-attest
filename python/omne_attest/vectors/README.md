# Fixtures

| file | what it is | where it came from |
|---|---|---|
| `attestation.bin` | a real 1,184-byte SEV-SNP `ATTESTATION_REPORT` | produced by a **rented** confidential VM on AMD Milan silicon — not our hardware. It carries that machine's `CHIP_ID` and launch measurement, which is what makes it usable as a test vector |
| `kds_vcek.der` | the VCEK certificate for that chip at that TCB | AMD's Key Distribution Service |
| `milan_ask.der` | AMD's Milan ASK (intermediate) | AMD KDS |
| `milan_ark.der` | AMD's Milan ARK (root) | AMD KDS |
| `milan_cert_chain.pem`, `milan.testcer`, `vcek.testcer` | the same material in other encodings | AMD KDS |

The ARK is pinned in the tests by SHA-256 of its DER:

```
69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd
```

Regenerate it yourself — download the Milan ARK from AMD's KDS and hash it. The
point of a pin is that you do not take ours on trust.

## One thing to know about the report

The guest that produced it was launched with the **debug bit set** (guest
policy `0x0b0000`, bit 19). Every cryptographic leg verifies; a *policy* with
`reject_debug` will — correctly — refuse it, because a debug-enabled guest can
be inspected by its host. That is a property of the rented VM we could capture
a report from, not of the verifier. Tests that need the vector to pass end to
end set a permissive policy and say so.
