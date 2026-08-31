# Claim–Evidence Matrix

| Claim | Evidence in this project |
| --- | --- |
| Scanner input is exact artifact bytes | `artifacts/requirements.txt`, producer SHA-256, and the same path in `trivy fs` argv |
| Receipt reflects raw Trivy result | frozen adapter tests plus `out/trivy.raw.json` and `out/receipt.json` |
| Evidence is byte-bound | `out/evidence.json` SHA-256 is copied into `receipt.evidence_digest`; Core consumer check passes |
| Scanner failure cannot silently become clean | missing binary, non-zero invocation, malformed report map to `inconclusive`/non-zero; adapter regression tests |
| Real consumer can ingest producer output | alpha.3 CLI reports artifact/evidence binding `pass`; scanner `findings` correctly yields admission `fail` |
| External runtime completed | pinned Trivy 0.74.0 binary, official checksum, DB metadata, invocation stderr, and raw report |
