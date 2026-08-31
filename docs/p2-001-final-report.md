# P2-001 local acceptance report

Evidence captured on 2026-08-31 from one real Windows runtime:

- `TRIVY_VERSION`: `0.74.0`
- `TRIVY_RELEASE_URL`: `https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_windows-64bit.zip`
- `TRIVY_BINARY_CHECKSUM`: `sha256:4c532e1f28f53282dc364671e87381cd77760fa9cafab143f576449c2207cdd5` (extracted executable); release archive checksum `sha256:94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842`
- `ARTIFACT_REF`: `D:\Projects\mcp-evidence-producer-trivy\artifacts\requirements.txt`
- `ARTIFACT_SHA256`: `sha256:3689190d8460c3a48b04e6c81c4ad290187f622d32ceea5f4bee907e40957293`
- `TRIVY_DB_METADATA`: recorded in `out/evidence.json` (`DownloadedAt`, `UpdatedAt`, `NextUpdate`, schema version)
- `TRIVY_DB_SHA256`: `sha256:6bcd9c0b5055a7364350bfc664ad6a8733b3c3ef99e7fd65024bbad1beedbee1`
- `RAW_REPORT_SHA256`: `sha256:ee7892f68f3ae0f7441b58a3d283cb21ea44d790f4f630055c1ba8f14317117c`
- `EVIDENCE_SHA256`: `sha256:c852c671f7e86742c63a30838dbe481ddd647088d0c3973cb02341f49b6057c5`
- `RECEIPT_VERDICT`: `findings`
- `RECEIPT_SCAN_SCOPE`: `dependency-vulnerabilities`

The immutable consumer command used alpha.3 at `d404b38f0ac0303438b561fe7358b0eec487c962` with `--policy permissive`. `receipt_structure`, `artifact_binding`, and `evidence_binding` were all `pass`; admission was correctly `fail` because the real scanner reported findings.

## Acceptance

| Layer | Result |
|---|---|
| IMPLEMENTATION_ACCEPTANCE | YES |
| PRODUCER_EVIDENCE_ACCEPTANCE | YES |
| CONSUMER_ACCEPTANCE | YES |
| EXTERNAL_RUNTIME | PASS |
| P2_001_COMPLETE | NO — remote promotion and dogfood PR were not authorized/executed in this local phase |

`PRODUCER_FINAL_HEAD`: local working tree after fail-closed pinning (base commit `206bb5d`). `PRODUCER_CI_RUN`: not run. `DOGFOOD_USES_PRODUCER_SHA`: not set. `DOGFOOD_RUN`: not run. `UNRESOLVED_REVIEW_THREADS`: remote promotion and dogfood exact-head closure. `EXTERNAL_UNKNOWN`: remote repository/PR/CI and dogfood exact-head closure remain unknown.
