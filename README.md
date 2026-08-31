# MCP Evidence Producers — Trivy + OSV Incubation

Scanner-specific producers for `mcp-evidence-gate`.

The repository was created for the Trivy producer and still preserves that
implementation unchanged. P2-002B incubates a second, logically independent
OSV-Scanner producer here because the current automation environment cannot
create a separate GitHub repository. The OSV producer has its own adapter,
producer entry point, tests, pinned scanner binary, real runtime CI, and evidence
artifacts; a later repository split must preserve those immutable contracts.

Both producers map only dependency-vulnerability evidence to the pinned
`registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22` receipt profile.
They do not change the Core verifier, claim server safety, compose scanners,
implement OCI, provenance/custody enforcement, signatures, or PKI.

## Trivy

```powershell
python -m pytest -q
python -m src.producer --trivy .\vendor\trivy.exe --artifact .\artifacts\requirements.txt --out .\out
```

Trivy writes `trivy.raw.json`, `trivy.stderr.log`, `evidence.json`, and
`receipt.json`.

## OSV-Scanner

The OSV producer is pinned to OSV-Scanner `v2.5.1`. On Linux CI its release
binary is admitted only when its SHA-256 is
`f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be`.

```bash
python -m src.osv_producer \
  --osv ./osv-scanner \
  --artifact artifacts/requirements.txt \
  --out out-osv
```

OSV writes `osv.raw.json`, `osv.stderr.log`, `evidence.json`, and `receipt.json`.
The exact invocation uses `scan --format json -L <artifact>`. Scanner exit codes
`0` (packages found, no findings) and `1` (findings) are valid result states;
no-package/error states are fail-closed as inconclusive. The adapter requires
every reported source path to bind to the requested artifact, at least one
primary `lockfile` source, and consistency between the scanner exit code and raw
vulnerability data.

OSV vulnerability data is queried remotely. The evidence manifest therefore
records `scanner_database.snapshot = "unavailable"` instead of inventing an
immutable database/rule-set identity.

For both producers, `scan_scope` is `dependency-vulnerabilities`, the artifact
digest binds the exact scanned file, and `evidence_digest` binds the retained
producer evidence manifest. Admission remains the downstream gate's job.
