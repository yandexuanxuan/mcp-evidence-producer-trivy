# MCP Evidence Producer — Trivy

Independent scanner-specific adapter for `mcp-evidence-gate`.

This project runs a pinned Trivy release against one exact dependency artifact,
preserves the raw JSON report, and maps the result to the pinned
`registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22` receipt profile.
It does not change the Core verifier, claim server safety, or implement OCI,
provenance, signatures, or a multi-scanner framework.

## Local usage

```powershell
python -m pytest -q
python -m src.producer --trivy .\vendor\trivy.exe --artifact .\artifacts\requirements.txt --out .\out
```

The producer writes `trivy.raw.json`, `trivy.stderr.log`, `evidence.json`, and
`receipt.json`. `scan_scope` is `dependency-vulnerabilities`; `verdict` is
derived only from the raw Trivy report and execution outcome.
