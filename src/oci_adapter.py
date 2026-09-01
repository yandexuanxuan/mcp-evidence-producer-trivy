from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .adapter import PROFILE, SCOPE


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _report_binds_exact_ref(raw: dict[str, Any], exact_ref: str, manifest_digest: str) -> bool:
    artifact_name = raw.get("ArtifactName")
    if artifact_name == exact_ref:
        return True
    metadata = raw.get("Metadata")
    if not isinstance(metadata, dict):
        return False
    repo_digests = metadata.get("RepoDigests")
    if not isinstance(repo_digests, list):
        return False
    expected_suffix = "@" + manifest_digest
    return any(isinstance(value, str) and (value == exact_ref or value.endswith(expected_suffix)) for value in repo_digests)


def map_image_report(
    raw: dict[str, Any],
    *,
    exact_ref: str,
    manifest_digest: str,
    scanner_version: str,
    scanned_at: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Map one Trivy image JSON report while preserving the resolved OCI manifest identity."""
    results = raw.get("Results")
    if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
        raise ValueError("malformed_trivy_image_report")
    trivy = raw.get("Trivy")
    if not isinstance(trivy, dict) or trivy.get("Version") != scanner_version:
        raise ValueError("trivy_version_mismatch")
    if not _report_binds_exact_ref(raw, exact_ref, manifest_digest):
        raise ValueError("oci_artifact_ref_mismatch")

    findings = 0
    for item in results:
        if not all(isinstance(item.get(key), str) and item.get(key) for key in ("Target", "Class", "Type")):
            raise ValueError("malformed_trivy_image_report")
        vulnerabilities = item.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ValueError("malformed_trivy_image_report")
        findings += len(vulnerabilities or [])

    receipt: dict[str, Any] = {
        "scanner": "trivy",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": exact_ref,
        "scanned_artifact_digest": manifest_digest,
        "scan_scope": [SCOPE],
        "verdict": "findings" if findings else "clean",
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    return receipt
