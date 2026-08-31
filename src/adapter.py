from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

SCOPE = "dependency-vulnerabilities"
PROFILE = "registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def map_report(raw: dict[str, Any], *, artifact_ref: str, artifact_sha256: str,
               scanner_version: str, scanned_at: str | None = None,
               evidence_digest: str | None = None, rule_set_ref: str | None = None) -> dict[str, Any]:
    """Map one parsed Trivy fs JSON report without changing scanner semantics."""
    reports = raw.get("Results")
    if not isinstance(reports, list):
        raise ValueError("malformed_trivy_report")
    trivy = raw.get("Trivy")
    if not isinstance(trivy, dict) or not isinstance(trivy.get("Version"), str):
        raise ValueError("malformed_trivy_report")
    if trivy["Version"] != scanner_version:
        raise ValueError("trivy_version_mismatch")
    if not isinstance(raw.get("ArtifactName"), str) or not raw["ArtifactName"]:
        raise ValueError("malformed_trivy_report")
    if Path(raw["ArtifactName"]).resolve() != Path(artifact_ref).resolve():
        raise ValueError("artifact_ref_mismatch")
    if any(not isinstance(item, dict) for item in reports):
        raise ValueError("malformed_trivy_report")
    findings = 0
    for item in reports:
        if not all(isinstance(item.get(k), str) and item.get(k) for k in ("Target", "Class", "Type")):
            raise ValueError("malformed_trivy_report")
        vulnerabilities = item.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ValueError("malformed_trivy_report")
        findings += len(vulnerabilities or [])
    receipt: dict[str, Any] = {
        "scanner": "trivy",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": artifact_ref,
        "scanned_artifact_digest": f"sha256:{artifact_sha256}",
        "scan_scope": [SCOPE],
        "verdict": "findings" if findings else "clean",
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    if rule_set_ref:
        receipt["rule_set_ref"] = rule_set_ref
    return receipt


def inconclusive_receipt(*, artifact_ref: str, artifact_sha256: str, scanner_version: str,
                         reason: str = "evidence_unavailable", scanned_at: str | None = None) -> dict[str, Any]:
    return {
        "scanner": "trivy", "scanner_version": scanner_version,
        "scanned_artifact_ref": artifact_ref,
        "scanned_artifact_digest": f"sha256:{artifact_sha256}",
        "scan_scope": [SCOPE], "verdict": "inconclusive",
        "inconclusive_reason": reason, "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted", "policy_profile": PROFILE,
    }
