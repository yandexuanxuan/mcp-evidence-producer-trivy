from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCOPE = "dependency-vulnerabilities"
PROFILE = "registry-pr-1404@20747d3253ba8638161dd95f1cec70df02993c22"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def map_report(
    raw: dict[str, Any],
    *,
    artifact_ref: str,
    artifact_sha256: str,
    scanner_version: str,
    scanner_exit_code: int,
    scanned_at: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Map one OSV-Scanner v2 JSON lockfile result without changing scanner semantics."""
    results = raw.get("results")
    if not isinstance(results, list):
        raise ValueError("malformed_osv_report")

    expected_artifact = Path(artifact_ref).resolve()
    saw_artifact_source = False
    package_count = 0
    finding_count = 0

    for result in results:
        if not isinstance(result, dict):
            raise ValueError("malformed_osv_report")

        source = result.get("source")
        if not isinstance(source, dict):
            raise ValueError("malformed_osv_report")
        source_path = source.get("path")
        source_type = source.get("type")
        if not isinstance(source_path, str) or not source_path:
            raise ValueError("malformed_osv_report")
        if source_type != "lockfile":
            raise ValueError("unexpected_osv_source_type")
        if Path(source_path).resolve() != expected_artifact:
            raise ValueError("artifact_ref_mismatch")
        saw_artifact_source = True

        packages = result.get("packages")
        if not isinstance(packages, list):
            raise ValueError("malformed_osv_report")
        for entry in packages:
            if not isinstance(entry, dict):
                raise ValueError("malformed_osv_report")
            package = entry.get("package")
            if not isinstance(package, dict):
                raise ValueError("malformed_osv_report")
            if not all(isinstance(package.get(key), str) and package.get(key) for key in ("name", "version", "ecosystem")):
                raise ValueError("malformed_osv_report")
            package_count += 1

            vulnerabilities = entry.get("vulnerabilities", [])
            if vulnerabilities is None:
                vulnerabilities = []
            if not isinstance(vulnerabilities, list):
                raise ValueError("malformed_osv_report")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("malformed_osv_report")
                if not isinstance(vulnerability.get("id"), str) or not vulnerability["id"]:
                    raise ValueError("malformed_osv_report")
                finding_count += 1

    if not saw_artifact_source or package_count == 0:
        # OSV-Scanner reserves exit 128 for no packages. A 0/1 report that does
        # not bind at least one parsed package to the requested lockfile is not
        # admissible as evidence of a clean/findings verdict.
        raise ValueError("osv_no_packages_in_report")

    if scanner_exit_code not in (0, 1):
        raise ValueError("unexpected_osv_exit_code")
    if scanner_exit_code == 0 and finding_count != 0:
        raise ValueError("osv_exit_verdict_mismatch")
    if scanner_exit_code == 1 and finding_count == 0:
        raise ValueError("osv_exit_verdict_mismatch")

    receipt: dict[str, Any] = {
        "scanner": "osv-scanner",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": artifact_ref,
        "scanned_artifact_digest": f"sha256:{artifact_sha256}",
        "scan_scope": [SCOPE],
        "verdict": "findings" if finding_count else "clean",
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
    if evidence_digest:
        receipt["evidence_digest"] = evidence_digest
    return receipt


def inconclusive_receipt(
    *,
    artifact_ref: str,
    artifact_sha256: str,
    scanner_version: str,
    reason: str = "evidence_unavailable",
    scanned_at: str | None = None,
) -> dict[str, Any]:
    return {
        "scanner": "osv-scanner",
        "scanner_version": scanner_version,
        "scanned_artifact_ref": artifact_ref,
        "scanned_artifact_digest": f"sha256:{artifact_sha256}",
        "scan_scope": [SCOPE],
        "verdict": "inconclusive",
        "inconclusive_reason": reason,
        "scanned_at": scanned_at or _now(),
        "attestation": "publisher-asserted",
        "policy_profile": PROFILE,
    }
