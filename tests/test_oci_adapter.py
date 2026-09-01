from __future__ import annotations

import pytest

from src.oci_adapter import map_image_report

DIGEST = "sha256:" + "a" * 64
EXACT_REF = f"ghcr.io/example/tool@{DIGEST}"


def raw_report(*, artifact_name: str = EXACT_REF, repo_digests=None, findings: int = 0):
    vulnerabilities = [{"VulnerabilityID": f"CVE-2026-{i:04d}"} for i in range(findings)]
    return {
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": artifact_name,
        "ArtifactType": "container_image",
        "Metadata": {"RepoDigests": repo_digests or []},
        "Results": [
            {
                "Target": "example (debian 12)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": vulnerabilities,
            }
        ],
    }


def test_exact_artifact_name_binds_manifest_digest():
    receipt = map_image_report(
        raw_report(),
        exact_ref=EXACT_REF,
        manifest_digest=DIGEST,
        scanner_version="0.74.0",
        scanned_at="2026-09-01T00:00:00Z",
    )
    assert receipt["scanned_artifact_ref"] == EXACT_REF
    assert receipt["scanned_artifact_digest"] == DIGEST
    assert receipt["verdict"] == "clean"


def test_repo_digest_can_prove_identity_when_artifact_name_is_normalized():
    receipt = map_image_report(
        raw_report(artifact_name="ghcr.io/example/tool:stable", repo_digests=[EXACT_REF], findings=1),
        exact_ref=EXACT_REF,
        manifest_digest=DIGEST,
        scanner_version="0.74.0",
    )
    assert receipt["verdict"] == "findings"


def test_report_without_exact_digest_binding_is_rejected():
    with pytest.raises(ValueError, match="oci_artifact_ref_mismatch"):
        map_image_report(
            raw_report(artifact_name="ghcr.io/example/tool:stable", repo_digests=[]),
            exact_ref=EXACT_REF,
            manifest_digest=DIGEST,
            scanner_version="0.74.0",
        )


def test_scanner_version_mismatch_is_rejected():
    raw = raw_report()
    raw["Trivy"]["Version"] = "0.73.0"
    with pytest.raises(ValueError, match="trivy_version_mismatch"):
        map_image_report(
            raw,
            exact_ref=EXACT_REF,
            manifest_digest=DIGEST,
            scanner_version="0.74.0",
        )
