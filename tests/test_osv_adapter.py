from __future__ import annotations

from pathlib import Path

import pytest

from src.osv_adapter import map_report


def raw_report(path: str, vulnerabilities: list[dict] | None = None) -> dict:
    return {
        "results": [
            {
                "source": {"path": path, "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.31.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": vulnerabilities or [],
                    }
                ],
            }
        ]
    }


def test_clean_exit_maps_clean(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    receipt = map_report(
        raw_report(str(artifact)),
        artifact_ref=str(artifact),
        artifact_sha256="a" * 64,
        scanner_version="2.5.1",
        scanner_exit_code=0,
        scanned_at="2026-09-01T00:00:00Z",
        evidence_digest=f"sha256:{'b' * 64}",
    )
    assert receipt["scanner"] == "osv-scanner"
    assert receipt["verdict"] == "clean"
    assert receipt["scan_scope"] == ["dependency-vulnerabilities"]
    assert receipt["evidence_digest"] == f"sha256:{'b' * 64}"


def test_findings_exit_maps_findings(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    receipt = map_report(
        raw_report(str(artifact), [{"id": "GHSA-example-1234"}]),
        artifact_ref=str(artifact),
        artifact_sha256="a" * 64,
        scanner_version="2.5.1",
        scanner_exit_code=1,
    )
    assert receipt["verdict"] == "findings"


@pytest.mark.parametrize(
    ("exit_code", "vulns"),
    [(0, [{"id": "GHSA-example-1234"}]), (1, [])],
)
def test_exit_code_and_json_verdict_must_agree(tmp_path: Path, exit_code: int, vulns: list[dict]) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="osv_exit_verdict_mismatch"):
        map_report(
            raw_report(str(artifact), vulns),
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=exit_code,
        )


def test_report_must_bind_source_to_requested_lockfile(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    other = tmp_path / "other.txt"
    with pytest.raises(ValueError, match="artifact_ref_mismatch"):
        map_report(
            raw_report(str(other)),
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )


def test_empty_results_cannot_be_clean(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="osv_no_packages_in_report"):
        map_report(
            {"results": []},
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )


def test_non_lockfile_source_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "requirements.txt"
    artifact.write_text("requests==2.31.0\n", encoding="utf-8")
    raw = raw_report(str(artifact))
    raw["results"][0]["source"]["type"] = "git"
    with pytest.raises(ValueError, match="unexpected_osv_source_type"):
        map_report(
            raw,
            artifact_ref=str(artifact),
            artifact_sha256="a" * 64,
            scanner_version="2.5.1",
            scanner_exit_code=0,
        )
