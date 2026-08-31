import json
from src.adapter import map_report


def test_clean_and_findings_are_deterministic():
    base = {"Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "python"}]}
    clean = map_report(base, artifact_ref="artifacts/requirements.txt", artifact_sha256="a" * 64, scanner_version="Version: 0.74.0", scanned_at="2026-08-31T00:00:00Z")
    assert clean["verdict"] == "clean"
    raw = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-TEST"}]}]}
    found = map_report(raw, artifact_ref="a", artifact_sha256="b" * 64, scanner_version="Version: 0.74.0", scanned_at="2026-08-31T00:00:00Z")
    assert found["verdict"] == "findings"


def test_malformed_report_is_rejected():
    try:
        map_report({}, artifact_ref="a", artifact_sha256="a" * 64, scanner_version="Version: 0.74.0")
    except ValueError as exc:
        assert str(exc) == "malformed_trivy_report"
    else:
        raise AssertionError("malformed report must not become clean")
