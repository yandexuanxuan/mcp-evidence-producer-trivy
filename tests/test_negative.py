from src.adapter import inconclusive_receipt, map_report


def test_malformed_raw_report_never_becomes_clean():
    try:
        map_report({"Results": "not-a-list"}, artifact_ref="a", artifact_sha256="a" * 64, scanner_version="0.74.0")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed raw report must fail closed")


def test_incomplete_result_never_becomes_clean():
    try:
        map_report({"Trivy": {"Version": "0.74.0"}, "ArtifactName": "a", "Results": [{}]}, artifact_ref="a", artifact_sha256="a" * 64, scanner_version="0.74.0")
    except ValueError:
        pass
    else:
        raise AssertionError("incomplete result must fail closed")


def test_malformed_result_element_never_becomes_clean():
    try:
        map_report({"Results": ["corrupt"]}, artifact_ref="a", artifact_sha256="a" * 64, scanner_version="0.74.0")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed result element must fail closed")


def test_execution_failure_is_inconclusive():
    receipt = inconclusive_receipt(artifact_ref="a", artifact_sha256="b" * 64, scanner_version="unavailable")
    assert receipt["verdict"] == "inconclusive"
    assert receipt["inconclusive_reason"] == "evidence_unavailable"
