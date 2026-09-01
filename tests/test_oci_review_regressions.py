from __future__ import annotations

import json

from src.oci_identity import OCI_INDEX, OCI_MANIFEST, ManifestResponse, resolve_oci_identity, sha256_bytes
from src.oci_producer import run


def encoded(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def response(body: bytes, media_type: str) -> ManifestResponse:
    return ManifestResponse(body=body, content_type=media_type, docker_content_digest=sha256_bytes(body))


def test_index_platform_is_explicitly_descriptor_verified():
    manifest = encoded({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {}, "layers": []})
    digest = sha256_bytes(manifest)
    index = encoded({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [{
            "mediaType": OCI_MANIFEST,
            "digest": digest,
            "size": len(manifest),
            "platform": {"os": "linux", "architecture": "amd64"},
        }],
    })
    root = sha256_bytes(index)

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        if reference == root:
            return response(index, OCI_INDEX)
        if reference == digest:
            return response(manifest, OCI_MANIFEST)
        raise AssertionError(reference)

    resolved = resolve_oci_identity(
        f"ghcr.io/example/tool@{root}",
        os_name="linux",
        architecture="amd64",
        fetch_manifest=fetch,
    )
    selected = resolved.record["selected"]
    assert selected["platform"] == {"os": "linux", "architecture": "amd64"}
    assert selected["platform_verified"] is True
    assert selected["platform_source"] == "index-descriptor"


def test_direct_manifest_does_not_overclaim_platform_verification():
    manifest = encoded({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {}, "layers": []})
    digest = sha256_bytes(manifest)

    def fetch(_registry: str, _repository: str, reference: str) -> ManifestResponse:
        assert reference == digest
        return response(manifest, OCI_MANIFEST)

    resolved = resolve_oci_identity(
        f"ghcr.io/example/tool@{digest}",
        os_name="linux",
        architecture="amd64",
        fetch_manifest=fetch,
    )
    selected = resolved.record["selected"]
    assert selected["selection_source"] == "direct-manifest"
    assert selected["platform"] == {"os": "linux", "architecture": "amd64"}
    assert selected["platform_verified"] is False
    assert selected["platform_source"] == "caller-requested-unverified"


def test_real_producer_rejects_mutable_tag_before_scanner_or_network(tmp_path):
    out = tmp_path / "out"
    code = run(
        "/definitely/not/a/trivy/binary",
        "ghcr.io/example/tool:latest",
        out,
        os_name="linux",
        architecture="amd64",
    )
    assert code == 1
    error = json.loads((out / "oci-error.json").read_text(encoding="utf-8"))
    assert error["error"] == "mutable_oci_reference_rejected"
