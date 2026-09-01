from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .oci_adapter import map_image_report
from .oci_identity import OciIdentityError, RegistryClient, parse_reference, resolve_oci_identity
from .producer import (
    PINNED_TRIVY_SHA256,
    PINNED_TRIVY_VERSION,
    PRODUCER_VERSION,
    database_metadata,
    sha256,
    trivy_version,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fail(out: Path, code: str, detail: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "oci-error.json", {"error": code, "detail": detail})
    return 1


def run(
    binary: str,
    image: str,
    out: Path,
    *,
    os_name: str,
    architecture: str,
    variant: str | None = None,
) -> int:
    out.mkdir(parents=True, exist_ok=True)

    try:
        requested = parse_reference(image)
    except OciIdentityError as exc:
        return _fail(out, "oci_reference_invalid", str(exc))
    if requested.reference_kind != "digest":
        return _fail(out, "mutable_oci_reference_rejected", "real OCI producer requires an @sha256 digest reference")

    expected_binary_hash = PINNED_TRIVY_SHA256.get(sys.platform)
    try:
        binary_hash = sha256(Path(binary))
    except OSError as exc:
        return _fail(out, "trivy_binary_unavailable", str(exc))
    if expected_binary_hash is None or binary_hash != expected_binary_hash:
        return _fail(out, "trivy_binary_digest_mismatch", binary_hash)
    try:
        version = trivy_version(binary)
    except (OSError, subprocess.CalledProcessError) as exc:
        return _fail(out, "trivy_version_unavailable", str(exc))
    if version != PINNED_TRIVY_VERSION:
        return _fail(out, "trivy_version_mismatch", version)

    client = RegistryClient()
    try:
        resolved = resolve_oci_identity(
            image,
            os_name=os_name,
            architecture=architecture,
            variant=variant,
            fetch_manifest=client.fetch_manifest,
        )
    except OciIdentityError as exc:
        return _fail(out, "oci_identity_resolution_failed", str(exc))

    identity_path = out / "oci-identity.json"
    manifest_path = out / "oci.manifest.json"
    index_path = out / "oci.index.json"
    _write_json(identity_path, resolved.record)
    manifest_path.write_bytes(resolved.manifest_body)
    if resolved.root_body != resolved.manifest_body:
        index_path.write_bytes(resolved.root_body)

    selected = resolved.record["selected"]
    if not isinstance(selected, dict):
        return _fail(out, "oci_identity_internal_error", "selected identity is not an object")
    exact_ref = selected.get("exact_ref")
    manifest_digest = selected.get("manifest_digest")
    if not isinstance(exact_ref, str) or not isinstance(manifest_digest, str):
        return _fail(out, "oci_identity_internal_error", "selected identity fields missing")
    if "sha256:" + sha256(manifest_path) != manifest_digest:
        return _fail(out, "oci_manifest_persistence_mismatch", manifest_digest)

    raw_path = out / "trivy.raw.json"
    stderr_path = out / "trivy.stderr.log"
    started = utc_now()
    argv = [
        binary,
        "image",
        "--format",
        "json",
        "--output",
        str(raw_path),
        "--scanners",
        "vuln",
        "--exit-code",
        "0",
        exact_ref,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True)
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    completed = utc_now()

    try:
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = None
    if proc.returncode != 0 or not isinstance(raw, dict):
        return _fail(out, "trivy_image_scan_failed", f"exit={proc.returncode}")

    evidence: dict[str, Any] = {
        "schema_version": "project-defined-evidence-manifest-v1",
        "artifact": {
            "kind": "oci-image-manifest",
            "requested_ref": image,
            "exact_ref": exact_ref,
            "sha256": manifest_digest.removeprefix("sha256:"),
            "manifest_path": str(manifest_path),
            "manifest_size": manifest_path.stat().st_size,
            "identity_path": str(identity_path),
            "identity_sha256": sha256(identity_path),
            "root_digest": resolved.record["root"]["digest"],
            "platform": selected["platform"],
        },
        "scanner": {
            "name": "trivy",
            "version": version,
            "binary_sha256": binary_hash,
        },
        "scanner_database": database_metadata(),
        "invocation": {
            "argv": argv,
            "started_at": started,
            "completed_at": completed,
            "exit_code": proc.returncode,
            "target_exact_ref": exact_ref,
        },
        "raw_report": {
            "path": str(raw_path),
            "sha256": sha256(raw_path),
        },
        "producer": {
            "name": "mcp-evidence-producer-trivy",
            "version": PRODUCER_VERSION,
            "mode": "oci-image",
        },
    }
    if index_path.exists():
        evidence["artifact"]["index_path"] = str(index_path)
        evidence["artifact"]["index_sha256"] = sha256(index_path)

    evidence_path = out / "evidence.json"
    _write_json(evidence_path, evidence)
    try:
        receipt = map_image_report(
            raw,
            exact_ref=exact_ref,
            manifest_digest=manifest_digest,
            scanner_version=version,
            scanned_at=completed,
            evidence_digest="sha256:" + sha256(evidence_path),
        )
    except ValueError as exc:
        return _fail(out, "trivy_image_report_binding_failed", str(exc))

    _write_json(out / "receipt.json", receipt)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform-os", required=True)
    parser.add_argument("--platform-arch", required=True)
    parser.add_argument("--platform-variant")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return run(
        args.trivy,
        args.image,
        args.out,
        os_name=args.platform_os,
        architecture=args.platform_arch,
        variant=args.platform_variant,
    )


if __name__ == "__main__":
    raise SystemExit(main())
