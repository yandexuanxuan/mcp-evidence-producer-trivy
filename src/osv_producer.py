from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .osv_adapter import inconclusive_receipt, map_report

PRODUCER_VERSION = "0.1.0"
PINNED_OSV_VERSION = "2.5.1"
PINNED_OSV_SHA256 = {
    "linux": "f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _platform_key() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def osv_version(binary: str) -> str:
    proc = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True)
    text = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)", text)
    if not match:
        raise ValueError("unparseable_osv_version")
    return match.group(1)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_receipt(out: Path, receipt: dict[str, Any]) -> None:
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(binary: str, artifact: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    raw_path = out / "osv.raw.json"
    stderr_path = out / "osv.stderr.log"
    artifact_hash = sha256(artifact)

    try:
        binary_hash = sha256(Path(binary))
    except OSError:
        binary_hash = None
    expected_binary_hash = PINNED_OSV_SHA256.get(_platform_key())
    if expected_binary_hash is None or binary_hash != expected_binary_hash:
        _write_receipt(
            out,
            inconclusive_receipt(
                artifact_ref=str(artifact),
                artifact_sha256=artifact_hash,
                scanner_version="unverified",
                reason="evidence_unavailable",
            ),
        )
        return 1

    try:
        version = osv_version(binary)
    except (OSError, subprocess.CalledProcessError, ValueError):
        _write_receipt(
            out,
            inconclusive_receipt(
                artifact_ref=str(artifact),
                artifact_sha256=artifact_hash,
                scanner_version="unavailable",
            ),
        )
        return 1
    if version != PINNED_OSV_VERSION:
        _write_receipt(
            out,
            inconclusive_receipt(
                artifact_ref=str(artifact),
                artifact_sha256=artifact_hash,
                scanner_version=version,
                reason="evidence_unavailable",
            ),
        )
        return 1

    started = _now()
    argv = [binary, "scan", "--format", "json", "-L", str(artifact)]
    proc = subprocess.run(argv, capture_output=True, text=True)
    completed = _now()
    raw_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")

    raw: dict[str, Any] | None = None
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, dict):
            raw = parsed
    except json.JSONDecodeError:
        pass

    if proc.returncode not in (0, 1) or raw is None:
        _write_receipt(
            out,
            inconclusive_receipt(
                artifact_ref=str(artifact),
                artifact_sha256=artifact_hash,
                scanner_version=version,
                reason="evidence_unavailable",
            ),
        )
        return 1

    evidence = {
        "schema_version": "project-defined-evidence-manifest-v1",
        "artifact": {
            "ref": str(artifact),
            "sha256": artifact_hash,
            "size": artifact.stat().st_size,
        },
        "scanner": {
            "name": "osv-scanner",
            "version": version,
            "binary_sha256": binary_hash,
        },
        "scanner_database": {
            "source": "https://osv.dev",
            "mode": "remote-query",
            "snapshot": "unavailable",
        },
        "invocation": {
            "argv": argv,
            "started_at": started,
            "completed_at": completed,
            "exit_code": proc.returncode,
        },
        "raw_report": {
            "path": str(raw_path),
            "sha256": sha256(raw_path),
        },
        "producer": {
            "name": "mcp-evidence-producer-osv",
            "version": PRODUCER_VERSION,
            "repository": "yandexuanxuan/mcp-evidence-producer-trivy",
        },
    }
    evidence_path = out / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        receipt = map_report(
            raw,
            artifact_ref=str(artifact),
            artifact_sha256=artifact_hash,
            scanner_version=version,
            scanner_exit_code=proc.returncode,
            evidence_digest=f"sha256:{sha256(evidence_path)}",
        )
    except ValueError:
        receipt = inconclusive_receipt(
            artifact_ref=str(artifact),
            artifact_sha256=artifact_hash,
            scanner_version=version,
            reason="evidence_unavailable",
        )
        return_code = 1
    else:
        # A findings receipt is successful evidence production even though the
        # scanner's own result code is 1. Admission policy is the consumer's job.
        return_code = 0

    _write_receipt(out, receipt)
    return return_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--osv", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return run(args.osv, args.artifact, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
