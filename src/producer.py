from __future__ import annotations

import argparse, hashlib, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapter import map_report, inconclusive_receipt

PRODUCER_VERSION = "0.1.0"
PINNED_TRIVY_VERSION = "0.74.0"
PINNED_TRIVY_SHA256 = {
    "win32": "4c532e1f28f53282dc364671e87381cd77760fa9cafab143f576449c2207cdd5",
    "linux": "d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def trivy_version(binary: str) -> str:
    p = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True)
    first = p.stdout.strip().splitlines()[0]
    return first.split(":", 1)[1].strip() if ":" in first else first


def database_metadata() -> dict[str, Any]:
    cache = Path(os.environ.get("TRIVY_CACHE_DIR", Path.home() / ".cache" / "trivy")) / "db"
    metadata: dict[str, Any] = {}
    metadata_path = cache / "metadata.json"
    db_path = cache / "trivy.db"
    if metadata_path.exists():
        try:
            metadata["metadata"] = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metadata["metadata_read_error"] = True
    if db_path.exists():
        metadata["trivy_db_path"] = str(db_path)
        metadata["trivy_db_sha256"] = sha256(db_path)
        metadata["trivy_db_size"] = db_path.stat().st_size
    return metadata


def run(binary: str, artifact: Path, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    raw_path, stderr_path = out / "trivy.raw.json", out / "trivy.stderr.log"
    artifact_hash = sha256(artifact)
    try:
        binary_hash = sha256(Path(binary))
    except OSError:
        binary_hash = None
    expected_binary_hash = PINNED_TRIVY_SHA256.get(sys.platform)
    if expected_binary_hash is None or binary_hash != expected_binary_hash:
        receipt = inconclusive_receipt(artifact_ref=str(artifact), artifact_sha256=artifact_hash,
                                       scanner_version="unverified", reason="evidence_unavailable")
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1
    try:
        version = trivy_version(binary)
    except (OSError, subprocess.CalledProcessError):
        receipt = inconclusive_receipt(artifact_ref=str(artifact), artifact_sha256=artifact_hash,
                                       scanner_version="unavailable")
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1
    if version != PINNED_TRIVY_VERSION:
        receipt = inconclusive_receipt(artifact_ref=str(artifact), artifact_sha256=artifact_hash,
                                       scanner_version=version, reason="evidence_unavailable")
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1
    started = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    argv = [binary, "fs", "--format", "json", "--output", str(raw_path), "--scanners", "vuln", "--exit-code", "0", str(artifact)]
    proc = subprocess.run(argv, capture_output=True, text=True)
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    completed = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    raw: dict[str, Any] | None = None
    try:
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    if proc.returncode == 0 and raw is not None:
        evidence = {
            "schema_version": "project-defined-evidence-manifest-v1",
            "artifact": {"ref": str(artifact), "sha256": artifact_hash, "size": artifact.stat().st_size},
            "scanner": {"name": "trivy", "version": version},
            "scanner_database": database_metadata(),
            "invocation": {"argv": argv, "started_at": started, "completed_at": completed, "exit_code": proc.returncode},
            "raw_report": {"path": str(raw_path), "sha256": sha256(raw_path)},
            "producer": {"name": "mcp-evidence-producer-trivy", "version": PRODUCER_VERSION},
        }
        evidence_path = out / "evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            receipt = map_report(raw, artifact_ref=str(artifact), artifact_sha256=artifact_hash,
                                 scanner_version=version, evidence_digest=f"sha256:{sha256(evidence_path)}")
        except ValueError:
            receipt = inconclusive_receipt(artifact_ref=str(artifact), artifact_sha256=artifact_hash,
                                           scanner_version=version)
            return_code = 1
        else:
            return_code = 0
    else:
        receipt = inconclusive_receipt(artifact_ref=str(artifact), artifact_sha256=artifact_hash,
                                       scanner_version=version)
        return_code = 1
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return return_code


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--trivy", required=True)
    p.add_argument("--artifact", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    return run(args.trivy, args.artifact, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
