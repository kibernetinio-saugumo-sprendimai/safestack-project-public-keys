#!/usr/bin/env python3
"""SafeStack Project Public Key Registry Verifier & Tool.

Validates the root-signed Ed25519 public key registry and provides
fingerprint derivation and project identity verification.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from canonical_serializer import canonical_json

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as exc:
    raise RuntimeError("key registry requires cryptography; install cryptography>=42") from exc

SCHEMA = "safestack.project-key-registry.v1"
ACTIVE = "active"
REVOKED = "revoked"


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("encoded key must be a string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64 key") from exc


def unsigned_registry(registry: dict[str, Any]) -> dict[str, Any]:
    result = dict(registry)
    result.pop("signature", None)
    return result


def _registry_bytes(registry: dict[str, Any]) -> bytes:
    return canonical_json(unsigned_registry(registry)).encode("utf-8")


def fingerprint_bytes(key_bytes: bytes) -> str:
    return hashlib.sha256(key_bytes).hexdigest()


def fingerprint_b64(key_b64: str) -> str:
    return fingerprint_bytes(_unb64(key_b64))


def verify_registry(registry: dict[str, Any]) -> None:
    if registry.get("schema") != SCHEMA or not isinstance(registry.get("projects"), dict):
        raise ValueError(f"invalid registry schema: expected {SCHEMA}")
    
    root_bytes = _unb64(registry.get("root_public_key"))
    if len(root_bytes) != 32:
        raise ValueError("invalid root public key length (must be 32 bytes)")
    
    signature = _unb64(registry.get("signature"))
    if len(signature) != 64:
        raise ValueError("invalid registry signature length (must be 64 bytes)")
    
    root = Ed25519PublicKey.from_public_bytes(root_bytes)
    root.verify(signature, _registry_bytes(registry))

    for project_id, entry in registry["projects"].items():
        if not isinstance(project_id, str) or not project_id or not isinstance(entry, dict):
            raise ValueError(f"invalid project entry for {project_id}")
        if entry.get("status") not in {ACTIVE, REVOKED}:
            raise ValueError(f"invalid project status for {project_id}")
        pk_bytes = _unb64(entry.get("public_key"))
        if len(pk_bytes) != 32:
            raise ValueError(f"invalid public key length for {project_id}")


def verify_artifact(registry: dict[str, Any], signature: dict[str, str], artifact: bytes) -> None:
    verify_registry(registry)
    if signature.get("registry_id") != registry.get("registry_id"):
        raise ValueError("signature belongs to another registry")
    entry = registry["projects"].get(signature.get("project_id"))
    if not entry or entry.get("status") != ACTIVE:
        raise ValueError("project key is missing or revoked")
    Ed25519PublicKey.from_public_bytes(_unb64(entry["public_key"])).verify(
        _unb64(signature.get("signature")), artifact
    )


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage and verify the signed SafeStack project-key registry")
    sub = parser.add_subparsers(dest="command", required=True)

    verify_cmd = sub.add_parser("verify", help="Verify cryptographic signature of the registry file")
    verify_cmd.add_argument("--registry", type=Path, required=True, help="Path to public-project-keys.json")

    list_cmd = sub.add_parser("list", help="List registered projects and their status")
    list_cmd.add_argument("--registry", type=Path, default=Path("public-project-keys.json"))

    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            registry = _load(args.registry)
            verify_registry(registry)
            print("registry signature valid")
            return 0

        if args.command == "list":
            registry = _load(args.registry)
            verify_registry(registry)
            print(f"Registry ID: {registry.get('registry_id')} (Schema: {registry.get('schema')})")
            print(f"Root Public Key: {registry.get('root_public_key')}")
            print(f"Total Projects: {len(registry.get('projects', {}))}\n")
            for pid, pdata in sorted(registry.get("projects", {}).items()):
                fp = fingerprint_b64(pdata["public_key"])
                status = pdata.get("status", "unknown")
                pname = pdata.get("project_name", "")
                repo = pdata.get("repository", "")
                print(f"[{status.upper():7s}] {pid} - {pname} ({repo})")
                print(f"          Fingerprint: {fp}")
            return 0

    except Exception as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
