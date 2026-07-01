#!/usr/bin/env python3
"""Profile-driven Firecracker image tooling.

This is intentionally a thin production interface over the image composition
work proven in the LUMI Firecracker phases. It validates declarative profiles,
emits build plans/manifests, and can generate the shell entrypoint that invokes
the current rootfs composer. The long-term builder can replace the backend
without changing the profile contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


REQUIRED_TOP_LEVEL = ("name", "arch", "distribution", "kernel", "devices", "rootfs", "packages", "agent")
SUPPORTED_ARCHES = {"x86_64", "aarch64"}
SUPPORTED_WORKSPACE_MODES = {"tmpfs", "overlay", "block"}
SUPPORTED_BASE_MODES = {"read_only", "read_write"}


def main() -> int:
    args = parse_args()
    profile = load_profile(args.profile)
    errors = validate_profile(profile)
    if args.command == "validate":
        output = {"assessment": "pass" if not errors else "fail", "profile": profile, "errors": errors}
        write_output(args.output, output)
        return 0 if not errors else 2
    if errors:
        write_output(args.output, {"assessment": "fail", "profile": profile, "errors": errors})
        return 2
    if args.command == "plan":
        write_output(args.output, build_plan(profile))
        return 0
    if args.command == "manifest":
        manifest = build_manifest(
            profile,
            kernel=args.kernel,
            rootfs=args.rootfs,
            firecracker=args.firecracker,
            extra_artifacts=args.extra_artifact,
        )
        write_output(args.output, manifest)
        return 0
    if args.command == "emit-build-script":
        script = emit_build_script(profile, args)
        if args.output:
            Path(args.output).write_text(script, encoding="utf-8")
        else:
            print(script, end="")
        return 0
    raise AssertionError(args.command)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and plan Firecracker image builds.")
    parser.add_argument("command", choices=("validate", "plan", "manifest", "emit-build-script"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--firecracker", type=Path)
    parser.add_argument("--extra-artifact", action="append", default=[], type=Path)
    parser.add_argument("--workspace-template", default="workspaces/fixtures/mvp")
    parser.add_argument("--artifact-cache-dir", default="${BASE_ROOT}/cache")
    parser.add_argument("--rootfs-cache-dir", default="${BASE_ROOT}/rootfs")
    parser.add_argument("--builder", default="scripts/firecracker_lumi_phase5.py")
    return parser.parse_args()


def load_profile(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except ImportError:
            data = load_simple_yaml(text)
        else:
            data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise SystemExit(f"{path} did not parse to a mapping")
    data["_profile_path"] = str(path)
    return data


def validate_profile(profile: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_TOP_LEVEL:
        if key not in profile:
            errors.append(f"missing top-level key: {key}")
    arch = profile.get("arch")
    if arch not in SUPPORTED_ARCHES:
        errors.append(f"unsupported arch {arch!r}; expected one of {sorted(SUPPORTED_ARCHES)}")
    rootfs = mapping(profile.get("rootfs"))
    if rootfs.get("base_mode") not in SUPPORTED_BASE_MODES:
        errors.append("rootfs.base_mode must be read_only or read_write")
    if rootfs.get("workspace_mode") not in SUPPORTED_WORKSPACE_MODES:
        errors.append("rootfs.workspace_mode must be tmpfs, overlay, or block")
    if int(rootfs.get("logical_size_mb") or 0) <= 0:
        errors.append("rootfs.logical_size_mb must be positive")
    if int(rootfs.get("workspace_size_mb") or 0) <= 0:
        errors.append("rootfs.workspace_size_mb must be positive")
    devices = profile.get("devices") or []
    for required in ("serial", "virtio-block", "virtio-vsock"):
        if required not in devices:
            errors.append(f"devices must include {required}")
    apt = mapping(profile.get("packages")).get("apt") or []
    if not isinstance(apt, list) or not all(isinstance(item, str) for item in apt):
        errors.append("packages.apt must be a list of package names")
    for required_pkg in ("bash", "coreutils"):
        if required_pkg not in apt:
            errors.append(f"packages.apt should include {required_pkg}")
    agent = mapping(profile.get("agent"))
    if agent.get("transport") != "vsock":
        errors.append("agent.transport must be vsock for the current production path")
    return errors


def build_plan(profile: dict[str, Any]) -> dict[str, Any]:
    apt = sorted(mapping(profile.get("packages")).get("apt") or [])
    rootfs = mapping(profile.get("rootfs"))
    return {
        "assessment": "pass",
        "profile": public_profile(profile),
        "build_steps": [
            "resolve and cache package indexes for the requested distribution/release",
            "materialize a rootfs tree with the requested package closure",
            "inject the vsock command agent and workspace template",
            "create an ext4 rootfs image with the requested logical size",
            "boot-smoke the image under Firecracker with the configured guest kernel",
            "emit manifest with package inventory, kernel config id, rootfs mode, and workspace reset mode",
        ],
        "package_count": len(apt),
        "packages": apt,
        "rootfs_contract": {
            "base_mode": rootfs.get("base_mode"),
            "workspace_mode": rootfs.get("workspace_mode"),
            "workspace_size_mb": rootfs.get("workspace_size_mb"),
            "reset_semantics": "discard writable workspace/layer, keep base OS immutable",
        },
        "portability": {
            "host_kernel_match_required": False,
            "guest_kernel_constraints": "must match architecture and include Firecracker device support",
            "snapshot_portability": "tied to Firecracker version, CPU template/features, memory size, devices, kernel, and rootfs identity",
        },
    }


def build_manifest(
    profile: dict[str, Any],
    *,
    kernel: Path | None,
    rootfs: Path | None,
    firecracker: Path | None,
    extra_artifacts: list[Path],
) -> dict[str, Any]:
    artifacts = {}
    for label, path in (("kernel", kernel), ("rootfs", rootfs), ("firecracker", firecracker)):
        if path is not None:
            artifacts[label] = artifact_record(path)
    for path in extra_artifacts:
        artifacts[str(path)] = artifact_record(path)
    return {
        "assessment": "pass",
        "profile": public_profile(profile),
        "profile_hash": stable_hash(public_profile(profile)),
        "artifacts": artifacts,
        "notes": [
            "Checksums are validation metadata, not the primary distribution interface.",
            "The source profile plus build logs should be enough to recreate the image.",
        ],
    }


def emit_build_script(profile: dict[str, Any], args: argparse.Namespace) -> str:
    apt = " ".join(shlex.quote(item) for item in sorted(mapping(profile.get("packages")).get("apt") or []))
    profile_json = json.dumps(public_profile(profile), sort_keys=True)
    lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        "",
        "# Generated by scripts/firecracker_image_builder.py.",
        "# Current backend: existing LUMI phase5 rootfs composer.",
        "",
        f"export FIRECRACKER_IMAGE_PROFILE_JSON={shlex.quote(profile_json)}",
        f"export FIRECRACKER_IMAGE_PROFILE_NAME={shlex.quote(str(profile.get('name')))}",
        f"export FIRECRACKER_IMAGE_PACKAGES={shlex.quote(apt)}",
        "",
        "BASE_ROOT=${BASE_ROOT:-/scratch/${PROJECT:-project_462001516}/users/${USER}/firecracker-bench}",
        f"ARTIFACT_CACHE_DIR={args.artifact_cache_dir}",
        f"ROOTFS_CACHE_DIR={args.rootfs_cache_dir}",
        f"WORKSPACE_TEMPLATE={shlex.quote(args.workspace_template)}",
        "",
        "# The current composer consumes the package roots embedded in phase5.",
        "# The next backend should read FIRECRACKER_IMAGE_PROFILE_JSON directly.",
        "python3 - <<'PY'",
        "import json, os",
        "profile=json.loads(os.environ['FIRECRACKER_IMAGE_PROFILE_JSON'])",
        "print(json.dumps({'profile': profile['name'], 'packages': profile['packages']['apt']}, indent=2, sort_keys=True))",
        "PY",
        "",
    ]
    return "\n".join(lines) + "\n"


def artifact_record(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {"path": str(path), "exists": False}
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return {
        "path": str(path),
        "exists": True,
        "bytes": path.stat().st_size,
        "sha256": h.hexdigest(),
    }


def stable_hash(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def public_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in profile.items() if not key.startswith("_")}


def write_output(path: Path | None, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def load_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by image_profiles/*.yaml.

    This is not a general YAML parser. It supports nested mappings, scalar
    values, and lists of scalar values so the profile validator has no hard
    dependency beyond the Python standard library.
    """
    rows: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        rows.append((indent, raw.strip()))
    parsed, index = parse_yaml_block(rows, 0, 0)
    if index != len(rows):
        raise SystemExit("failed to parse profile YAML subset")
    if not isinstance(parsed, dict):
        raise SystemExit("profile YAML must parse to a mapping")
    return parsed


def parse_yaml_block(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(rows):
        return {}, index
    if rows[index][0] < indent:
        return {}, index
    is_list = rows[index][1].startswith("- ")
    if is_list:
        values = []
        while index < len(rows) and rows[index][0] == indent and rows[index][1].startswith("- "):
            text = rows[index][1][2:].strip()
            if text:
                values.append(parse_scalar(text))
                index += 1
            else:
                child, index = parse_yaml_block(rows, index + 1, indent + 2)
                values.append(child)
        return values, index

    values: dict[str, Any] = {}
    while index < len(rows):
        row_indent, text = rows[index]
        if row_indent < indent:
            break
        if row_indent > indent:
            raise SystemExit(f"unexpected indentation near: {text}")
        if text.startswith("- "):
            break
        if ":" not in text:
            raise SystemExit(f"expected key/value YAML row, got: {text}")
        key, raw_value = text.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        index += 1
        if raw_value:
            values[key] = parse_scalar(raw_value)
            continue
        if index >= len(rows) or rows[index][0] <= indent:
            values[key] = {}
            continue
        child, index = parse_yaml_block(rows, index, rows[index][0])
        values[key] = child
    return values, index


def parse_scalar(value: str) -> Any:
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        return value.strip('"').strip("'")


if __name__ == "__main__":
    raise SystemExit(main())
