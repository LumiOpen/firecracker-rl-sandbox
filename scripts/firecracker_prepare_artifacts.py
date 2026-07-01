#!/usr/bin/env python3
"""Fetch/build the basic artifacts needed by the Firecracker service."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from firecracker_lumi_bench import download_firecracker, download_kernel, mkdir
from firecracker_lumi_net_poc import download_gvisor_tap_vsock
from firecracker_lumi_phase5 import prepare_rootfs


def main() -> int:
    args = parse_args()
    base_root = Path(args.base_root).expanduser().resolve()
    artifact_cache_dir = Path(args.artifact_cache_dir or base_root / "cache")
    rootfs_cache_dir = Path(args.rootfs_cache_dir or base_root / "rootfs")
    workspace_template = Path(args.workspace_template).resolve()
    mkdir(base_root)
    mkdir(artifact_cache_dir)
    mkdir(rootfs_cache_dir)

    firecracker = (
        {"path": str(Path(args.firecracker_bin).expanduser().resolve()), "override": True}
        if args.firecracker_bin
        else download_firecracker(artifact_cache_dir / "firecracker")
    )
    kernel = (
        {"path": str(Path(args.kernel).expanduser().resolve()), "override": True}
        if args.kernel
        else download_kernel(artifact_cache_dir / "kernel")
    )
    tools = download_gvisor_tap_vsock(artifact_cache_dir / "gvisor-tap-vsock")
    rootfs = (
        {"path": str(Path(args.rootfs).expanduser().resolve()), "override": True}
        if args.rootfs
        else prepare_rootfs(rootfs_cache_dir, artifact_cache_dir, tools, workspace_template)
    )

    result: dict[str, Any] = {
        "assessment": "pass",
        "profile": args.profile,
        "base_root": str(base_root),
        "artifact_cache_dir": str(artifact_cache_dir),
        "rootfs_cache_dir": str(rootfs_cache_dir),
        "workspace_template": str(workspace_template),
        "firecracker": firecracker,
        "kernel": kernel,
        "rootfs": rootfs,
    }
    if args.json_output:
        Path(args.json_output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.env_output:
        Path(args.env_output).write_text(render_env(result), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare Firecracker, kernel, and rootfs artifacts.")
    parser.add_argument("--profile", default="python-coding", choices=("python-coding",))
    parser.add_argument("--base-root", default=default_base_root())
    parser.add_argument("--artifact-cache-dir")
    parser.add_argument("--rootfs-cache-dir")
    parser.add_argument("--workspace-template", default="workspaces/fixtures/mvp")
    parser.add_argument("--firecracker-bin", help="Use this Firecracker executable instead of downloading one.")
    parser.add_argument("--kernel", help="Use this guest kernel instead of downloading one.")
    parser.add_argument("--rootfs", help="Use this rootfs image instead of composing one.")
    parser.add_argument("--json-output")
    parser.add_argument("--env-output")
    return parser.parse_args()


def default_base_root() -> str:
    if os.environ.get("BASE_ROOT"):
        return os.environ["BASE_ROOT"]
    project = os.environ.get("PROJECT")
    user = os.environ.get("USER")
    if project and user and Path(f"/scratch/{project}/users/{user}").exists():
        return f"/scratch/{project}/users/{user}/firecracker-rl-sandbox"
    return ".firecracker-rl-sandbox-artifacts"


def render_env(result: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"export FIRECRACKER_BIN={shell_quote(result['firecracker']['path'])}",
            f"export FIRECRACKER_KERNEL={shell_quote(result['kernel']['path'])}",
            f"export FIRECRACKER_ROOTFS={shell_quote(result['rootfs']['path'])}",
            f"export FIRECRACKER_ARTIFACT_BASE={shell_quote(result['base_root'])}",
            "",
        ]
    )


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":
    raise SystemExit(main())

