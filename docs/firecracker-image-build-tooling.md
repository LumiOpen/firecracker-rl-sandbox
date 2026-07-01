# Firecracker Image Build Tooling

Phase 9 makes image construction an explicit production interface instead of an
implicit artifact left behind by a benchmark run.

## Contract

- The host kernel does not need to match the guest kernel. The guest kernel must
  match the VM architecture and include the Firecracker devices used by the
  profile: serial, virtio block, and virtio-vsock for the offline MVP.
- Base images are portable across hosts with compatible architecture and KVM
  support. Snapshots are more constrained and should be treated as tied to the
  Firecracker version, CPU template/features, memory size, device model, kernel,
  and rootfs identity.
- The production reset model should be an immutable base OS plus a disposable
  writable workspace or overlay. The current LUMI image already mounts
  `/workspace` as tmpfs and reseeds it on reset; Phase 9 formalizes that as a
  profile field.
- The primary distribution interface should be the profile, build script, build
  log, and manifest. Checksums are useful validation metadata, not the user
  workflow.

## Profiles

Profiles live in `image_profiles/`:

- `base.yaml`: shell/coreutils profile.
- `python-coding.yaml`: Python, pytest, git, and common text tools.
- `full-coding.yaml`: Python plus C/C++ build tools and extra diagnostics.

Each profile declares architecture, distribution, kernel/device expectations,
rootfs size, workspace mode, package roots, and command-agent transport.

## Tool

Use `scripts/firecracker_image_builder.py`:

```bash
python3 scripts/firecracker_image_builder.py validate --profile image_profiles/python-coding.yaml
python3 scripts/firecracker_image_builder.py plan --profile image_profiles/python-coding.yaml
python3 scripts/firecracker_image_builder.py emit-build-script --profile image_profiles/python-coding.yaml
python3 scripts/firecracker_image_builder.py manifest \
  --profile image_profiles/python-coding.yaml \
  --kernel /path/to/vmlinux \
  --rootfs /path/to/rootfs.ext4 \
  --firecracker /path/to/firecracker
```

The current implementation validates and plans the profile contract. The emitted
build script records the requested package set and delegates to the existing
Phase 5 rootfs composer backend. The next backend should consume
`FIRECRACKER_IMAGE_PROFILE_JSON` directly so packages and modes are not embedded
in Python constants.

## Open Production Work

- Move package roots out of `firecracker_lumi_phase5.py` and into image
  profiles.
- Add a real `build` subcommand that consumes profile JSON directly.
- Add a profile-level boot smoke: command agent ready, workspace reset, package
  inventory, and no unintended host mounts.
- Add optional overlay/block workspace modes for workloads that need larger or
  persistent scratch inside a session.
- Record snapshot compatibility metadata separately from generic image metadata.
