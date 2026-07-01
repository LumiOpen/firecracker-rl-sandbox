# Firecracker Image Build Tooling

Image construction should be a reproducible interface, not an implicit artifact
left behind by a benchmark run. A sandbox deployment should be able to name a
profile, build or fetch the required artifacts, inspect a manifest, and pass the
artifacts to `LocalPool` or the service.

## Contract

- The host kernel does not need to match the guest kernel. The guest kernel must
  match the VM architecture and include the Firecracker devices used by the
  profile: serial, virtio block, and virtio-vsock for the current command
  channel.
- Base images are portable across hosts with compatible architecture and KVM
  support. Snapshots are more constrained and should be treated as tied to the
  Firecracker version, CPU template/features, memory size, device model, kernel,
  and rootfs identity.
- The reset model should be an immutable base OS plus a disposable writable
  workspace or overlay. The current profile model treats workspace behavior as
  part of the image/profile contract.
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
build script records the requested package set and delegates to the current
rootfs composer backend. The artifact helper used by the quick start,
`scripts/firecracker_prepare_artifacts.py`, fetches a Firecracker binary and
guest kernel, then composes a default rootfs and writes an environment file for
the Python APIs or service command.

The remaining work to make this a full production image builder is tracked in
GitHub issue #6.
