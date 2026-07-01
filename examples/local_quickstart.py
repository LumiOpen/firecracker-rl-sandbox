from firecracker_rl_sandbox import LocalPool


def main() -> int:
    pool = LocalPool(
        profile="python-coding",
        size=2,
        mem_mib=768,
        vcpus=1,
        # network="egress",  # uncomment to allow network egress
    )
    with pool.allocate() as sandbox:
        result = sandbox.run("python3 - <<'PY'\nprint('ready')\nPY")
        print(result.stdout_text.strip())
        assert result.exit_code == 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
