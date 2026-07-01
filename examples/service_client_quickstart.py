from firecracker_rl_sandbox import ServiceClient


def main() -> int:
    client = ServiceClient("http://127.0.0.1:8765")
    pool = client.create_pool(
        pool_id="quickstart",
        profile="python-coding",
        size=1,
        mem_mib=768,
        vcpus=1,
        # network="egress",  # uncomment to allow network egress
    )
    with pool.allocate() as sandbox:
        result = sandbox.run("pwd; python3 -c 'print(1 + 1)'")
        print(result.stdout_text.strip())
        assert result.exit_code == 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
