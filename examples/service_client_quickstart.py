from firecracker_rl_sandbox import ServiceClient


def main() -> int:
    client = ServiceClient("http://127.0.0.1:8765")
    pool = client.pool("default", profile="python-coding")
    with pool.allocate() as sandbox:
        result = sandbox.run("pwd; python3 -c 'print(1 + 1)'")
        print(result.stdout_text.strip())
        assert result.exit_code == 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
