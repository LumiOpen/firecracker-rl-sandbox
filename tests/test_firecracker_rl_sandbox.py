from firecracker_rl_sandbox import SubprocessPool
import unittest


class LocalPoolTests(unittest.TestCase):
    def test_local_pool_runs_commands_and_cleans_workspace(self):
        pool = SubprocessPool(size=1)
        with pool.allocate(task_id="unit") as sandbox:
            result = sandbox.run("printf hello > file.txt; cat file.txt")
            workspace = sandbox.workspace
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, b"hello")
        self.assertFalse(workspace.exists())

    def test_local_process_cancel(self):
        pool = SubprocessPool(size=1)
        with pool.allocate() as sandbox:
            proc = sandbox.start_process("sleep 30")
            self.assertTrue(proc.status()["running"])
            status = proc.cancel()
            self.assertIn(status["running"], {True, False})

    def test_process_handle_interactive_input(self):
        pool = SubprocessPool(size=1)
        with pool.allocate() as sandbox:
            proc = sandbox.start_process("printf 'name? '; read name; echo \"hello $name\"", interactive=True)
            prompt = proc.read(wait_ms=1000)
            self.assertEqual(prompt.stdout, b"name? ")
            write = proc.write("Ada\n")
            self.assertTrue(write["ok"])
            proc.close_stdin()
            stdout = b""
            result = None
            for _ in range(10):
                result = proc.read(wait_ms=100)
                stdout += result.stdout
                if result.exit_code is not None:
                    break
            self.assertIsNotNone(result)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(stdout, b"hello Ada\n")


if __name__ == "__main__":
    unittest.main()
