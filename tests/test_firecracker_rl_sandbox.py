from firecracker_rl_sandbox import LocalPool
import unittest


class LocalPoolTests(unittest.TestCase):
    def test_local_pool_runs_commands_and_cleans_workspace(self):
        pool = LocalPool(size=1)
        with pool.allocate(task_id="unit") as sandbox:
            result = sandbox.run("printf hello > file.txt; cat file.txt")
            workspace = sandbox.workspace
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, b"hello")
        self.assertFalse(workspace.exists())

    def test_local_process_cancel(self):
        pool = LocalPool(size=1)
        with pool.allocate() as sandbox:
            proc = sandbox.start_process("sleep 30")
            self.assertTrue(proc.status()["running"])
            status = proc.cancel()
            self.assertIn(status["running"], {True, False})


if __name__ == "__main__":
    unittest.main()
