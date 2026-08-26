import unittest

from tests.process_control import wait_for_expected_exit


class FakeProcess:
    def __init__(self, *, exitcode=None, alive=True):
        self.exitcode = exitcode
        self.alive = alive
        self.join_calls = []
        self.terminated = False
        self.killed = False

    def join(self, timeout=None):
        self.join_calls.append(timeout)

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        self.alive = False
        self.exitcode = -15

    def kill(self):
        self.killed = True
        self.alive = False
        self.exitcode = -9


class ProcessControlTests(unittest.TestCase):
    def test_expected_exit_returns_without_cleanup(self):
        process = FakeProcess(exitcode=98, alive=False)

        wait_for_expected_exit(process, expected_exit=98, timeout_seconds=7)

        self.assertEqual(process.join_calls, [7])
        self.assertFalse(process.terminated)
        self.assertFalse(process.killed)

    def test_timeout_ends_the_owned_process_before_failing(self):
        process = FakeProcess()

        with self.assertRaisesRegex(AssertionError, "timed out after 7 seconds"):
            wait_for_expected_exit(process, expected_exit=98, timeout_seconds=7)

        self.assertTrue(process.terminated)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.join_calls, [7, 5])


if __name__ == "__main__":
    unittest.main()
