def stop_process(process, grace_seconds=5):
    if not process.is_alive():
        return
    process.terminate()
    process.join(grace_seconds)
    if process.is_alive():
        process.kill()
        process.join(grace_seconds)
    if process.is_alive():
        raise AssertionError("owned child process survived terminate and kill")


def wait_for_expected_exit(process, *, expected_exit, timeout_seconds):
    process.join(timeout_seconds)
    if process.is_alive():
        stop_process(process)
        raise AssertionError(
            f"owned child process timed out after {timeout_seconds} seconds"
        )
    if process.exitcode != expected_exit:
        raise AssertionError(
            f"owned child process exited {process.exitcode}, expected {expected_exit}"
        )
