from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
from collections import deque
from pathlib import Path


EVENT_PREFIX = "AO_TEST_EVENT "
TIMEOUT_EXIT = 124
CREATE_NEW_PROCESS_GROUP = 0x00000200
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


def _utc_now():
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


class _TimedResult(unittest.TextTestResult):
    def startTest(self, test):
        self._started = time.monotonic()
        self._outcome = "unknown"
        self._reason = None
        self._detail = None
        print(
            EVENT_PREFIX
            + json.dumps({"event": "start", "test": test.id(), "utc": _utc_now()}),
            flush=True,
        )
        super().startTest(test)

    def addSuccess(self, test):
        self._outcome = "success"
        super().addSuccess(test)

    def addSkip(self, test, reason):
        self._outcome = "skip"
        self._reason = str(reason)[:2000]
        # unittest writes the parent test label without a trailing newline before
        # reporting its first skipped subtest. Start on a fresh line so the
        # supervisor can recognize every machine event in the merged stream.
        print(
            "\n"
            + EVENT_PREFIX
            + json.dumps(
                {
                    "event": "skip",
                    "skip_reason": self._reason,
                    "test": test.id(),
                    "utc": _utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        super().addSkip(test, reason)

    def addFailure(self, test, err):
        self._outcome = "failure"
        self._detail = self._exc_info_to_string(err, test)[-12000:]
        super().addFailure(test, err)

    def addError(self, test, err):
        self._outcome = "error"
        self._detail = self._exc_info_to_string(err, test)[-12000:]
        super().addError(test, err)

    def addExpectedFailure(self, test, err):
        self._outcome = "expected-failure"
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._outcome = "unexpected-success"
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self._outcome = "failure" if issubclass(err[0], test.failureException) else "error"
            self._detail = self._exc_info_to_string(err, test)[-12000:]
        super().addSubTest(test, subtest, err)

    def stopTest(self, test):
        event = {
            "duration_seconds": round(time.monotonic() - self._started, 6),
            "event": "stop",
            "outcome": self._outcome,
            "test": test.id(),
            "utc": _utc_now(),
        }
        if self._reason is not None:
            event["skip_reason"] = self._reason
        if self._detail is not None:
            event["detail"] = self._detail
        print(EVENT_PREFIX + json.dumps(event, sort_keys=True), flush=True)
        super().stopTest(test)


def _worker(test_names):
    loader = unittest.defaultTestLoader
    suite = loader.loadTestsFromNames(test_names) if test_names else loader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2, resultclass=_TimedResult).run(suite)
    return 0 if result.wasSuccessful() else 1


class _ProcessEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class _MemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def _process_parents():
    kernel = ctypes.windll.kernel32
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    snapshot = kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return {}
    parents = {}
    entry = _ProcessEntry32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        present = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            present = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return parents


def _tree_pids(root_pid):
    parents = _process_parents()
    selected = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return sorted(selected)


def _process_metrics(pid):
    kernel = ctypes.windll.kernel32
    kernel.OpenProcess.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None
    try:
        handles = ctypes.c_ulong()
        counters = _MemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not kernel.GetProcessHandleCount(handle, ctypes.byref(handles)):
            return None
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), ctypes.sizeof(counters)
        ):
            return None
        return int(handles.value), int(counters.WorkingSetSize), int(counters.PrivateUsage)
    finally:
        kernel.CloseHandle(handle)


def _storage(root):
    count = 0
    size = 0
    if not root.exists():
        return count, size
    for directory, _directories, files in os.walk(root):
        for name in files:
            try:
                size += (Path(directory) / name).stat().st_size
                count += 1
            except OSError:
                continue
    return count, size


def _sample(root_pid, task_root, active_test):
    pids = _tree_pids(root_pid)
    handles = 0
    working_set = 0
    private_bytes = 0
    measured = []
    for pid in pids:
        metrics = _process_metrics(pid)
        if metrics is None:
            continue
        measured.append(pid)
        handles += metrics[0]
        working_set += metrics[1]
        private_bytes += metrics[2]
    storage_count, storage_bytes = _storage(task_root)
    return {
        "active_test": active_test,
        "child_count": max(0, len(pids) - 1),
        "event": "sample",
        "handle_count": handles,
        "measured_pids": measured,
        "private_bytes": private_bytes,
        "process_ids": pids,
        "task_root_bytes": storage_bytes,
        "task_root_files": storage_count,
        "utc": _utc_now(),
        "working_set_bytes": working_set,
    }


def _end_tree(process):
    subprocess.run(
        ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    return process.poll() is not None


def _append_tail(tail, line, limit, length):
    tail.append(line)
    length += len(line)
    while tail and length > limit:
        length -= len(tail.popleft())
    return length


def _supervise(args):
    if os.name != "nt":
        raise SystemExit("run_windows_tests.py requires Windows")
    evidence = Path(args.evidence_dir).resolve()
    task_root = Path(args.task_root).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    task_root.mkdir(parents=True, exist_ok=False)
    temp_root = task_root / "temp"
    temp_root.mkdir()

    repository_root = Path(__file__).parents[1]
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", *args.tests]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join(
        value
        for value in (str(repository_root), environment.get("PYTHONPATH"))
        if value
    )
    environment["TEMP"] = str(temp_root)
    environment["TMP"] = str(temp_root)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=repository_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        creationflags=CREATE_NEW_PROCESS_GROUP,
    )
    state = {"active": None, "active_started": None}
    lock = threading.Lock()
    events = []
    tail = deque()
    tail_length = 0
    reader_done = threading.Event()

    with (evidence / "events.jsonl").open("x", encoding="utf-8", newline="\n") as event_file, (
        evidence / "samples.jsonl"
    ).open("x", encoding="utf-8", newline="\n") as sample_file:

        def read_output():
            nonlocal tail_length
            assert process.stdout is not None
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                tail_length = _append_tail(tail, line, args.output_chars, tail_length)
                if not line.startswith(EVENT_PREFIX):
                    continue
                try:
                    event = json.loads(line[len(EVENT_PREFIX) :])
                except json.JSONDecodeError:
                    continue
                events.append(event)
                event_file.write(json.dumps(event, sort_keys=True) + "\n")
                event_file.flush()
                with lock:
                    if event["event"] == "start":
                        state["active"] = event["test"]
                        state["active_started"] = time.monotonic()
                    elif event["event"] == "stop" and state["active"] == event.get("test"):
                        state["active"] = None
                        state["active_started"] = None
            reader_done.set()

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        timed_out = False
        worker_tree_ended = False
        next_sample = 0.0
        while process.poll() is None:
            now = time.monotonic()
            with lock:
                active = state["active"]
                active_started = state["active_started"]
            if now >= next_sample:
                sample = _sample(process.pid, task_root, active)
                sample_file.write(json.dumps(sample, sort_keys=True) + "\n")
                sample_file.flush()
                next_sample = now + args.sample_interval
            if active_started is not None and now - active_started > args.test_timeout:
                timed_out = True
                worker_tree_ended = _end_tree(process)
                break
            time.sleep(min(0.1, args.sample_interval))
        reader_done.wait(10)
        reader.join(timeout=1)
        if not timed_out:
            worker_tree_ended = process.poll() is not None

    stops = [event for event in events if event.get("event") == "stop"]
    skips = [event for event in events if event.get("event") == "skip"]
    outcomes = {}
    for event in stops:
        outcome = event.get("outcome", "unknown")
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    with lock:
        active_test = state["active"]
    result = "TIMEOUT" if timed_out else ("PASS" if process.returncode == 0 else "FAIL")
    summary = {
        "active_test": active_test,
        "duration_seconds": round(time.monotonic() - started, 6),
        "event_count": len(events),
        "outcomes": outcomes,
        "result": result,
        "schema_version": 1,
        "skip_event_count": len(skips),
        "test_count": len(stops),
        "test_timeout_seconds": args.test_timeout,
        "utc_completed": _utc_now(),
        "worker_exit": process.returncode,
        "worker_pid": process.pid,
        "worker_tree_ended": worker_tree_ended,
    }
    (evidence / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence / "output-tail.txt").write_text("".join(tail), encoding="utf-8")
    try:
        shutil.rmtree(temp_root)
        task_root.rmdir()
        summary["task_root_residue"] = False
    except OSError:
        summary["task_root_residue"] = True
    (evidence / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"windows-test-runner result={result} tests={len(stops)} "
        f"duration={summary['duration_seconds']} active={active_test or '-'}",
        file=sys.stderr if result != "PASS" else sys.stdout,
    )
    return TIMEOUT_EXIT if timed_out else int(process.returncode or 0)


def _parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--evidence-dir")
    parser.add_argument("--task-root")
    parser.add_argument("--test-timeout", type=float, default=600)
    parser.add_argument("--sample-interval", type=float, default=30)
    parser.add_argument("--output-chars", type=int, default=12000)
    parser.add_argument("tests", nargs="*")
    return parser


def main():
    args = _parser().parse_args()
    if args.worker:
        return _worker(args.tests)
    if not args.evidence_dir or not args.task_root:
        raise SystemExit("--evidence-dir and --task-root are required")
    if args.test_timeout <= 0 or args.sample_interval <= 0 or args.output_chars <= 0:
        raise SystemExit("timeouts, sample interval, and output bound must be positive")
    return _supervise(args)


if __name__ == "__main__":
    raise SystemExit(main())
