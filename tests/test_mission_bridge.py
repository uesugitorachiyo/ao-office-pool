import ast
import ctypes
import errno
import hashlib
import hmac
import io
import json
import os
import signal
import stat
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

import internal.mission_bridge as mission_bridge
from internal.mission_bridge import MissionBridgeError, start_or_resume
from internal.pool import Pool
from internal.windows_paths import canonical_windows_path


FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
mode = os.environ.get("AO_TEST_FAKE_MODE")
if mode == "slow-large":
    sys.stdout.write("x" * 70000)
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)
home = pathlib.Path(sys.argv[sys.argv.index("--home") + 1])
home.mkdir(parents=True, exist_ok=True)
log = home / "fake-arguments.jsonl"
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
(home / "fake-cwd").write_text(str(pathlib.Path.cwd()))
if "inspect" in sys.argv:
    mission_id = sys.argv[sys.argv.index("--mission") + 1]
    if mode == "inspect-mismatch":
        mission_id = "mission-fedcba9876543210"
    objective_digest = (home / "objective-digest").read_text()
else:
    task_text = sys.argv[-1]
    import hashlib
    objective_digest = "sha256:" + hashlib.sha256(task_text.encode()).hexdigest()
    (home / "objective-digest").write_text(objective_digest)
    mission_id = "mission-0123456789abcdef"
if mode == "invalid-id":
    mission_id = "mission-not-valid"
print(json.dumps({
    "schema": "ao.mission.record.v0.1",
    "mission_id": mission_id,
    "objective_digest": objective_digest,
    "status": "active",
    "current_route": "ao-blueprint"
}))
'''

DARWIN_FAKE = r'''
#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef PAYLOAD
#define PAYLOAD "benign"
#endif

static int write_bytes(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t size = strlen(value), offset = 0;
    while (offset < size) {
        ssize_t count = write(fd, value + offset, size - offset);
        if (count <= 0) { close(fd); return -1; }
        offset += (size_t)count;
    }
    return close(fd);
}

static int read_bytes(const char *path, char *value, size_t capacity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t count = read(fd, value, capacity - 1);
    close(fd);
    if (count < 0) return -1;
    value[count] = '\0';
    return 0;
}

static void digest(const char *value, char output[72]) {
    unsigned char raw[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(value, (CC_LONG)strlen(value), raw);
    strcpy(output, "sha256:");
    for (int index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        sprintf(output + 7 + index * 2, "%02x", raw[index]);
    }
}

int main(int argc, char **argv) {
    const char *mode = getenv("AO_TEST_FAKE_MODE");
    if (mode && strcmp(mode, "slow-large") == 0) {
        char block[1000]; memset(block, 'x', sizeof(block));
        for (int index = 0; index < 70; index++) write(STDOUT_FILENO, block, sizeof(block));
        struct timespec delay = {10, 0}; nanosleep(&delay, NULL); return 0;
    }
    if (mode && strcmp(mode, "large") == 0) {
        char block[1000]; memset(block, 'x', sizeof(block));
        for (int index = 0; index < 70; index++) write(STDOUT_FILENO, block, sizeof(block));
        return 0;
    }
    const char *home = NULL;
    for (int index = 1; index + 1 < argc; index++) {
        if (strcmp(argv[index], "--home") == 0) home = argv[index + 1];
    }
    if (!home) return 64;
    char path[PATH_MAX], cwd[PATH_MAX], objective[128], mission[64];
    snprintf(path, sizeof(path), "%s/payload-marker", home);
    if (write_bytes(path, PAYLOAD "\n") != 0) return 65;
    snprintf(path, sizeof(path), "%s/fake-cwd", home);
    if (!getcwd(cwd, sizeof(cwd)) || write_bytes(path, cwd) != 0) return 66;
    snprintf(path, sizeof(path), "%s/fake-arguments.jsonl", home);
    int log = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (log < 0) return 67;
    write(log, "[", 1);
    for (int index = 1; index < argc; index++) {
        dprintf(log, "%s\"%s\"", index == 1 ? "" : ",", argv[index]);
    }
    write(log, "]\n", 2); close(log);
    strcpy(mission, "mission-0123456789abcdef");
    bool inspect = false;
    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "inspect") == 0) inspect = true;
        if (strcmp(argv[index], "--mission") == 0 && index + 1 < argc) {
            snprintf(mission, sizeof(mission), "%s", argv[index + 1]);
        }
    }
    snprintf(path, sizeof(path), "%s/objective-digest", home);
    if (inspect) {
        if (read_bytes(path, objective, sizeof(objective)) != 0) return 68;
        if (mode && strcmp(mode, "inspect-mismatch") == 0) {
            strcpy(mission, "mission-fedcba9876543210");
        }
    } else {
        digest(argv[argc - 1], objective);
        if (write_bytes(path, objective) != 0) return 69;
    }
    if (strcmp(PAYLOAD, "malicious") == 0) strcpy(mission, "mission-fedcba9876543210");
    if (mode && strcmp(mode, "invalid-id") == 0) strcpy(mission, "mission-not-valid");
    const char *escalation =
        mode && strcmp(mode, "escalation") == 0 ? ",\"executes_work\":true" : "";
    dprintf(STDOUT_FILENO,
        "{\"mission_id\":\"%s\",\"objective_digest\":\"%s\","
        "\"status\":\"active\",\"current_route\":\"ao-blueprint\"%s}\n",
        mission, objective, escalation);
    return 0;
}
'''


class WindowsBinaryDescriptorTests(unittest.TestCase):
    def test_native_handle_conversions_and_fd_wrappers_are_binary(self):
        # MUTATION: omitting O_BINARY/text mode corrupts Windows byte descriptors.
        roots = Path(mission_bridge.__file__).parent
        handle_flags = []
        fdopen_modes = []
        for name in ("mission_bridge.py", "execution.py", "transactions.py"):
            tree = ast.parse(roots.joinpath(name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr == "open_osfhandle":
                    handle_flags.append(ast.unparse(node.args[1]))
                elif node.func.attr == "fdopen":
                    fdopen_modes.append(ast.literal_eval(node.args[1]))
        self.assertEqual(len(handle_flags), 5)
        self.assertTrue(all("O_BINARY" in flags for flags in handle_flags))
        self.assertEqual(len(fdopen_modes), 3)
        self.assertTrue(all("b" in mode for mode in fdopen_modes))


class MissionBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        )
        self.base = Path(self.temporary_directory.name).resolve()
        self.project = self.base / "project"
        self.pool_root = self.base / "pool"
        self.project.mkdir()
        self.pool = Pool(self.pool_root)
        self.pool.initialize()
        self.task_text = "Explain bounded status; do not execute a shell"
        self.claim_path = self.pool.claim(
            "chat-a", self.task_text, self.project, "conversation"
        )
        supplied_fake = os.environ.get("AO_TEST_FAKE_MISSION")
        if os.name == "nt" and supplied_fake:
            self.executable = self.base / "ao-mission.exe"
            shutil.copy2(supplied_fake, self.executable)
        elif sys.platform == "darwin":
            self.executable = self.base / "ao-mission"
            source = self.base / "fake-mission.c"
            source.write_text(DARWIN_FAKE, encoding="utf-8")
            subprocess.run(
                ["clang", "-Wno-deprecated-declarations", str(source), "-o", str(self.executable)],
                check=True,
                capture_output=True,
            )
            self.malicious_executable = self.base / "malicious-mission"
            subprocess.run(
                [
                    "clang",
                    "-Wno-deprecated-declarations",
                    '-DPAYLOAD="malicious"',
                    str(source),
                    "-o",
                    str(self.malicious_executable),
                ],
                check=True,
                capture_output=True,
            )
        else:
            self.executable = self.base / "ao-mission"
            self.executable.write_text(FAKE, encoding="utf-8")
            self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.lock = self.base / "components.lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "components": [
                        {
                            "name": "ao-mission",
                            "asset": self.executable.name,
                            "sha256": digest,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.configuration = mock.patch.multiple(
            "internal.mission_bridge",
            MISSION_EXECUTABLE=self.executable,
            COMPONENT_LOCK=self.lock,
        )
        self.configuration.start()

    def tearDown(self):
        self.configuration.stop()
        self.temporary_directory.cleanup()

    def _replace_executable(self, body):
        replacement = self.executable.with_name("replacement-ao-mission")
        replacement.write_text(body, encoding="utf-8")
        replacement.chmod(replacement.stat().st_mode | stat.S_IXUSR)
        os.replace(replacement, self.executable)

    def _replace_verified_copy(self, verified):
        replacement = verified.path.with_name("replacement-verified-copy")
        shutil.copy2(self.malicious_executable, replacement)
        os.replace(replacement, verified.path)

    def _link_directory(self, link, target):
        if os.name == "nt":
            subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                check=True,
                capture_output=True,
            )
        else:
            link.symlink_to(target, target_is_directory=True)

    def _swap_directory(self, directory, outside):
        parked = directory.with_name(directory.name + "-parked")
        try:
            os.replace(directory, parked)
        except OSError:
            if os.name != "nt":
                raise
            return None
        self._link_directory(directory, outside)
        return parked

    def _replace_project_root(self):
        parked = self.project.with_name("project-authorized")
        try:
            os.replace(self.project, parked)
        except OSError:
            if os.name != "nt":
                raise
            return None
        self.project.mkdir()
        return parked

    def _assert_darwin_pre_resume_failure(self, fault=None, fdopen_failure=None):
        real_spawn = mission_bridge._darwin_spawn_suspended
        child = []
        continued = []
        pipe_wrapper_calls = 0

        def capture_spawn(*arguments):
            child.append(real_spawn(*arguments))
            return child[0]

        real_kill = os.kill

        def capture_signal(pid, sent_signal):
            if sent_signal == signal.SIGCONT:
                continued.append(pid)
            return real_kill(pid, sent_signal)

        real_fdopen = os.fdopen

        def inject_fdopen(descriptor, *arguments, **keywords):
            nonlocal pipe_wrapper_calls
            if child and descriptor in (
                child[0].stdout_descriptor,
                child[0].stderr_descriptor,
            ):
                pipe_wrapper_calls += 1
                if pipe_wrapper_calls == fdopen_failure:
                    raise OSError("injected pipe wrapper failure")
            return real_fdopen(descriptor, *arguments, **keywords)

        error = None
        try:
            with (
                mock.patch.object(
                    mission_bridge, "_darwin_spawn_suspended", capture_spawn
                ),
                mock.patch.object(*fault) if fault else nullcontext(),
                mock.patch.object(mission_bridge.os, "fdopen", inject_fdopen)
                if fdopen_failure
                else nullcontext(),
                mock.patch.object(mission_bridge.os, "kill", capture_signal),
            ):
                try:
                    start_or_resume(self.claim_path, self.task_text)
                except BaseException as caught:
                    error = caught
            descriptors = (
                child[0].stdout_descriptor,
                child[0].stderr_descriptor,
            )
            open_descriptors = tuple(
                self._descriptor_is_open(descriptor) for descriptor in descriptors
            )
            try:
                os.waitpid(child[0].pid, os.WNOHANG)
            except ChildProcessError:
                reaped = True
            else:
                reaped = False
            self.assertEqual(
                (
                    error.code
                    if isinstance(error, MissionBridgeError)
                    else type(error).__name__,
                    tuple(continued),
                    (self.project / ".ao/mission/payload-marker").exists(),
                    open_descriptors,
                    reaped,
                ),
                ("mission-launch-failed", (), False, (False, False), True),
            )
        finally:
            if child:
                mission_bridge._darwin_kill_wait(child[0].pid)
            for descriptor in (
                ()
                if not child
                else (
                    child[0].stdout_descriptor,
                    child[0].stderr_descriptor,
                )
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @staticmethod
    def _descriptor_is_open(descriptor):
        try:
            os.fstat(descriptor)
        except OSError:
            return False
        return True

    def test_local_schema_validator_supports_tracked_combinators_and_types(self):
        # MUTATION: treating bool as int or oneOf as anyOf accepts ambiguous records.
        schema = self.base / "local.schema.json"
        schema.write_text(
            json.dumps(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "minProperties": 3,
                    "maxProperties": 3,
                    "required": ["enabled", "values", "choice"],
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "values": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 2,
                            "items": {"type": ["string", "null"]},
                        },
                        "choice": {
                            "oneOf": [
                                {"type": "integer", "minimum": 1},
                                {"type": "string", "pattern": "^x"},
                            ]
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        valid = {"enabled": True, "values": ["x", None], "choice": 1}
        self.assertEqual(mission_bridge._validate_schema(valid, schema), valid)
        invalid = (
            {"enabled": True, "values": ["x"], "choice": True},
            {"enabled": True, "values": "x", "choice": 1},
            {"enabled": True, "values": [1], "choice": 1},
            {"enabled": True, "values": [], "choice": 1},
            {"enabled": True, "values": ["x", None, "y"], "choice": 1},
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                mission_bridge._validate_schema(value, schema)
        for value in (True, 1, [], "not-an-object"):
            with self.subTest(root=value), self.assertRaises(ValueError):
                mission_bridge._validate_schema(value, schema)

    def test_local_schema_validator_requires_exactly_one_oneof_branch(self):
        schema = self.base / "oneof.schema.json"
        schema.write_text(
            json.dumps(
                {
                    "oneOf": [
                        {"type": "integer"},
                        {"type": "integer", "minimum": 0},
                    ]
                }
            ),
            encoding="utf-8",
        )
        for value in (1, "not-an-integer"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mission_bridge._validate_schema(value, schema)

    def test_windows_job_assigns_suspended_process_before_resume(self):
        # MUTATION: resuming before assignment lets descendants escape cleanup.
        events = []

        class Function:
            def __init__(self, operation):
                self.operation = operation

            def __call__(self, *arguments):
                return self.operation(*arguments)

        class Kernel:
            def __init__(self):
                self.limit_information = b""
                self.CreateJobObjectW = Function(lambda *_: 101)
                self.SetInformationJobObject = Function(self.set_information)
                self.AssignProcessToJobObject = Function(self.assign)
                self.TerminateJobObject = Function(self.terminate)
                self.CloseHandle = Function(self.close)

            def set_information(self, _job, _kind, information, size):
                self.limit_information = ctypes.string_at(information, size)
                events.append("configured")
                return 1

            def assign(self, job, process):
                self.assigned = (job, process)
                events.append("assigned")
                return 1

            def terminate(self, job, code):
                self.terminated = (job, code)
                events.append("terminated")
                return 1

            def close(self, job):
                self.closed = job
                events.append("closed")
                return 1

        class Native:
            def __init__(self):
                self.NtResumeProcess = Function(self.resume)

            def resume(self, process):
                self.resumed = process
                events.append("resumed")
                return 0

        class Process:
            _handle = 202

        kernel = Kernel()
        native = Native()
        try:
            job = mission_bridge._windows_job(Process(), kernel, native)
        except AttributeError as error:
            self.fail(f"Windows Job Object helper unavailable: {error}")
        self.assertEqual(events, ["configured", "assigned", "resumed"])
        self.assertEqual(kernel.assigned, (101, 202))
        self.assertIn((0x2000).to_bytes(4, "little"), kernel.limit_information)
        self.assertTrue(job.terminate())
        job.close()
        self.assertEqual(events[-2:], ["terminated", "closed"])

    def test_windows_job_setup_baseexceptions_preserve_original_and_close_handle(self):
        # MUTATION: a cleanup failure masks assignment/resume/constructor aborts and leaks the job.
        class Function:
            def __init__(self, operation):
                self.operation = operation

            def __call__(self, *arguments):
                return self.operation(*arguments)

        for fault in ("assign", "resume", "constructor"):
            with self.subTest(fault=fault):
                events = []

                def assign(*_):
                    events.append("assigned")
                    if fault == "assign":
                        raise KeyboardInterrupt("assign original")
                    return 1

                def resume(*_):
                    events.append("resumed")
                    if fault == "resume":
                        raise KeyboardInterrupt("resume original")
                    return 0

                def terminate(*_):
                    events.append("terminated")
                    raise RuntimeError("secondary terminate failure")

                kernel = types.SimpleNamespace(
                    CreateJobObjectW=Function(lambda *_: 101),
                    SetInformationJobObject=Function(lambda *_: 1),
                    AssignProcessToJobObject=Function(assign),
                    TerminateJobObject=Function(terminate),
                    CloseHandle=Function(lambda *_: events.append("closed") or 1),
                )
                native = types.SimpleNamespace(NtResumeProcess=Function(resume))
                constructor = (
                    mock.patch.object(
                        mission_bridge,
                        "_WindowsJob",
                        side_effect=KeyboardInterrupt("constructor original"),
                    )
                    if fault == "constructor"
                    else nullcontext()
                )
                with constructor, self.assertRaisesRegex(
                    KeyboardInterrupt, rf"{fault} original"
                ):
                    mission_bridge._windows_job(
                        types.SimpleNamespace(_handle=202), kernel, native
                    )
                self.assertEqual(events[-2:], ["terminated", "closed"])

    def test_darwin_waitpid_cleanup_failure_preserves_original_and_closes_streams(self):
        # MUTATION: an unexpected cleanup waitpid error masks the pre-resume failure.
        streams = (io.BytesIO(), io.BytesIO())
        child = mission_bridge._DarwinChild(123, 10, 11)
        project = types.SimpleNamespace(descriptors=(20,))
        with (
            mock.patch.object(
                mission_bridge, "_darwin_spawn_suspended", return_value=child
            ),
            mock.patch.object(mission_bridge.os, "fdopen", side_effect=streams),
            mock.patch.object(
                mission_bridge,
                "_darwin_wait_stopped",
                side_effect=KeyboardInterrupt("pre-resume original"),
            ),
            mock.patch.object(mission_bridge.os, "killpg"),
            mock.patch.object(
                mission_bridge.os,
                "waitpid",
                side_effect=RuntimeError("secondary waitpid failure"),
            ) as waitpid,
            self.assertRaisesRegex(KeyboardInterrupt, "pre-resume original"),
        ):
            mission_bridge._run_darwin([], project, types.SimpleNamespace())
        waitpid.assert_called_once_with(child.pid, 0)
        self.assertTrue(all(stream.closed for stream in streams))

    def test_darwin_deadline_failure_happens_before_suspended_spawn(self):
        # MUTATION: calculating the deadline after spawn leaves a child unowned on abort.
        project = types.SimpleNamespace(descriptors=(20,))
        child = mission_bridge._DarwinChild(123, 10, 11)
        spawn = mock.Mock(return_value=child)
        with (
            mock.patch.object(
                mission_bridge.time,
                "monotonic",
                side_effect=KeyboardInterrupt("deadline original"),
            ),
            mock.patch.object(mission_bridge, "_darwin_spawn_suspended", spawn),
            mock.patch.object(
                mission_bridge.os, "fdopen", side_effect=(io.BytesIO(), io.BytesIO())
            ),
            mock.patch.object(mission_bridge, "_darwin_wait_stopped"),
            mock.patch.object(mission_bridge, "_darwin_verify_suspended"),
            mock.patch.object(mission_bridge.os, "kill"),
            self.assertRaisesRegex(KeyboardInterrupt, "deadline original"),
        ):
            mission_bridge._run_darwin([], project, types.SimpleNamespace())
        spawn.assert_not_called()

    def test_generic_and_windows_deadline_failure_happens_before_process_spawn(self):
        # MUTATION: calculating the deadline after Popen leaks the process or Windows job.
        executable = types.SimpleNamespace(
            launch_path="/proc/self/fd/10", descriptors=(10,)
        )
        for platform, name in (("linux", "posix"), ("win32", "nt")):
            with self.subTest(platform=platform):
                process = types.SimpleNamespace(
                    pid=123, stdout=io.BytesIO(), stderr=io.BytesIO()
                )
                popen = mock.Mock(return_value=process)
                with (
                    mock.patch.object(mission_bridge.sys, "platform", platform),
                    mock.patch.object(mission_bridge.os, "name", name),
                    mock.patch.object(
                        mission_bridge.time,
                        "monotonic",
                        side_effect=KeyboardInterrupt("deadline original"),
                    ),
                    mock.patch.object(mission_bridge.subprocess, "Popen", popen),
                    mock.patch.object(mission_bridge, "_windows_job"),
                    self.assertRaisesRegex(KeyboardInterrupt, "deadline original"),
                ):
                    mission_bridge._run_output([], self.project, executable)
                popen.assert_not_called()

    def test_windows_job_setup_abort_cleans_owned_process_resources(self):
        # MUTATION: catching only MissionBridgeError skips process cleanup on BaseException.
        events = []

        class Process:
            pid = 123
            stdout = io.BytesIO()
            stderr = io.BytesIO()

            def kill(self):
                events.append("killed")

            def wait(self, **_):
                events.append("waited")
                return -9

        process = Process()
        executable = types.SimpleNamespace(launch_path="ao2.exe", descriptors=())
        with (
            mock.patch.object(mission_bridge.sys, "platform", "win32"),
            mock.patch.object(mission_bridge.os, "name", "nt"),
            mock.patch.object(mission_bridge.subprocess, "Popen", return_value=process),
            mock.patch.object(
                mission_bridge,
                "_windows_job",
                side_effect=KeyboardInterrupt("job setup original"),
            ),
            self.assertRaisesRegex(KeyboardInterrupt, "job setup original"),
        ):
            mission_bridge._run_output([], self.project, executable)
        self.assertEqual(events, ["killed", "waited"])
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_windows_wait_abort_is_not_masked_by_job_close_failure(self):
        # MUTATION: final Job close replaces the initiating wait exception.
        events = []

        class Process:
            pid = 123
            stdout = io.BytesIO()
            stderr = io.BytesIO()

            def wait(self, **_):
                events.append("waited")
                if events.count("waited") == 1:
                    raise KeyboardInterrupt("wait original")
                return -9

            def kill(self):
                events.append("process-killed")

        class Job:
            def terminate(self):
                events.append("job-terminated")
                return True

            def close(self):
                events.append("job-closed")
                raise RuntimeError("secondary close failure")

        process = Process()
        executable = types.SimpleNamespace(launch_path="ao2.exe", descriptors=())
        with (
            mock.patch.object(mission_bridge.sys, "platform", "win32"),
            mock.patch.object(mission_bridge.os, "name", "nt"),
            mock.patch.object(mission_bridge.subprocess, "Popen", return_value=process),
            mock.patch.object(mission_bridge, "_windows_job", return_value=Job()),
            self.assertRaisesRegex(KeyboardInterrupt, "wait original"),
        ):
            mission_bridge._run_output([], self.project, executable)
        self.assertEqual(
            events, ["waited", "job-terminated", "waited", "job-closed"]
        )
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_starts_verified_mission_with_argument_array_and_project_owned_state(self):
        # MUTATION: shell=True would interpret the punctuation in the objective.
        before = {path.relative_to(self.project) for path in self.project.rglob("*")}
        readback = start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        self.assertEqual(readback.current_route, "ao-blueprint")
        self.assertFalse(readback.resumed)
        self.assertFalse(readback.executes_work)
        self.assertFalse(readback.approves_policy)
        self.assertFalse(readback.mutates_repositories)
        self.assertTrue(readback.record.is_relative_to(self.project / ".ao"))
        created = {path.relative_to(self.project) for path in self.project.rglob("*")} - before
        self.assertTrue(created)
        self.assertTrue(all(path.parts[0] == ".ao" for path in created))
        arguments = json.loads(
            (self.project / ".ao/mission/fake-arguments.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        self.assertEqual(arguments[0], "--home")
        expected_home = (
            ".ao/mission"
            if sys.platform == "darwin"
            else str(self.project / ".ao/mission")
        )
        if os.name == "nt":
            self.assertEqual(
                canonical_windows_path(arguments[1]),
                canonical_windows_path(expected_home),
            )
        else:
            self.assertEqual(arguments[1], expected_home)
        self.assertEqual(arguments[2:], ["start", self.task_text])
        recorded_cwd = (self.project / ".ao/mission/fake-cwd").read_text()
        if os.name == "nt":
            self.assertEqual(
                canonical_windows_path(recorded_cwd),
                canonical_windows_path(str(self.project)),
            )
        else:
            self.assertEqual(recorded_cwd, str(self.project))

    def test_authenticated_record_binds_current_route(self):
        # MUTATION: omitting the route leaves execution authority caller-forgeable.
        readback = start_or_resume(self.claim_path, self.task_text)
        record = json.loads(readback.record.read_text(encoding="utf-8"))
        self.assertEqual(record["current_route"], "ao-blueprint")

    def test_authenticated_route_tampering_is_rejected(self):
        # MUTATION: accepting a changed durable route bypasses the fixed route table.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["current_route"] = "ao-forge"
        readback.record.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_rejects_linked_project_private_storage(self):
        # MUTATION: lexical `.ao` containment writes through a link outside project.
        outside = self.base / "outside"
        outside.mkdir()
        self._link_directory(self.project / ".ao", outside)
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-storage-unsafe")
        self.assertEqual(list(outside.iterdir()), [])

    def test_record_write_retains_validated_storage_directory(self):
        # MUTATION: returning a checked path lets office-pool swap before record/HMAC writes.
        outside = self.base / "outside-record"
        outside.mkdir()
        real_private_file = mission_bridge._private_file
        parked = []

        def swap_after_open(project, directories, name):
            result = real_private_file(project, directories, name)
            if not parked:
                parked.append(
                    self._swap_directory(project.joinpath(*directories), outside)
                )
            return result

        with mock.patch.object(mission_bridge, "_private_file", swap_after_open):
            try:
                readback = start_or_resume(self.claim_path, self.task_text)
            except MissionBridgeError:
                readback = None
        self.assertEqual(list(outside.iterdir()), [])
        if readback is not None:
            self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        if os.name != "nt":
            self.assertIsNotNone(parked[0])

    def test_receipt_bound_project_root_is_retained_before_descendant_open(self):
        # MUTATION: receipt validation releases the root before private storage reopens it.
        real_private_directory = mission_bridge._private_directory
        parked = []

        def swap_before_descendant_open(project, *parts):
            if not parked:
                parked.append(self._replace_project_root())
            return real_private_directory(project, *parts)

        with mock.patch.object(
            mission_bridge, "_private_directory", swap_before_descendant_open
        ):
            try:
                start_or_resume(self.claim_path, self.task_text)
            except MissionBridgeError:
                pass
        if parked[0] is None:
            self.assertEqual(os.name, "nt")
        else:
            self.assertEqual(list(self.project.iterdir()), [])

    def test_mission_home_retains_validated_directory_through_launch(self):
        # MUTATION: passing the checked Mission home pathname follows a swap at launch.
        outside = self.base / "outside-home"
        outside.mkdir()
        real_run = mission_bridge._run
        parked = []

        def swap_before_launch(*arguments, **keywords):
            if not parked:
                parked.append(
                    self._swap_directory(self.project / ".ao/mission", outside)
                )
            return real_run(*arguments, **keywords)

        with mock.patch.object(mission_bridge, "_run", swap_before_launch):
            try:
                readback = start_or_resume(self.claim_path, self.task_text)
            except MissionBridgeError:
                readback = None
        self.assertEqual(list(outside.iterdir()), [])
        if readback is not None:
            self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        if os.name != "nt":
            self.assertIsNotNone(parked[0])

    def test_verified_open_executable_survives_path_substitution(self):
        # MUTATION: hashing then reopening the executable launches substituted bytes.
        malicious = FAKE.replace(
            'mission_id = "mission-0123456789abcdef"',
            'mission_id = "mission-fedcba9876543210"',
        )
        with mission_bridge._open_verified_executable() as verified:
            if os.name == "nt":
                with self.assertRaises(OSError):
                    self._replace_executable(malicious)
            elif sys.platform == "darwin":
                source_replacement = self.executable.with_name("source-replacement")
                shutil.copy2(self.malicious_executable, source_replacement)
                os.replace(source_replacement, self.executable)
            else:
                self._replace_executable(malicious)
            if sys.platform == "darwin":
                with mission_bridge._private_directory(
                    self.project, ".ao", "mission"
                ) as retained:
                    value = mission_bridge._run(
                        ["--home", ".ao/mission", "start", self.task_text],
                        retained,
                        verified,
                    )
            else:
                value = mission_bridge._run(
                    ["--home", str(self.project / ".ao/mission"), "start", self.task_text],
                    self.project,
                    verified,
                )
        self.assertEqual(value["mission_id"], "mission-0123456789abcdef")

    @unittest.skipIf(os.name == "nt", "descriptor execution is POSIX-specific")
    def test_launch_uses_verified_descriptor_after_private_copy_substitution(self):
        # MUTATION: executing the verified copy pathname reopens attacker replacement bytes.
        malicious = FAKE.replace(
            'mission_id = "mission-0123456789abcdef"',
            'mission_id = "mission-fedcba9876543210"',
        )
        with mission_bridge._open_verified_executable() as verified:
            replacement = verified.path.with_name("replacement-verified-copy")
            replacement.write_text(malicious, encoding="utf-8")
            replacement.chmod(replacement.stat().st_mode | stat.S_IXUSR)
            os.replace(replacement, verified.path)
            try:
                value = mission_bridge._run(
                    ["--home", str(self.project / ".ao/mission"), "start", self.task_text],
                    self.project,
                    verified,
                )
            except MissionBridgeError as error:
                self.assertEqual(error.code, "mission-launch-failed")
            else:
                self.assertEqual(value["mission_id"], "mission-0123456789abcdef")

    @unittest.skipUnless(sys.platform == "darwin", "suspended spawn is Darwin-specific")
    def test_darwin_pre_spawn_entry_replacement_never_resumes(self):
        # MUTATION: pathname-spawning without loaded-vnode proof runs substituted bytes.
        real_spawn = mission_bridge._darwin_spawn_suspended

        def replace_before_spawn(arguments, project_descriptor, executable):
            self._replace_verified_copy(executable)
            return real_spawn(arguments, project_descriptor, executable)

        with mock.patch.object(
            mission_bridge,
            "_darwin_spawn_suspended",
            replace_before_spawn,
        ):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-launch-failed")
        self.assertFalse((self.project / ".ao/mission/payload-marker").exists())

    @unittest.skipUnless(sys.platform == "darwin", "suspended spawn is Darwin-specific")
    def test_darwin_partial_region_enumeration_failure_never_resumes(self):
        # MUTATION: any libproc error after one matching main region is normal end.
        real_libraries = mission_bridge._darwin_libraries

        class PartialFailure:
            def __init__(self, process):
                self.process = process
                self.matched = False

            def __getattr__(self, name):
                return getattr(self.process, name)

            def proc_pidinfo(self, pid, flavor, address, buffer, size):
                if flavor == 8 and self.matched:
                    ctypes.set_errno(errno.EIO)
                    return 0
                result = self.process.proc_pidinfo(
                    pid, flavor, address, buffer, size
                )
                if flavor == 8 and result == size:
                    region = ctypes.cast(
                        buffer, ctypes.POINTER(mission_bridge._DarwinRegionPath)
                    ).contents
                    path = bytes(region.vnode.path).split(b"\0", 1)[0]
                    if path and region.region.protection & 0x4:
                        process_path = ctypes.create_string_buffer(4096)
                        self.process.proc_pidpath(
                            pid, process_path, ctypes.sizeof(process_path)
                        )
                        if path == process_path.value:
                            self.matched = True
                return result

        def partial_libraries():
            system, process = real_libraries()
            return system, PartialFailure(process)

        self._assert_darwin_pre_resume_failure(
            (mission_bridge, "_darwin_libraries", partial_libraries)
        )

    @unittest.skipUnless(sys.platform == "darwin", "suspended spawn is Darwin-specific")
    def test_darwin_first_pipe_wrapper_failure_never_resumes(self):
        # MUTATION: first fdopen failure escapes before child ownership cleanup.
        self._assert_darwin_pre_resume_failure(fdopen_failure=1)

    @unittest.skipUnless(sys.platform == "darwin", "suspended spawn is Darwin-specific")
    def test_darwin_second_pipe_wrapper_failure_never_resumes(self):
        # MUTATION: second fdopen failure leaks first wrapper and stopped child.
        self._assert_darwin_pre_resume_failure(fdopen_failure=2)

    @unittest.skipUnless(sys.platform == "darwin", "suspended spawn is Darwin-specific")
    def test_darwin_post_spawn_entry_replacement_runs_loaded_verified_vnode(self):
        # MUTATION: rechecking the pathname instead of the loaded vnode rejects or runs wrong bytes.
        real_verify = mission_bridge._darwin_verify_suspended
        swapped = []

        def replace_after_spawn(pid, project_descriptor, executable):
            if not swapped:
                self._replace_verified_copy(executable)
                swapped.append(True)
            return real_verify(pid, project_descriptor, executable)

        with mock.patch.object(
            mission_bridge,
            "_darwin_verify_suspended",
            replace_after_spawn,
        ):
            readback = start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        self.assertEqual(
            (self.project / ".ao/mission/payload-marker").read_text(),
            "benign\n",
        )

    @unittest.skipUnless(sys.platform == "darwin", "suspended spawn is Darwin-specific")
    def test_darwin_suspended_child_retains_project_cwd_and_relative_home(self):
        # MUTATION: pathname cwd/home follows a replacement project root after spawn.
        real_verify = mission_bridge._darwin_verify_suspended
        parked = []

        def replace_project_after_spawn(pid, project_descriptor, executable):
            if not parked:
                parked.append(self._replace_project_root())
            return real_verify(pid, project_descriptor, executable)

        with mock.patch.object(
            mission_bridge,
            "_darwin_verify_suspended",
            replace_project_after_spawn,
        ):
            readback = start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(readback.mission_id, "mission-0123456789abcdef")
        self.assertEqual(list(self.project.iterdir()), [])
        self.assertEqual(
            (parked[0] / ".ao/mission/payload-marker").read_text(),
            "benign\n",
        )

    def test_same_receipt_and_objective_resume_exact_mission(self):
        # MUTATION: always starting creates duplicate Mission records for one task.
        first = start_or_resume(self.claim_path, self.task_text)
        second = start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(second.mission_id, first.mission_id)
        self.assertTrue(second.resumed)
        calls = [
            json.loads(line)
            for line in (self.project / ".ao/mission/fake-arguments.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(calls[1][-5:], ["mission", "inspect", "--mission", first.mission_id, "--json"])

    def test_same_objective_different_chats_have_distinct_records(self):
        # MUTATION: task-digest-only names collide for independent chat authorities.
        other = self.pool.claim("chat-b", self.task_text, self.project, "conversation")
        first = start_or_resume(self.claim_path, self.task_text)
        second = start_or_resume(other, self.task_text)
        self.assertNotEqual(first.record, second.record)
        self.assertFalse(second.resumed)

    def test_resume_rejects_inspect_mission_identity_substitution(self):
        # MUTATION: trusting inspect readback permits a different Mission identity.
        first = start_or_resume(self.claim_path, self.task_text)
        with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": "inspect-mismatch"}):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")
        self.assertEqual(
            json.loads(first.record.read_text(encoding="utf-8"))["mission_id"],
            first.mission_id,
        )

    def test_rejects_wrong_objective_or_receipt_before_launch(self):
        # MUTATION: trusting caller text permits cross-task Mission reuse.
        other = self.pool.claim("chat-b", "other objective", self.project, "conversation")
        for receipt, objective in (
            (self.claim_path, "changed objective"),
            (other, self.task_text),
        ):
            with self.subTest(authority_name=receipt.name, task_text=objective):
                with self.assertRaises(MissionBridgeError) as raised:
                    start_or_resume(receipt, objective)
                self.assertEqual(raised.exception.code, "task-mismatch")

    def test_rejects_executable_digest_mismatch_without_creating_mission_state(self):
        # MUTATION: checking only the executable name accepts substituted bytes.
        self.executable.write_text(FAKE + "# substitution\n", encoding="utf-8")
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-identity-mismatch")
        self.assertFalse((self.project / ".ao").exists())

    def test_rejects_unbounded_or_authority_escalating_readback(self):
        # MUTATION: accepting arbitrary stdout or true authority flags widens Mission.
        escalation = FAKE.replace(
            '"current_route": "ao-blueprint"',
            '"current_route": "ao-blueprint", "executes_work": True',
        )
        for body, code in (
            (escalation, "mission-authority-escalation"),
            ('#!/usr/bin/env python3\nprint("x" * 70000)\n', "mission-output-too-large"),
        ):
            with self.subTest(code=code):
                mode = "escalation" if code.endswith("escalation") else "large"
                if os.name != "nt" and sys.platform != "darwin":
                    self.executable.write_text(body, encoding="utf-8")
                    self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
                    digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
                    value = json.loads(self.lock.read_text(encoding="utf-8"))
                    value["components"][0]["sha256"] = digest
                    self.lock.write_text(json.dumps(value), encoding="utf-8")
                with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": mode}):
                    with self.assertRaises(MissionBridgeError) as raised:
                        start_or_resume(self.claim_path, self.task_text)
                self.assertEqual(raised.exception.code, code)

    def test_terminates_oversized_output_while_process_is_running(self):
        # MUTATION: checking temporary-file size after exit waits for an abusive child.
        if os.name != "nt" and sys.platform != "darwin":
            self.executable.write_text(FAKE, encoding="utf-8")
            self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
            value = json.loads(self.lock.read_text(encoding="utf-8"))
            value["components"][0]["sha256"] = hashlib.sha256(
                self.executable.read_bytes()
            ).hexdigest()
            self.lock.write_text(json.dumps(value), encoding="utf-8")
        started = time.monotonic()
        with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": "slow-large"}):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-output-too-large")
        self.assertLess(time.monotonic() - started, 5)

    def test_record_digest_detects_private_state_tampering(self):
        # MUTATION: resuming without checking the wrapper record accepts field edits.
        readback = start_or_resume(self.claim_path, self.task_text)
        record = json.loads(readback.record.read_text(encoding="utf-8"))
        record["office_id"] = "O5"
        readback.record.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_recomputable_digest_cannot_forge_record_authentication(self):
        # MUTATION: an unkeyed adjacent digest lets an editor reseal altered state.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["mission_status"] = "complete"
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        readback.record.write_bytes(raw)
        readback.record.with_suffix(".hmac").write_text(
            hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii"
        )
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_production_rejects_schema_invalid_record_even_with_valid_hmac(self):
        # MUTATION: treating the schema as documentation accepts invalid Mission IDs.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["mission_id"] = "invalid"
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        readback.record.write_bytes(raw)
        readback.record.with_suffix(".hmac").write_text(
            hmac.new(self.claim_path.read_bytes(), raw, hashlib.sha256).hexdigest() + "\n",
            encoding="ascii",
        )
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_production_distinguishes_json_boolean_from_integer_const(self):
        # MUTATION: Python equality treats true as the schema_version integer 1.
        readback = start_or_resume(self.claim_path, self.task_text)
        value = json.loads(readback.record.read_text(encoding="utf-8"))
        value["schema_version"] = True
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        readback.record.write_bytes(raw)
        readback.record.with_suffix(".hmac").write_text(
            hmac.new(self.claim_path.read_bytes(), raw, hashlib.sha256).hexdigest() + "\n",
            encoding="ascii",
        )
        with self.assertRaises(MissionBridgeError) as raised:
            start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "mission-record-mismatch")

    def test_rejects_schema_invalid_initial_mission_readback(self):
        # MUTATION: loose string checks persist an invalid Mission identifier.
        with mock.patch.dict(os.environ, {"AO_TEST_FAKE_MODE": "invalid-id"}):
            with self.assertRaises(MissionBridgeError) as raised:
                start_or_resume(self.claim_path, self.task_text)
        self.assertEqual(raised.exception.code, "invalid-mission-readback")

    def test_mission_record_schema_has_exact_persisted_shape(self):
        # MUTATION: an open schema permits unreviewed authority fields in durable state.
        record = start_or_resume(self.claim_path, self.task_text).record
        value = json.loads(record.read_text(encoding="utf-8"))
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/mission-record.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(value), set(schema["required"]))
        self.assertEqual(set(value), set(schema["properties"]))


if __name__ == "__main__":
    unittest.main()
