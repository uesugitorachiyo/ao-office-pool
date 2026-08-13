import hashlib
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import types
import unittest
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from unittest import mock

import internal.execution as execution_module
import internal.mission_bridge as mission_bridge
from internal.execution import ExecutionError, execute
from internal.governance_witness import issue_witness
from tests import test_governance_witness as witness_tests


FAKE_AO2 = r'''
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <direct.h>
#define environ _environ
#define task_sleep(seconds) Sleep((seconds) * 1000)
#define task_getcwd _getcwd
#define task_mkdir(path) _mkdir(path)
#else
#include <sys/stat.h>
#include <unistd.h>
#define task_sleep(seconds) sleep(seconds)
#define task_getcwd getcwd
#define task_mkdir(path) mkdir(path, 0700)
#endif

#ifndef _WIN32
extern char **environ;
#endif

#ifndef PAYLOAD
#define PAYLOAD "benign"
#endif

static const char *argument_value(int argc, char **argv, const char *name) {
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], name) == 0) return argv[i + 1];
  }
  return NULL;
}

static int path_separator(char value) {
#ifdef _WIN32
  return value == '/' || value == '\\';
#else
  return value == '/';
#endif
}

static int make_directory(const char *path) {
  return task_mkdir(path) == 0 || errno == EEXIST ? 0 : -1;
}

static int make_directories(const char *path) {
  char copy[4096];
  size_t length = strlen(path);
  if (length == 0 || length >= sizeof(copy)) return -1;
  memcpy(copy, path, length + 1);
  char *cursor = copy;
#ifdef _WIN32
  if (length >= 3 && copy[1] == ':' && path_separator(copy[2])) {
    cursor = copy + 3;
  } else if (length >= 2 && path_separator(copy[0]) && path_separator(copy[1])) {
    cursor = copy + 2;
    for (int component = 0; component < 2; component++) {
      while (*cursor && !path_separator(*cursor)) cursor++;
      while (path_separator(*cursor)) cursor++;
    }
  }
#else
  while (path_separator(*cursor)) cursor++;
#endif
  for (; *cursor; cursor++) {
    if (!path_separator(*cursor)) continue;
    char separator = *cursor;
    *cursor = '\0';
    if (make_directory(copy) != 0) return -1;
    *cursor = separator;
    while (path_separator(cursor[1])) cursor++;
  }
  return make_directory(copy);
}

static int write_bytes(const char *path, const char *value) {
  FILE *stream = fopen(path, "wb");
  if (!stream) return -1;
  size_t size = strlen(value);
  int written = fwrite(value, 1, size, stream) == size;
  return fclose(stream) == 0 && written ? 0 : -1;
}

static int read_bytes(const char *path, char *value, size_t capacity) {
  FILE *stream = fopen(path, "rb");
  if (!stream) return -1;
  size_t count = fread(value, 1, capacity - 1, stream);
  int failed = ferror(stream);
  if (fclose(stream) != 0) failed = 1;
  if (failed) return -1;
  value[count] = '\0';
  return 0;
}

static void write_json_string(FILE *stream, const char *value) {
  fputc('"', stream);
  for (const unsigned char *byte = (const unsigned char *)value; *byte; byte++) {
    switch (*byte) {
      case '"': fputs("\\\"", stream); break;
      case '\\': fputs("\\\\", stream); break;
      case '\b': fputs("\\b", stream); break;
      case '\f': fputs("\\f", stream); break;
      case '\n': fputs("\\n", stream); break;
      case '\r': fputs("\\r", stream); break;
      case '\t': fputs("\\t", stream); break;
      default:
        if (*byte < 0x20) fprintf(stream, "\\u%04x", *byte);
        else fputc(*byte, stream);
    }
  }
  fputc('"', stream);
}

typedef struct {
  uint8_t data[64];
  uint32_t data_size;
  uint64_t bit_size;
  uint32_t state[8];
} sha256_context;

static const uint32_t sha256_rounds[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotate_right(uint32_t value, uint32_t count) {
  return (value >> count) | (value << (32 - count));
}

static void sha256_transform(sha256_context *context, const uint8_t data[64]) {
  uint32_t words[64], a, b, c, d, e, f, g, h;
  for (int i = 0, j = 0; i < 16; i++, j += 4) {
    words[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
      ((uint32_t)data[j + 2] << 8) | data[j + 3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t first = rotate_right(words[i - 15], 7) ^
      rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3);
    uint32_t second = rotate_right(words[i - 2], 17) ^
      rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10);
    words[i] = words[i - 16] + first + words[i - 7] + second;
  }
  a = context->state[0]; b = context->state[1]; c = context->state[2];
  d = context->state[3]; e = context->state[4]; f = context->state[5];
  g = context->state[6]; h = context->state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t choice = (e & f) ^ (~e & g);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t first = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    uint32_t second = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    uint32_t temporary_one = h + first + choice + sha256_rounds[i] + words[i];
    uint32_t temporary_two = second + majority;
    h = g; g = f; f = e; e = d + temporary_one;
    d = c; c = b; b = a; a = temporary_one + temporary_two;
  }
  context->state[0] += a; context->state[1] += b; context->state[2] += c;
  context->state[3] += d; context->state[4] += e; context->state[5] += f;
  context->state[6] += g; context->state[7] += h;
}

static void sha256_init(sha256_context *context) {
  context->data_size = 0;
  context->bit_size = 0;
  context->state[0] = 0x6a09e667; context->state[1] = 0xbb67ae85;
  context->state[2] = 0x3c6ef372; context->state[3] = 0xa54ff53a;
  context->state[4] = 0x510e527f; context->state[5] = 0x9b05688c;
  context->state[6] = 0x1f83d9ab; context->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_context *context, const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; i++) {
    context->data[context->data_size++] = data[i];
    if (context->data_size == 64) {
      sha256_transform(context, context->data);
      context->bit_size += 512;
      context->data_size = 0;
    }
  }
}

static void sha256_final(sha256_context *context, uint8_t hash[32]) {
  uint32_t size = context->data_size;
  context->data[size++] = 0x80;
  if (size > 56) {
    while (size < 64) context->data[size++] = 0;
    sha256_transform(context, context->data);
    size = 0;
  }
  while (size < 56) context->data[size++] = 0;
  context->bit_size += (uint64_t)context->data_size * 8;
  for (int i = 0; i < 8; i++) {
    context->data[63 - i] = (uint8_t)(context->bit_size >> (i * 8));
  }
  sha256_transform(context, context->data);
  for (int i = 0; i < 4; i++) {
    for (int state = 0; state < 8; state++) {
      hash[i + state * 4] = (uint8_t)(context->state[state] >> (24 - i * 8));
    }
  }
}

static int mission_digest(const char *value, char output[72]) {
  unsigned char raw[32];
  sha256_context context;
  sha256_init(&context);
  sha256_update(&context, (const uint8_t *)value, strlen(value));
  sha256_final(&context, raw);
  strcpy(output, "sha256:");
  for (int i = 0; i < 32; i++) sprintf(output + 7 + i * 2, "%02x", raw[i]);
  return 0;
}

static int fake_mission(int argc, char **argv) {
  const char *mode = getenv("AO_TEST_FAKE_MODE");
  if (mode && (strcmp(mode, "large") == 0 || strcmp(mode, "slow-large") == 0)) {
    char block[1000]; memset(block, 'x', sizeof(block));
    for (int i = 0; i < 70; i++) fwrite(block, 1, sizeof(block), stdout);
    fflush(stdout);
    if (strcmp(mode, "slow-large") == 0) task_sleep(10);
    return 0;
  }
  const char *home = argument_value(argc, argv, "--home");
  if (!home) return 64;
  if (make_directories(home) != 0) return 65;
  char path[4096], cwd[4096], objective[72];
  char mission[64] = "mission-0123456789abcdef";
  snprintf(path, sizeof(path), "%s/payload-marker", home);
  if (write_bytes(path, PAYLOAD "\n") != 0) return 65;
  snprintf(path, sizeof(path), "%s/fake-cwd", home);
  if (!task_getcwd(cwd, sizeof(cwd)) || write_bytes(path, cwd) != 0) return 66;
  snprintf(path, sizeof(path), "%s/fake-arguments.jsonl", home);
  FILE *log = fopen(path, "ab");
  if (!log) return 67;
  fputc('[', log);
  for (int i = 1; i < argc; i++) {
    if (i > 1) fputc(',', log);
    write_json_string(log, argv[i]);
  }
  fputs("]\n", log);
  if (fclose(log) != 0) return 67;
  int inspect = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "inspect") == 0) inspect = 1;
    if (strcmp(argv[i], "--mission") == 0 && i + 1 < argc) {
      snprintf(mission, sizeof(mission), "%s", argv[i + 1]);
    }
  }
  snprintf(path, sizeof(path), "%s/objective-digest", home);
  if (inspect) {
    if (read_bytes(path, objective, sizeof(objective)) != 0) return 68;
    if (mode && strcmp(mode, "inspect-mismatch") == 0) {
      strcpy(mission, "mission-fedcba9876543210");
    }
  } else {
    if (mission_digest(argv[argc - 1], objective) != 0) return 69;
    if (write_bytes(path, objective) != 0) return 69;
  }
  if (strcmp(PAYLOAD, "malicious") == 0) strcpy(mission, "mission-fedcba9876543210");
  if (mode && strcmp(mode, "invalid-id") == 0) strcpy(mission, "mission-not-valid");
  const char *escalation =
    mode && strcmp(mode, "escalation") == 0 ? ",\"executes_work\":true" : "";
  printf(
    "{\"mission_id\":\"%s\",\"objective_digest\":\"%s\","
    "\"status\":\"active\",\"current_route\":\"ao-blueprint\"%s}\n",
    mission, objective, escalation
  );
  return 0;
}

int main(int argc, char **argv) {
  if (argument_value(argc, argv, "--home")) return fake_mission(argc, argv);
  const char *target = NULL, *run = NULL;
  char mode_buffer[64] = {0};
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], "--target") == 0) target = argv[i + 1];
    if (strcmp(argv[i], "--run-id") == 0) run = argv[i + 1];
  }
  if (argc < 3 || !target || !run) return 64;
  FILE *mode_file = fopen("ao2-mode", "rb");
  if (mode_file) {
    fread(mode_buffer, 1, sizeof(mode_buffer) - 1, mode_file);
    fclose(mode_file);
  }
  const char *mode = mode_buffer[0] ? mode_buffer : NULL;
  FILE *environment = fopen("ao2-environment.txt", "wb");
  if (!environment) return 72;
  const char *environment_names[] = {
    "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "PYTHONPATH"
  };
  for (int i = 0; i < 3; i++) {
    if (getenv(environment_names[i])) fprintf(environment, "%s\n", environment_names[i]);
  }
  for (char **entry = environ; *entry; entry++) {
    if (strncmp(*entry, "AO_TEST_", 8) == 0) fprintf(environment, "%s\n", *entry);
  }
  fclose(environment);
  if (mode && (strcmp(mode, "child-timeout") == 0 || strcmp(mode, "child-large") == 0)) {
#ifdef _WIN32
    STARTUPINFOA startup;
    PROCESS_INFORMATION child;
    char executable[MAX_PATH];
    char command[] = "ping.exe -n 31 127.0.0.1";
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&child, sizeof(child));
    startup.cb = sizeof(startup);
    if (!GetSystemDirectoryA(executable, sizeof(executable)) || strlen(executable) + strlen("\\ping.exe") >= sizeof(executable)) return 71;
    strcat(executable, "\\ping.exe");
    if (!CreateProcessA(executable, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &child)) return 71;
    FILE *pid_file = fopen("ao2-child-pid", "wb");
    if (pid_file) { fprintf(pid_file, "%lu", (unsigned long)child.dwProcessId); fclose(pid_file); }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    Sleep(50);
    if (strcmp(mode, "child-timeout") == 0) task_sleep(30);
#else
    pid_t child = fork();
    if (child < 0) return 71;
    if (child == 0) {
      FILE *pid_file = fopen("ao2-child-pid", "wb");
      if (pid_file) { fprintf(pid_file, "%d", getpid()); fclose(pid_file); }
      close(1); close(2); sleep(30); return 0;
    }
    usleep(50000);
    if (strcmp(mode, "child-timeout") == 0) task_sleep(30);
#endif
    char output[70000]; memset(output, 'x', sizeof(output));
    fwrite(output, 1, sizeof(output), stdout); fflush(stdout); task_sleep(30);
  }
  FILE *arguments = fopen("ao2-arguments.txt", "wb");
  if (!arguments) return 65;
  for (int i = 1; i < argc; i++) fprintf(arguments, "%s\n", argv[i]);
  fclose(arguments);
  FILE *workflow = fopen(argv[2], "rb");
  FILE *workflow_copy = fopen("ao2-workflow.txt", "wb");
  if (!workflow || !workflow_copy) return 66;
  int byte;
  while ((byte = fgetc(workflow)) != EOF) fputc(byte, workflow_copy);
  fclose(workflow); fclose(workflow_copy);
  FILE *out = fopen("ao2-output.txt", "wb");
  if (!out) return 67;
  fputs("executed\n", out);
  fclose(out);
  if (mode && strcmp(mode, "native-readback") == 0) {
    printf("run_id=%s\nstatus=Accepted\nrun_record=ignored\nevidence_dir=ignored\nreplay_state=accepted\nevidence_pack=ignored\nreport=ignored\n", run);
    return 0;
  }
  if (mode && strcmp(mode, "json-list") == 0) { puts("[]"); return 0; }
  if (mode && strcmp(mode, "wrong-types") == 0) {
    printf("{\"status\":1,\"run_id\":%s}\n", "true"); return 0;
  }
  if (mode && strcmp(mode, "invalid-utf8") == 0) {
    fputc(0xff, stdout); return 0;
  }
  printf("{\"status\":\"accepted\",\"run_id\":\"%s\"}\n", run);
  return 0;
}
'''


@unittest.skipIf(
    os.name == "nt" and not os.environ.get("AO_TEST_FAKE_AO2"),
    "native fake AO2 required",
)
class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.harness = witness_tests.GovernanceWitnessTests(
            "test_consumption_is_atomic_and_one_use"
        )
        self.harness.setUp()
        self.addCleanup(self.harness.tearDown)
        self.base = self.harness.base
        self.project = self.harness.project
        self.pool = self.harness.pool
        self.claim_path = self.harness.claim_path
        runtime = (
            self.harness.pool_root
            / "offices"
            / self.harness.authority["office_id"]
            / "runtime"
            / "versions"
            / "test-runtime"
        )
        runtime.mkdir(parents=True)
        self.executable = runtime / ("ao2.exe" if os.name == "nt" else "ao2")
        supplied = os.environ.get("AO_TEST_FAKE_AO2")
        if supplied:
            shutil.copy2(supplied, self.executable)
        else:
            self._compile(FAKE_AO2, self.executable)
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)
        self.executable_digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        for component in self.harness.components:
            if component["name"] == "ao2":
                component["sha256"] = self.executable_digest
        self.harness._write_lock()
        covenant = json.loads(self.harness.covenant.read_text(encoding="utf-8"))
        covenant["ao2_sha256"] = self.executable_digest
        self.harness.covenant.write_text(json.dumps(covenant), encoding="utf-8")
        self.malicious = self.base / ("malicious.exe" if os.name == "nt" else "malicious")
        if supplied:
            shutil.copy2(supplied, self.malicious)
        else:
            self._compile(
                FAKE_AO2.replace('fputs("executed\\n", out);', 'fputs("substituted\\n", out);'),
                self.malicious,
            )
        self.malicious.chmod(self.malicious.stat().st_mode | stat.S_IXUSR)
        self.envelope = self._witness()

    def _compile(self, source: str, output: Path) -> None:
        source_path = self.base / (output.stem + "-source.c")
        source_path.write_text(source, encoding="utf-8")
        subprocess.run(["cc", str(source_path), "-o", str(output)], check=True)

    def _witness(self) -> Path:
        return issue_witness(
            self.claim_path,
            self.harness.task_text,
            self.harness.valid_artifacts(),
        )

    def _set_ao2_mode(self, mode: str) -> None:
        (self.project / "ao2-mode").write_text(mode, encoding="utf-8")

    def _replace_verified_copy(self, verified) -> None:
        replacement = verified.path.with_name("replacement-" + verified.path.name)
        shutil.copy2(self.malicious, replacement)
        os.replace(replacement, verified.path)

    def _replace_workflow_stage(self) -> None:
        staging_directory = (
            self.project
            / ".ao"
            / "governance"
            / "office-pool"
            / "staging"
        )
        digest = hashlib.sha256(self.harness.workflow.read_bytes()).hexdigest()
        staging = next(staging_directory.glob(f"{digest}-*"))
        replacement = staging.with_name("replacement-workflow")
        replacement.write_text("name: substituted\n", encoding="utf-8")
        os.replace(replacement, staging)

    def _assert_child_dead(self) -> None:
        child = int((self.project / "ao2-child-pid").read_text(encoding="utf-8"))
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            library = ctypes.WinDLL("kernel32", use_last_error=True)
            library.OpenProcess.argtypes = (
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            )
            library.OpenProcess.restype = wintypes.HANDLE
            library.CloseHandle.argtypes = (wintypes.HANDLE,)
            library.CloseHandle.restype = wintypes.BOOL
            handle = library.OpenProcess(0x00100000, False, child)
            if handle:
                self.assertTrue(library.CloseHandle(handle))
                self.fail(f"descendant {child} survived cleanup")
            self.assertEqual(
                ctypes.get_last_error(),
                87,
                f"descendant {child} lookup failed unexpectedly",
            )
            return
        try:
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass

    @property
    def _execution_records(self) -> Path:
        return self.project / ".ao" / "evidence" / "office-pool"

    @contextmanager
    def _during_record_readback(self, mutate):
        before = set(self._execution_records.glob("execution-*.json"))
        real_read = os.read
        mutated = False

        def mutate_then_read(descriptor, amount):
            nonlocal mutated
            created = set(self._execution_records.glob("execution-*.json")) - before
            if created and not mutated:
                mutated = True
                mutate(next(iter(created)), descriptor, amount)
            return real_read(descriptor, amount)

        with mock.patch.object(execution_module.os, "read", mutate_then_read):
            yield

    def _assert_accepted_completed_record(self, result) -> None:
        record = json.loads(result.record.read_text(encoding="utf-8"))
        self.assertEqual(result.status, "accepted")
        self.assertEqual(record["phase"], "completed")
        self.assertEqual(record["request_digest"], result.request_digest)
        self.assertEqual(record["ao2_sha256"], self.executable_digest)
        self.assertEqual(
            record["authority_digest"],
            hashlib.sha256(self.harness.authority_raw).hexdigest(),
        )

    def test_executes_only_envelope_bound_objects_and_relative_target(self):
        # MUTATION: reopening caller paths exposes absolute workflow/target pathnames.
        result = execute(self.claim_path, self.envelope, timeout_seconds=30)
        self.assertEqual(result.status, "accepted")
        arguments = (self.project / "ao2-arguments.txt").read_text().splitlines()
        self.assertEqual(arguments[0], "run")
        self.assertEqual(arguments[2:], ["--target", ".", "--run-id", self.harness.run_id])
        if os.name == "nt":
            digest = hashlib.sha256(self.harness.workflow.read_bytes()).hexdigest()
            self.assertRegex(Path(arguments[1]).name, rf"^{digest}-[0-9a-f]{{32}}$")
        else:
            self.assertTrue(
                arguments[1].startswith(
                    "/dev/fd/" if sys.platform == "darwin" else "/proc/self/fd/"
                ),
                arguments[1],
            )
        self.assertEqual((self.project / "ao2-workflow.txt").read_bytes(), self.harness.workflow.read_bytes())
        record = json.loads(result.record.read_text(encoding="utf-8"))
        self.assertEqual(record["request_digest"], result.request_digest)
        self.assertEqual(record["ao2_sha256"], self.executable_digest)
        self.assertNotIn("stdout", record)

    def test_verified_ao2_path_replacement_never_runs_substituted_bytes(self):
        # MUTATION: pathname launch after verification runs attacker replacement bytes.
        real_run = mission_bridge._run_output

        def replace_then_run(arguments, project, executable, **options):
            try:
                self._replace_verified_copy(executable)
            except OSError:
                pass
            return real_run(arguments, project, executable, **options)

        with mock.patch.object(execution_module, "_run_output", replace_then_run):
            if sys.platform == "darwin":
                with self.assertRaises(ExecutionError) as raised:
                    execute(self.claim_path, self.envelope)
                self.assertEqual(raised.exception.code, "execution-launch-failed")
            else:
                execute(self.claim_path, self.envelope)
        output = self.project / "ao2-output.txt"
        self.assertFalse(output.exists() and output.read_text() == "substituted\n")

    def test_project_delete_recreate_never_redirects_child_cwd(self):
        # MUTATION: pathname cwd after verification redirects AO2 into a replacement project.
        parked = self.project.with_name("retained-project")

        def replace_project():
            try:
                os.replace(self.project, parked)
                self.project.mkdir()
            except OSError:
                pass

        if sys.platform == "darwin":
            real_verify = mission_bridge._darwin_verify_suspended

            def replace_after_spawn(pid, project_descriptor, executable):
                replace_project()
                return real_verify(pid, project_descriptor, executable)

            patcher = mock.patch.object(
                mission_bridge, "_darwin_verify_suspended", replace_after_spawn
            )
        else:
            real_popen = mission_bridge.subprocess.Popen

            def replace_before_create(*arguments, **options):
                replace_project()
                return real_popen(*arguments, **options)

            patcher = mock.patch.object(mission_bridge.subprocess, "Popen", replace_before_create)
        with patcher:
            execute(self.claim_path, self.envelope)
        retained = parked if parked.exists() else self.project
        self.assertTrue((retained / "ao2-output.txt").is_file())
        if parked.exists():
            self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_authenticated_target_substitution_is_rejected_before_launch(self):
        # MUTATION: trusting a caller-edited target redirects governed execution.
        value = json.loads(self.envelope.read_text(encoding="utf-8"))
        value["target"]["canonical_path"] = str(self.base / "substituted")
        payload = dict(value)
        payload.pop("payload_digest")
        value["payload_digest"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.envelope.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        with self.assertRaises(ExecutionError):
            execute(self.claim_path, self.envelope)
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_workflow_path_replacement_uses_retained_digest_copy(self):
        # MUTATION: reopening the staging pathname launches a substituted workflow.
        real_run = mission_bridge._run_output

        def replace_then_run(arguments, project, executable, **options):
            try:
                self._replace_workflow_stage()
            except OSError:
                pass
            return real_run(arguments, project, executable, **options)

        with mock.patch.object(execution_module, "_run_output", replace_then_run):
            if sys.platform == "darwin":
                with self.assertRaises(ExecutionError) as raised:
                    execute(self.claim_path, self.envelope)
                self.assertEqual(raised.exception.code, "workflow-identity-mismatch")
            else:
                execute(self.claim_path, self.envelope)
        copied = self.project / "ao2-workflow.txt"
        if copied.exists():
            self.assertEqual(copied.read_bytes(), self.harness.workflow.read_bytes())

    def test_launched_workflow_snapshot_rejects_in_place_mutation(self):
        # MUTATION: launching a same-user writable staging inode lets verified bytes change.
        real_run = mission_bridge._run_output
        mutation_succeeded = []

        def mutate_then_run(arguments, project, executable, **options):
            workflow_path = Path(arguments[1])
            if os.name != "nt":
                descriptor = int(workflow_path.name)
                try:
                    os.pwrite(descriptor, b"name: substituted\n", 0)
                except OSError:
                    mutation_succeeded.append(False)
                else:
                    mutation_succeeded.append(True)
                launched = os.fstat(descriptor)
                snapshot = next(
                    (
                        candidate
                        for candidate in (
                            self.project
                            / ".ao"
                            / "governance"
                            / "office-pool"
                            / "staging"
                        ).iterdir()
                        if (candidate.stat().st_dev, candidate.stat().st_ino)
                        == (launched.st_dev, launched.st_ino)
                    ),
                    workflow_path,
                )
            else:
                snapshot = workflow_path
            opened = None
            try:
                opened = os.open(snapshot, os.O_WRONLY)
                os.write(opened, b"name: substituted\n")
            except OSError:
                mutation_succeeded.append(False)
            else:
                mutation_succeeded.append(True)
            finally:
                if opened is not None:
                    os.close(opened)
            return real_run(arguments, project, executable, **options)

        with mock.patch.object(execution_module, "_run_output", mutate_then_run):
            execute(self.claim_path, self.envelope)
        self.assertTrue(mutation_succeeded)
        self.assertFalse(any(mutation_succeeded), mutation_succeeded)
        self.assertEqual(
            (self.project / "ao2-workflow.txt").read_bytes(),
            self.harness.workflow.read_bytes(),
        )

    def test_linux_requires_available_successful_workflow_sealing(self):
        # MUTATION: missing or failed Linux seals fall back to the mutable disk snapshot.
        raw = b"name: bounded\n"
        digest = hashlib.sha256(raw).hexdigest()
        fake_fcntl = types.SimpleNamespace(
            F_ADD_SEALS=1,
            F_GET_SEALS=2,
            F_SEAL_WRITE=4,
            F_SEAL_GROW=8,
            F_SEAL_SHRINK=16,
            F_SEAL_SEAL=32,
            fcntl=mock.Mock(),
        )
        failing_fcntl = types.SimpleNamespace(
            F_ADD_SEALS=1,
            F_GET_SEALS=2,
            F_SEAL_WRITE=4,
            F_SEAL_GROW=8,
            F_SEAL_SHRINK=16,
            F_SEAL_SEAL=32,
            fcntl=mock.Mock(side_effect=OSError("F_ADD_SEALS failed")),
        )

        def disk_descriptor(*_):
            return os.open(
                self.base / "fake-memfd",
                os.O_RDWR | os.O_CREAT | os.O_TRUNC,
                0o600,
            )

        cases = (
            (types.SimpleNamespace(), mock.Mock(return_value=99)),
            (fake_fcntl, mock.Mock(side_effect=OSError("memfd unavailable"))),
            (failing_fcntl, mock.Mock(side_effect=disk_descriptor)),
        )
        for fcntl_module, memfd_create in cases:
            with self.subTest(fcntl=bool(vars(fcntl_module))):
                with (
                    mock.patch.object(execution_module.sys, "platform", "linux"),
                    mock.patch.object(
                        execution_module.Path, "is_dir", return_value=True
                    ),
                    mock.patch.object(
                        execution_module.os,
                        "memfd_create",
                        memfd_create,
                        create=True,
                    ),
                    mock.patch.object(
                        execution_module.os, "MFD_ALLOW_SEALING", 1, create=True
                    ),
                    mock.patch.object(
                        execution_module.os, "MFD_CLOEXEC", 2, create=True
                    ),
                    mock.patch.dict(sys.modules, {"fcntl": fcntl_module}),
                    self.assertRaises(ExecutionError) as raised,
                ):
                    execution_module._sealed_workflow_descriptor(raw, digest)
                self.assertEqual(
                    raised.exception.code, "workflow-identity-mismatch"
                )

    @unittest.skipIf(os.name == "nt", "descriptor hash mutation is POSIX-specific")
    def test_workflow_identity_rejects_preheld_writer_mutation_during_hash(self):
        # MUTATION: one pre-hash fstat accepts bytes changed through a pre-held writer.
        raw = b"a" * 4096
        path = self.base / "workflow-identity.yaml"
        path.write_bytes(raw)
        writable = os.open(path, os.O_RDWR)
        readable = os.open(path, os.O_RDONLY)
        os.chmod(path, 0o400)
        self.addCleanup(os.close, writable)
        self.addCleanup(os.close, readable)
        real_read = os.read
        real_pread = os.pread
        mutated = False

        def mutate_after_read(chunk):
            nonlocal mutated
            if chunk and not mutated:
                mutated = True
                os.pwrite(writable, b"b", 0)
                os.fsync(writable)
            return chunk

        def injected_read(descriptor, amount):
            return mutate_after_read(real_read(descriptor, amount))

        def injected_pread(descriptor, amount, offset):
            return mutate_after_read(real_pread(descriptor, amount, offset))

        with (
            mock.patch.object(execution_module.os, "read", injected_read),
            mock.patch.object(execution_module.os, "pread", injected_pread),
            self.assertRaises(ExecutionError) as raised,
        ):
            execution_module._workflow_identity(
                readable, hashlib.sha256(raw).hexdigest()
            )
        self.assertTrue(mutated)
        self.assertEqual(raised.exception.code, "workflow-identity-mismatch")

    def test_completed_and_failed_executions_remove_per_run_workflow_snapshots(self):
        # MUTATION: closing retained handles without unlinking accumulates UUID snapshots.
        staging = (
            self.project / ".ao" / "governance" / "office-pool" / "staging"
        )
        execute(self.claim_path, self.envelope)
        self.assertEqual(list(staging.iterdir()), [])
        execute(self.claim_path, self._witness())
        self.assertEqual(list(staging.iterdir()), [])
        self._set_ao2_mode("wrong-types")
        with self.assertRaises(ExecutionError):
            execute(self.claim_path, self._witness())
        self.assertEqual(list(staging.iterdir()), [])

    def test_deadline_setup_abort_removes_per_run_workflow_snapshot(self):
        staging = (
            self.project / ".ao" / "governance" / "office-pool" / "staging"
        )
        with (
            mock.patch.object(
                mission_bridge.time,
                "monotonic",
                side_effect=KeyboardInterrupt("deadline original"),
            ),
            self.assertRaisesRegex(KeyboardInterrupt, "deadline original"),
        ):
            execute(self.claim_path, self.envelope)
        self.assertEqual(list(staging.iterdir()), [])

    def test_ao2_environment_strips_ambient_injection_variables(self):
        # MUTATION: inheriting the parent environment exposes AO2 to config/code injection.
        hostile = {
            "DYLD_INSERT_LIBRARIES": "/tmp/hostile.dylib",
            "LD_PRELOAD": "/tmp/hostile.so",
            "PYTHONPATH": "/tmp/hostile-python",
            "AO_TEST_FAKE_AO2_MODE": "wrong-types",
            "AO_TEST_UNRELATED_CONFIG": "hostile",
        }
        with mock.patch.dict(os.environ, hostile):
            execute(self.claim_path, self.envelope)
        self.assertEqual(
            (self.project / "ao2-environment.txt").read_text(encoding="utf-8"), ""
        )

    def test_timeout_kills_complete_process_tree(self):
        # MUTATION: killing only the AO2 leader leaves its child alive.
        self._set_ao2_mode("child-timeout")
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope, timeout_seconds=10 if os.name == "nt" else 1)
        self.assertEqual(raised.exception.code, "execution-timeout")
        self._assert_child_dead()
        self.assertEqual(json.loads(raised.exception.record.read_text())["phase"], "failed")

    def test_output_overflow_kills_complete_process_tree(self):
        # MUTATION: killing only the AO2 leader on overflow leaves its child alive.
        self._set_ao2_mode("child-large")
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "execution-output-too-large")
        self._assert_child_dead()
        self.assertEqual(json.loads(raised.exception.record.read_text())["phase"], "failed")

    def test_envelope_is_one_use(self):
        # MUTATION: omitting atomic consumption permits replayed execution.
        execute(self.claim_path, self.envelope)
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "governance-envelope-consumed")

    def test_native_ao2_allowlisted_readback_is_accepted(self):
        self._set_ao2_mode("native-readback")
        result = execute(self.claim_path, self.envelope)
        self.assertEqual(
            result.diagnostics,
            {"status": "accepted", "run_id": self.harness.run_id},
        )

    def test_malformed_ao2_output_is_normalized_and_recorded(self):
        # MUTATION: assuming decoded JSON is a dict leaks TypeError/AttributeError.
        for mode in ("json-list", "wrong-types", "invalid-utf8"):
            with self.subTest(mode=mode):
                envelope = self.envelope if mode == "json-list" else self._witness()
                self._set_ao2_mode(mode)
                with self.assertRaises(ExecutionError) as raised:
                    execute(self.claim_path, envelope)
                self.assertEqual(raised.exception.code, "invalid-execution-readback")
                self.assertEqual(
                    json.loads(raised.exception.record.read_text())["phase"], "failed"
                )

    def test_completed_record_schema_rejects_cross_phase_fields(self):
        # MUTATION: independent field schemas accept failed-record fields in completed records.
        record = json.loads(execute(self.claim_path, self.envelope).record.read_text())
        invalid = (
            {**record, "diagnostics": {}},
            {**record, "diagnostics": {**record["diagnostics"], "extra": "field"}},
            {**record, "diagnostics": {"status": 1, "run_id": record["run_id"]}},
            {**record, "exit_code": None},
            {**record, "exit_code": 1},
            {**record, "failure_code": "execution-failed"},
        )
        schema = Path(execution_module.__file__).parents[1] / "schemas" / "execution-record.schema.json"
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                mission_bridge._validate_schema(value, schema)

    def test_failed_record_schema_rejects_cross_phase_fields(self):
        # MUTATION: an open failure_code and diagnostics object admit ambiguous failed records.
        completed = json.loads(execute(self.claim_path, self.envelope).record.read_text())
        failed = {
            **completed,
            "phase": "failed",
            "diagnostics": {},
            "exit_code": None,
            "failure_code": "execution-failed",
        }
        invalid = (
            {**failed, "diagnostics": completed["diagnostics"]},
            {**failed, "diagnostics": {"extra": "field"}},
            {**failed, "exit_code": True},
            {**failed, "exit_code": "1"},
            {**failed, "failure_code": None},
            {**failed, "failure_code": "unbounded-failure"},
        )
        schema = Path(execution_module.__file__).parents[1] / "schemas" / "execution-record.schema.json"
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                mission_bridge._validate_schema(value, schema)

    def test_record_write_rejects_malformed_diagnostic_types_before_creation(self):
        # MUTATION: writing before schema validation persists untyped AO2 diagnostics.
        before = set(self._execution_records.glob("execution-*.json"))
        malformed = {"status": 1, "run_id": self.harness.run_id}
        with (
            mock.patch.object(execution_module, "_diagnostics", return_value=malformed),
            self.assertRaises(ExecutionError) as raised,
        ):
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(
            set(self._execution_records.glob("execution-*.json")), before
        )

    def test_execution_id_collision_never_overwrites(self):
        # MUTATION: replace-based record writes overwrite pre-existing evidence.
        self._execution_records.mkdir(parents=True, exist_ok=True)
        sentinel = self._execution_records / ("execution-" + "a" * 32 + ".json")
        sentinel.write_bytes(b"preserve-me")
        identifiers = [
            types.SimpleNamespace(hex="c" * 32),
            types.SimpleNamespace(hex="a" * 32),
            types.SimpleNamespace(hex="b" * 32),
        ]
        with mock.patch.object(
            execution_module.uuid, "uuid4", side_effect=identifiers
        ):
            result = execute(self.claim_path, self.envelope)
        self.assertEqual(sentinel.read_bytes(), b"preserve-me")
        self.assertEqual(result.record.name, "execution-" + "b" * 32 + ".json")

    def test_execution_id_collision_exhaustion_is_bounded_and_preserves_sentinel(self):
        # MUTATION: an unbounded collision retry can hold the authority lease forever.
        self._execution_records.mkdir(parents=True, exist_ok=True)
        sentinel = self._execution_records / ("execution-" + "a" * 32 + ".json")
        sentinel.write_bytes(b"preserve-me")
        fixed = types.SimpleNamespace(hex="a" * 32)
        with (
            mock.patch.object(
                execution_module.uuid, "uuid4", side_effect=[fixed] * 130
            ) as ids,
            self.assertRaises(ExecutionError) as raised,
        ):
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertIsNone(raised.exception.record)
        self.assertEqual(ids.call_count, 129)
        self.assertEqual(sentinel.read_bytes(), b"preserve-me")

    def test_record_readback_mutation_preserves_written_evidence(self):
        # MUTATION: returning without exact readback accepts noncanonical changed bytes.
        def add_whitespace(record, _descriptor, _amount):
            before = record.read_bytes()
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    with record.open("ab") as stream:
                        stream.write(b" ")
                self.assertEqual(record.read_bytes(), before)
                return
            with record.open("ab") as stream:
                stream.write(b" ")

        if os.name == "nt":
            with self._during_record_readback(add_whitespace):
                result = execute(self.claim_path, self.envelope)
            self._assert_accepted_completed_record(result)
        else:
            with (
                self._during_record_readback(add_whitespace),
                self.assertRaises(ExecutionError) as raised,
            ):
                execute(self.claim_path, self.envelope)
            self.assertEqual(raised.exception.code, "recovery-required")
            self.assertIsNotNone(raised.exception.record)
            self.assertEqual(
                raised.exception.record.read_bytes()[-2:], b"\n "
            )

    def test_record_digest_mismatch_preserves_written_evidence(self):
        # MUTATION: schema-only readback accepts a syntactically valid false record digest.
        def replace_digest(record, _descriptor, _amount):
            before = record.read_bytes()
            value = json.loads(record.read_bytes())
            value["record_digest"] = "0" * 64
            replacement = (
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    record.write_bytes(replacement)
                self.assertEqual(record.read_bytes(), before)
                return
            record.write_bytes(replacement)

        if os.name == "nt":
            with self._during_record_readback(replace_digest):
                result = execute(self.claim_path, self.envelope)
            self._assert_accepted_completed_record(result)
        else:
            with (
                self._during_record_readback(replace_digest),
                self.assertRaises(ExecutionError) as raised,
            ):
                execute(self.claim_path, self.envelope)
            self.assertEqual(raised.exception.code, "recovery-required")
            self.assertIsNotNone(raised.exception.record)
            preserved = json.loads(raised.exception.record.read_bytes())
            self.assertEqual(preserved["record_digest"], "0" * 64)

    def test_record_rename_recreate_is_rejected_without_touching_replacement(self):
        # MUTATION: verifying only the open inode accepts a substituted record pathname.
        parked = self._execution_records / "parked-created-record.json"

        def replace_path(record, _descriptor, _amount):
            before = record.read_bytes()
            identity = (record.stat().st_dev, record.stat().st_ino)
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    os.replace(record, parked)
                self.assertEqual(record.read_bytes(), before)
                self.assertEqual((record.stat().st_dev, record.stat().st_ino), identity)
                return
            os.replace(record, parked)
            record.write_bytes(b"replacement-sentinel")

        if os.name == "nt":
            with self._during_record_readback(replace_path):
                result = execute(self.claim_path, self.envelope)
            self._assert_accepted_completed_record(result)
        else:
            with (
                self._during_record_readback(replace_path),
                self.assertRaises(ExecutionError) as raised,
            ):
                execute(self.claim_path, self.envelope)
            self.assertEqual(raised.exception.code, "recovery-required")
            self.assertEqual(raised.exception.record.read_bytes(), b"replacement-sentinel")
            self.assertTrue(parked.read_bytes().startswith(b'{"ao2_sha256"'))

    def test_record_delete_recreate_is_rejected_without_touching_replacement(self):
        # MUTATION: reopening the pathname reads attacker replacement instead of created bytes.
        preserved = self._execution_records / "preserved-created-record.json"

        def replace_path(record, descriptor, _amount):
            before = record.read_bytes()
            identity = (record.stat().st_dev, record.stat().st_ino)
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    record.unlink()
                self.assertEqual(record.read_bytes(), before)
                self.assertEqual((record.stat().st_dev, record.stat().st_ino), identity)
                return
            preserved.write_bytes(os.pread(descriptor, record.stat().st_size, 0))
            record.unlink()
            record.write_bytes(b"replacement-sentinel")

        if os.name == "nt":
            with self._during_record_readback(replace_path):
                result = execute(self.claim_path, self.envelope)
            self._assert_accepted_completed_record(result)
        else:
            with (
                self._during_record_readback(replace_path),
                self.assertRaises(ExecutionError) as raised,
            ):
                execute(self.claim_path, self.envelope)
            self.assertEqual(raised.exception.code, "recovery-required")
            self.assertEqual(raised.exception.record.read_bytes(), b"replacement-sentinel")
            self.assertTrue(preserved.read_bytes().startswith(b'{"ao2_sha256"'))

    @unittest.skipIf(os.name == "nt", "POSIX hard-link mutation assertion")
    def test_record_hardlink_during_readback_is_rejected_and_bytes_preserved(self):
        # MUTATION: omitting stable single-link fstats accepts aliased execution evidence.
        alias = self._execution_records / "aliased-created-record.json"

        def add_alias(record, _descriptor, _amount):
            os.link(record, alias)

        with (
            self._during_record_readback(add_alias),
            self.assertRaises(ExecutionError) as raised,
        ):
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "recovery-required")
        self.assertEqual(raised.exception.record.read_bytes(), alias.read_bytes())

    def test_record_readback_is_bounded_to_expected_bytes_plus_one(self):
        # MUTATION: EOF accumulation permits unbounded memory use after an oversized append.
        requested = []

        def capture_bound(record, _descriptor, amount):
            requested.append((amount, record.stat().st_size + 1))

        with self._during_record_readback(capture_bound):
            execute(self.claim_path, self.envelope)
        self.assertEqual(requested, [(requested[0][1], requested[0][1])])

    def test_runtime_tampering_fails_before_launch(self):
        # MUTATION: trusting only the envelope AO2 name accepts changed runtime bytes.
        self.executable.write_bytes(self.executable.read_bytes() + b"tamper")
        with self.assertRaises(ExecutionError) as raised:
            execute(self.claim_path, self.envelope)
        self.assertEqual(raised.exception.code, "ao2-identity-mismatch")
        self.assertFalse((self.project / "ao2-output.txt").exists())

    def test_fresh_witnesses_preserve_distinct_execution_records(self):
        # MUTATION: a fixed record name overwrites the prior governed result.
        first = execute(self.claim_path, self.envelope)
        second = execute(self.claim_path, self._witness())
        self.assertNotEqual(first.record, second.record)
        self.assertTrue(first.record.is_file())
        self.assertTrue(second.record.is_file())


class WindowsRecordCreationTests(unittest.TestCase):
    def _create_record(self, created_parent):
        parent = PureWindowsPath("C:/project/.ao/evidence/office-pool")
        record_name = "execution-" + "a" * 32 + ".json"
        record = types.SimpleNamespace(
            path=Path(str(parent / record_name)),
            directory=types.SimpleNamespace(handles=(11, 22)),
        )
        calls = []

        class FakeLibrary:
            def CreateFileW(self, *arguments):
                calls.append(arguments)
                return 33

            def GetFileInformationByHandle(self, _handle, pointer):
                pointer._obj.file_attributes = 0
                pointer._obj.number_of_links = 1
                return 1

            def CloseHandle(self, _handle):
                return 1

        library = FakeLibrary()

        def final_path(_library, handle):
            if handle == 22:
                return parent
            self.assertEqual(handle, 33)
            return created_parent / record_name

        # Use the real information structure but fake native calls and fd conversion.
        import internal.windows_identity as windows_identity

        fake_msvcrt = types.SimpleNamespace(
            open_osfhandle=mock.Mock(return_value=44), O_RDWR=2, O_BINARY=0x8000
        )

        with (
            mock.patch.object(execution_module.os, "name", "nt"),
            mock.patch.object(execution_module.os, "O_BINARY", 0x8000, create=True),
            mock.patch.object(windows_identity, "_kernel32", return_value=library),
            mock.patch.object(windows_identity, "_final_path", side_effect=final_path),
            mock.patch.object(windows_identity, "_native_path", return_value="native"),
            mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}),
        ):
            descriptor = execution_module._create_record_descriptor(record)
        return descriptor, calls, fake_msvcrt.open_osfhandle

    def test_windows_create_is_bound_to_retained_parent_before_write(self):
        # MUTATION: pathname creation with write/delete sharing can redirect or replace.
        parent = PureWindowsPath("C:/project/.ao/evidence/office-pool")
        descriptor, calls, open_osfhandle = self._create_record(parent)
        self.assertEqual(descriptor, 44)
        open_osfhandle.assert_called_once_with(33, 2 | 0x8000)
        self.assertEqual(calls[0][1], 0x80000000 | 0x40000000)
        self.assertEqual(calls[0][2], 1)
        self.assertEqual(calls[0][4], 1)

    def test_windows_create_rejects_redirected_parent_before_write(self):
        # MUTATION: absolute creation without final-parent comparison accepts redirection.
        redirected = PureWindowsPath("C:/recreated/.ao/evidence/office-pool")
        with self.assertRaises(ValueError):
            self._create_record(redirected)


@unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
class BoundedStreamCleanupTests(unittest.TestCase):
    def test_unexpected_wait_failure_kills_descendant_and_reaps_leader(self):
        # MUTATION: joining readers before killing on wait failure leaks the process tree.
        child_pid_path = Path(self.id().replace(".", "-"))
        child_pid_path = Path.cwd() / child_pid_path
        child_pid_path.unlink(missing_ok=True)
        self.addCleanup(child_pid_path.unlink, missing_ok=True)
        leader = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, subprocess, sys, time; "
                    "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                    "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
                    "time.sleep(30)"
                ),
                str(child_pid_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        def cleanup_group() -> None:
            try:
                os.killpg(leader.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                leader.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

        self.addCleanup(cleanup_group)

        def kill() -> None:
            try:
                os.killpg(leader.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        wait_calls = 0

        def wait() -> int:
            nonlocal wait_calls
            wait_calls += 1
            if wait_calls == 1:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if child_pid_path.exists() and child_pid_path.stat().st_size:
                        break
                    time.sleep(0.01)
                if not child_pid_path.exists() or not child_pid_path.stat().st_size:
                    raise AssertionError("descendant was not created")
                raise RuntimeError("unexpected wait failure")
            return leader.wait(timeout=5)

        with self.assertRaisesRegex(RuntimeError, "unexpected wait failure"):
            mission_bridge._read_bounded_streams(
                (io.BytesIO(), io.BytesIO()), kill, wait
            )
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        self.assertEqual(wait_calls, 2)
        self.assertIsNotNone(leader.returncode)
        deadline = time.monotonic() + 5
        while True:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                self.fail(f"descendant {child_pid} survived cleanup")
            time.sleep(0.01)


if __name__ == "__main__":
    unittest.main()
