import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import scripts.scan_git_history as history_scanner


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "scan_git_history.py"


def text(*parts):
    return "".join(parts)


class ScanGitHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(tempfile.gettempdir()).resolve()
        )
        self.repository = Path(self.temporary_directory.name) / "repository"
        self.repository.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "synthetic@example.invalid")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def git(self, *arguments, check=True):
        return subprocess.run(
            ["git", "-c", "core.quotepath=false", "-C", str(self.repository), *arguments],
            check=check,
            capture_output=True,
            text=True,
        )

    def write(self, relative, data=b"public\n"):
        path = self.repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "--allow-empty", "-m", message)

    def scan(self, repository=None, *, environment=None):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), str(repository or self.repository)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def fake_git_environment(self, mode):
        root = Path(self.temporary_directory.name) / "fake-git"
        root.mkdir(exist_ok=True)
        program = root / "fake_git.py"
        program.write_text(
            """import json, os, sys, time
args = sys.argv[1:]
mode = os.environ.get('FAKE_GIT_MODE', 'clean')
oid = '1' * 40
log = os.environ.get('FAKE_GIT_LOG')
if log:
    names = ['GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_CONFIG_PARAMETERS','GIT_NAMESPACE','GIT_REPLACE_REF_BASE','GIT_INDEX_FILE','GIT_SHALLOW_FILE','GIT_QUARANTINE_PATH']
    with open(log, 'a', encoding='utf-8') as stream:
        stream.write(json.dumps({'args': args, 'environment': {name: os.environ[name] for name in names if name in os.environ}}, sort_keys=True) + '\\n')
if 'rev-list' in args:
    if mode == 'timeout':
        time.sleep(2)
    if mode == 'infinite-output':
        while True:
            sys.stdout.buffer.write(b'x' * 65536)
            sys.stdout.buffer.flush()
    if mode == 'malformed-rev-list':
        sys.stdout.buffer.write(b'not-an-object\\n')
    elif mode == 'invalid-name':
        sys.stdout.buffer.write((('2' * 40) + '\\n' + ('3' * 40) + '\\n' + oid + '\\n').encode())
    elif mode == 'object-limit':
        for number in range(10001):
            sys.stdout.write(f'{number:040x}\\n')
    elif mode == 'aggregate-limit':
        for number in range(17):
            sys.stdout.write(f'{number + 1:040x}\\n')
    else:
        sys.stdout.write(oid + '\\n')
elif any(argument.startswith('--batch-check') for argument in args):
    marker = os.environ.get('FAKE_GIT_CHECK_MARKER')
    if marker:
        open(marker, 'w', encoding='utf-8').write('called')
    if mode == 'broken-check':
        raise SystemExit(3)
    size = 67108865 if mode == 'blob-limit' else 67108864 if mode == 'aggregate-limit' else 7
    for line in sys.stdin.buffer:
        requested = line.strip().decode()
        kind = 'commit' if mode == 'invalid-name' and requested == '2' * 40 else 'tree' if mode == 'invalid-name' and requested == '3' * 40 else 'blob'
        if kind == 'commit':
            size = len(('tree ' + ('3' * 40) + '\\n\\n').encode())
        elif kind == 'tree':
            size = len(b'100644 bad\\xff.txt\\0') + 20
        sys.stdout.buffer.write(f'{requested} {kind} {size}\\n'.encode())
        sys.stdout.buffer.flush()
elif 'show-ref' in args:
    if mode == 'unknown-ref':
        sys.stdout.write(('9' * 40) + ' HEAD\\n')
    elif mode == 'invalid-name':
        sys.stdout.write(('2' * 40) + ' HEAD\\n')
    else:
        sys.stdout.write(oid + ' HEAD\\n')
elif 'ls-tree' in args:
    sys.stdout.buffer.write(b'100644 blob ' + oid.encode() + b'\\tbad\\xff.txt\\0')
elif '--batch' in args:
    marker = os.environ.get('FAKE_GIT_BATCH_MARKER')
    if marker:
        open(marker, 'w', encoding='utf-8').write('called')
    for line in sys.stdin.buffer:
        requested = line.strip().decode()
        if mode == 'invalid-name' and requested == '2' * 40:
            data = ('tree ' + ('3' * 40) + '\\n\\n').encode()
            sys.stdout.buffer.write(f'{requested} commit {len(data)}\\n'.encode() + data + b'\\n')
        elif mode == 'invalid-name' and requested == '3' * 40:
            data = b'100644 bad\\xff.txt\\0' + bytes.fromhex(oid)
            sys.stdout.buffer.write(f'{requested} tree {len(data)}\\n'.encode() + data + b'\\n')
        elif mode == 'truncated-batch':
            sys.stdout.buffer.write(f'{requested} blob 10\\nxx'.encode())
            sys.stdout.buffer.flush()
            break
        elif mode == 'desynchronized-batch':
            sys.stdout.buffer.write(f'{requested} blob 6\\npublicX'.encode())
            sys.stdout.buffer.flush()
            break
        else:
            sys.stdout.buffer.write(f'{requested} blob 7\\npublic\\n\\n'.encode())
        sys.stdout.buffer.flush()
""",
            encoding="utf-8",
        )
        (root / "git.cmd").write_text(
            f'@"{sys.executable}" "{program}" %*\n', encoding="utf-8"
        )
        environment = os.environ.copy()
        environment["PATH"] = f"{root}{os.pathsep}{environment['PATH']}"
        environment["FAKE_GIT_MODE"] = mode
        return environment, root, program

    def scan_with_fake_git(self, mode, *, environment=None, timeout=None):
        fake_environment, root, program = self.fake_git_environment(mode)
        if environment:
            fake_environment.update(environment)
        original_git = history_scanner._git

        def fake_command(repository, *arguments):
            command = original_git(repository, *arguments)
            return [sys.executable, str(program), *command[1:]]

        output, errors = StringIO(), StringIO()
        patches = [
            patch.dict(os.environ, fake_environment, clear=True),
            patch.object(history_scanner, "_git", side_effect=fake_command),
            patch.object(sys, "argv", [str(SCRIPT), str(self.repository)]),
        ]
        if timeout is not None:
            patches.append(
                patch.object(
                    history_scanner, "GIT_TIMEOUT_SECONDS", timeout, create=True
                )
            )
        with patches[0], patches[1], patches[2]:
            if len(patches) == 4:
                with patches[3], redirect_stdout(output), redirect_stderr(errors):
                    result = history_scanner.main()
            else:
                with redirect_stdout(output), redirect_stderr(errors):
                    result = history_scanner.main()
        return subprocess.CompletedProcess(
            args=[], returncode=result, stdout=output.getvalue(), stderr=errors.getvalue()
        ), root

    @staticmethod
    def minimal_pe():
        data = bytearray(128)
        data[:2] = b"MZ"
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")
        data[0x40:0x44] = b"PE\0\0"
        return bytes(data)

    @staticmethod
    def rows(completed):
        return [json.loads(line) for line in completed.stdout.splitlines()]

    def test_finds_a_deleted_synthetic_secret_blob_without_disclosing_it(self):
        self.write("README.md")
        self.commit("safe")
        marker = text("token", "=synthetic-history-only\n").encode()
        self.write("deleted.txt", marker)
        self.commit("add synthetic marker")
        object_id = self.git("rev-parse", "HEAD:deleted.txt").stdout.strip()
        (self.repository / "deleted.txt").unlink()
        self.commit("delete synthetic marker")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stderr, "history findings=1\n")
        self.assertEqual(
            self.rows(completed),
            [
                {
                    "detail": "private",
                    "object": object_id,
                    "path": "deleted.txt",
                    "rule": "content",
                }
            ],
        )
        combined = completed.stdout + completed.stderr
        self.assertNotIn(str(self.repository), combined)
        self.assertNotIn(marker.decode().strip(), combined)

    def test_scans_every_reachable_branch_and_tag_not_only_head(self):
        self.write("README.md")
        self.commit("main")
        self.git("switch", "-c", "historical")
        self.write("branch-only.txt", text("secret", "=branch-only\n").encode())
        self.commit("branch marker")
        self.git("tag", "branch-marker")
        self.git("switch", "main")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stderr, "history findings=1\n")
        self.assertEqual(self.rows(completed)[0]["path"], "branch-only.txt")

    def test_scans_direct_tree_ref_names_without_disclosing_private_name(self):
        private_name = text("recovery", "-key-direct-tree.txt")
        self.write(private_name)
        self.git("add", private_name)
        tree = self.git("write-tree").stdout.strip()
        object_id = self.git("rev-parse", f"{tree}:{private_name}").stdout.strip()
        self.git("update-ref", "refs/tags/direct-tree", tree)

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [{"detail": "private", "object": object_id, "rule": "path"}],
        )
        self.assertNotIn(private_name, completed.stdout + completed.stderr)

    def test_scans_annotated_tag_to_tree_names_without_disclosing_private_name(self):
        private_name = text("recovery", "-key-tagged-tree.txt")
        self.write(private_name)
        self.git("add", private_name)
        tree = self.git("write-tree").stdout.strip()
        object_id = self.git("rev-parse", f"{tree}:{private_name}").stdout.strip()
        self.git("tag", "-a", "annotated-tree", "-m", "tree root", tree)

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [{"detail": "private", "object": object_id, "rule": "path"}],
        )
        self.assertNotIn(private_name, completed.stdout + completed.stderr)

    def test_scans_annotated_tag_chain_to_tree(self):
        private_name = text("recovery", "-key-tag-chain.txt")
        self.write(private_name)
        self.git("add", private_name)
        tree = self.git("write-tree").stdout.strip()
        object_id = self.git("rev-parse", f"{tree}:{private_name}").stdout.strip()
        self.git("tag", "-a", "tree-one", "-m", "tree", tree)
        self.git("tag", "-a", "tree-two", "-m", "tag chain", "tree-one")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [{"detail": "private", "object": object_id, "rule": "path"}],
        )

    def test_tag_cycle_fails_closed(self):
        first = b"1" * 40
        second = b"2" * 40
        values = {
            first: (b"tag", b"object " + second + b"\ntype tag\n"),
            second: (b"tag", b"object " + first + b"\ntype tag\n"),
        }

        with self.assertRaises(history_scanner.GitScanError) as raised:
            history_scanner._root_trees(
                values, ((b"refs/tags/cycle", first),)
            )

        self.assertEqual(raised.exception.stage, "git-metadata-read")

    def test_clean_multibranch_tag_repository_and_edge_blobs_pass(self):
        self.write("README.md")
        self.write("empty.txt", b"")
        self.write("invalid-utf8.txt", b"public\xff\xfe\x00")
        self.write("runtime.dll", self.minimal_pe())
        self.write("space and unicode-雪.txt", b"public\n")
        self.commit("main edge blobs")
        self.git("tag", "clean-tag")
        self.git("switch", "-c", "clean-branch")
        self.write("branch.txt")
        self.commit("clean branch")
        self.git("switch", "main")

        completed = self.scan()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "history findings=0\n")

    def test_empty_repository_passes(self):
        completed = self.scan()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "history findings=0\n")

    def test_detached_head_without_other_refs_is_scanned(self):
        marker = text("secret", "=detached-head-only\n").encode()
        self.write("detached.txt", marker)
        self.commit("detached authority")
        object_id = self.git("rev-parse", "HEAD:detached.txt").stdout.strip()
        self.git("checkout", "--detach")
        self.git("update-ref", "-d", "refs/heads/main")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [
                {
                    "detail": "private",
                    "object": object_id,
                    "path": "detached.txt",
                    "rule": "content",
                }
            ],
        )
        self.assertNotIn(marker.decode().strip(), completed.stdout + completed.stderr)

    def test_detached_head_move_during_scan_fails_closed_without_paths(self):
        self.write("first.txt")
        self.commit("first detached authority")
        first = self.git("rev-parse", "HEAD").stdout.strip()
        self.write("second.txt")
        self.commit("second detached authority")
        second = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("checkout", "--detach", first)
        self.git("update-ref", "-d", "refs/heads/main")
        original_enumerate = history_scanner._enumerate_objects

        def enumerate_then_move(*args, **kwargs):
            objects = original_enumerate(*args, **kwargs)
            self.git("reset", "--hard", second)
            return objects

        with patch.object(
            history_scanner, "_enumerate_objects", side_effect=enumerate_then_move
        ):
            with self.assertRaises(history_scanner.GitScanError) as raised:
                history_scanner.scan_history(self.repository)

        self.assertEqual(raised.exception.stage, "git-ref-drift")
        self.assertEqual(str(raised.exception), "git-ref-drift")
        self.assertNotIn(str(self.repository), str(raised.exception))

    def test_symbolic_head_and_branch_are_in_one_stable_snapshot(self):
        self.write("README.md")
        self.commit("symbolic head")
        object_id = self.git("rev-parse", "HEAD").stdout.encode().strip()

        snapshot = history_scanner._enumerate_ref_targets(
            self.repository, time.monotonic() + 10
        )

        self.assertEqual(
            snapshot,
            ((b"HEAD", object_id), (b"refs/heads/main", object_id)),
        )

    def test_symbolic_head_commit_move_during_scan_fails_closed(self):
        self.write("main.txt")
        self.commit("main authority")
        self.git("checkout", "-b", "other")
        self.write("other.txt")
        self.commit("other authority")
        self.git("checkout", "main")
        original_enumerate = history_scanner._enumerate_objects

        def enumerate_then_move_head(*args, **kwargs):
            objects = original_enumerate(*args, **kwargs)
            self.git("symbolic-ref", "HEAD", "refs/heads/other")
            return objects

        with patch.object(
            history_scanner,
            "_enumerate_objects",
            side_effect=enumerate_then_move_head,
        ):
            with self.assertRaises(history_scanner.GitScanError) as raised:
                history_scanner.scan_history(self.repository)

        self.assertEqual(raised.exception.stage, "git-ref-drift")
        self.assertEqual(str(raised.exception), "git-ref-drift")
        self.assertNotIn(str(self.repository), str(raised.exception))

    def test_unreachable_loose_blob_is_outside_ref_history(self):
        marker = text("token", "=unreachable-only\n").encode()
        subprocess.run(
            ["git", "-C", str(self.repository), "hash-object", "-w", "--stdin"],
            input=marker,
            capture_output=True,
            check=True,
        )

        completed = self.scan()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(marker.decode().strip(), completed.stdout + completed.stderr)

    def test_direct_blob_ref_is_scanned_without_inventing_a_path(self):
        marker = text("secret", "=direct-blob-ref\n").encode()
        object_id = subprocess.run(
            ["git", "-C", str(self.repository), "hash-object", "-w", "--stdin"],
            input=marker,
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        self.git("update-ref", "refs/tags/direct-blob", object_id)

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [{"detail": "private", "object": object_id, "rule": "content"}],
        )
        self.assertNotIn(marker.decode().strip(), completed.stdout + completed.stderr)

    def test_replacement_refs_cannot_hide_original_reachable_blob(self):
        marker = text("token", "=original-reachable-object\n").encode()
        self.write("payload.txt", marker)
        self.commit("original object")
        original = self.git("rev-parse", "HEAD:payload.txt").stdout.strip()
        benign = subprocess.run(
            ["git", "-C", str(self.repository), "hash-object", "-w", "--stdin"],
            input=b"public\n",
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        self.git("replace", original, benign)

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(self.rows(completed)[0]["object"], original)
        self.assertNotIn(marker.decode().strip(), completed.stdout + completed.stderr)

    def test_hostile_git_environment_cannot_route_scan_to_another_repository(self):
        self.write("payload.txt", text("secret", "=target-only\n").encode())
        self.commit("target marker")
        decoy = Path(self.temporary_directory.name) / "decoy"
        subprocess.run(["git", "init", "-b", "main", str(decoy)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(decoy), "config", "user.name", "Synthetic Test"], check=True)
        subprocess.run(["git", "-C", str(decoy), "config", "user.email", "synthetic@example.invalid"], check=True)
        (decoy / "README.md").write_text("public\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(decoy), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(decoy), "commit", "-m", "decoy"], check=True, capture_output=True)
        environment = os.environ.copy()
        environment["GIT_DIR"] = str(decoy / ".git")
        environment["GIT_WORK_TREE"] = str(decoy)

        completed = self.scan(environment=environment)

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stderr, "history findings=1\n")
        self.assertNotIn(str(decoy), completed.stdout + completed.stderr)

    def test_private_name_occurrence_is_reported_even_when_blob_has_safe_alias(self):
        self.write("public.txt", b"public\n")
        self.write(text("recovery", "-key.txt"), b"public\n")
        self.write(text("recovery", "-key-other.txt"), b"public\n")
        self.commit("same benign blob under safe and private names")
        object_id = self.git("rev-parse", "HEAD:public.txt").stdout.strip()

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [
                {"detail": "private", "object": object_id, "rule": "path"},
                {"detail": "private", "object": object_id, "rule": "path"},
            ],
        )

    def test_plaintext_secret_cannot_hide_behind_executable_extensions(self):
        self.write("renamed.dll", text("token", "=dll-plaintext\n").encode())
        self.write("renamed.exe", text("password", "=exe-plaintext\n").encode())
        self.commit("renamed plaintext")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(self.rows(completed)), 2)
        self.assertEqual({row["rule"] for row in self.rows(completed)}, {"content"})

    def test_structurally_valid_pe_history_blob_is_still_content_scanned(self):
        marker = text("token", "=inside-valid-pe\n").encode()
        self.write("runtime.dll", self.minimal_pe() + b"\n" + marker)
        self.commit("valid pe with synthetic marker")
        object_id = self.git("rev-parse", "HEAD:runtime.dll").stdout.strip()

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [
                {
                    "detail": "private",
                    "object": object_id,
                    "path": "runtime.dll",
                    "rule": "content",
                }
            ],
        )
        self.assertNotIn(marker.decode().strip(), completed.stdout + completed.stderr)

    def test_every_git_process_disables_replacements_and_drops_routing_environment(self):
        environment, fake_root, _ = self.fake_git_environment("clean")
        log = fake_root / "calls.jsonl"
        environment["FAKE_GIT_LOG"] = str(log)
        hostile = {
            "GIT_DIR": "routed",
            "GIT_WORK_TREE": "routed",
            "GIT_COMMON_DIR": "routed",
            "GIT_OBJECT_DIRECTORY": "routed",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "routed",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.replaceRefs",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_CONFIG_PARAMETERS": "'core.replaceRefs=true'",
            "GIT_NAMESPACE": "routed",
            "GIT_REPLACE_REF_BASE": "refs/hidden/",
            "GIT_INDEX_FILE": "routed",
            "GIT_SHALLOW_FILE": "routed",
            "GIT_QUARANTINE_PATH": "routed",
        }
        environment.update(hostile)

        completed, _ = self.scan_with_fake_git("clean", environment=environment)

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertGreaterEqual(len(calls), 3)
        for call in calls:
            self.assertIn("--no-replace-objects", call["args"])
            self.assertEqual(call["environment"], {})

    def test_invalid_historical_name_is_a_redacted_finding(self):
        completed, _ = self.scan_with_fake_git("invalid-name")

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(
            self.rows(completed),
            [{"detail": "private", "object": "1" * 40, "rule": "path"}],
        )
        self.assertNotIn("bad", completed.stdout + completed.stderr)

    def test_limits_reject_before_oversized_blob_bodies_are_requested(self):
        for mode, expected_kind in (
            ("blob-limit", "limit-blob-size"),
            ("aggregate-limit", "limit-aggregate-size"),
        ):
            with self.subTest(mode=mode):
                environment, fake_root, _ = self.fake_git_environment(mode)
                marker = fake_root / "batch-called"
                environment["FAKE_GIT_BATCH_MARKER"] = str(marker)

                completed, _ = self.scan_with_fake_git(mode, environment=environment)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(
                    self.rows(completed),
                    [{"error": "scan-failed", "kind": expected_kind}],
                )
                self.assertFalse(marker.exists())

    def test_object_count_limit_fails_before_batch_protocol(self):
        environment, fake_root, _ = self.fake_git_environment("object-limit")
        marker = fake_root / "batch-called"
        check_marker = fake_root / "check-called"
        environment["FAKE_GIT_BATCH_MARKER"] = str(marker)
        environment["FAKE_GIT_CHECK_MARKER"] = str(check_marker)

        completed, _ = self.scan_with_fake_git("object-limit", environment=environment)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            self.rows(completed),
            [{"error": "scan-failed", "kind": "limit-object-count"}],
        )
        self.assertFalse(marker.exists())
        self.assertFalse(check_marker.exists())

    def test_timeout_is_bounded_and_does_not_disclose_paths(self):
        started = time.monotonic()
        completed, _ = self.scan_with_fake_git("timeout", timeout=0.1)
        elapsed = time.monotonic() - started

        self.assertEqual(completed.returncode, 2)
        self.assertLess(elapsed, 1.0)
        self.assertEqual(json.loads(completed.stdout), {"error": "scan-failed", "kind": "git-timeout"})
        self.assertEqual(completed.stderr, "history scan-error=1\n")
        self.assertNotIn(str(self.repository), completed.stdout + completed.stderr)

    def test_stdout_limit_terminates_git_while_it_is_still_streaming(self):
        environment, _, program = self.fake_git_environment("infinite-output")
        original_git = history_scanner._git
        original_temporary_file = tempfile.TemporaryFile
        written = []

        class MeasuredTemporaryFile:
            def __init__(self, *args, **kwargs):
                self.stream = original_temporary_file(*args, **kwargs)
                self.total = 0

            def write(self, data):
                self.total += len(data)
                written.append(self.total)
                return self.stream.write(data)

            def __getattr__(self, name):
                return getattr(self.stream, name)

        def fake_command(repository, *arguments):
            command = original_git(repository, *arguments)
            return [sys.executable, str(program), *command[1:]]

        started = time.monotonic()
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(history_scanner, "_git", side_effect=fake_command),
            patch.object(history_scanner, "GIT_TIMEOUT_SECONDS", 0.25),
            patch.object(
                history_scanner.tempfile,
                "TemporaryFile",
                side_effect=MeasuredTemporaryFile,
            ),
        ):
            with self.assertRaises(history_scanner.GitScanError) as raised:
                history_scanner._run_git(
                    self.repository,
                    "git-rev-list",
                    ("rev-list", "--objects", "--all", "--no-object-names"),
                    lambda stream: stream.read(),
                    max_output=4096,
                )
        elapsed = time.monotonic() - started

        self.assertEqual(raised.exception.stage, "limit-protocol-size")
        self.assertLess(elapsed, 1.0)
        self.assertLessEqual(max(written, default=0), 4096)

    def test_repeated_commit_trees_do_not_amplify_git_commands(self):
        self.write("README.md")
        self.commit("base")
        for number in range(20):
            self.commit(f"same tree {number}")
        calls = []
        deadlines = []
        original_run_git = history_scanner._run_git

        def recording_run_git(*args, **kwargs):
            calls.append(args[2])
            deadlines.append(kwargs.get("deadline"))
            return original_run_git(*args, **kwargs)

        with patch.object(history_scanner, "_run_git", side_effect=recording_run_git):
            findings = history_scanner.scan_history(self.repository)

        self.assertEqual(findings, [])
        self.assertFalse(any("ls-tree" in arguments for arguments in calls), calls)
        self.assertLessEqual(len(calls), 6, calls)
        self.assertTrue(deadlines)
        self.assertIsNotNone(deadlines[0])
        self.assertEqual(len(set(deadlines)), 1)

    def test_scan_has_one_aggregate_deadline_across_all_git_commands(self):
        self.write("README.md")
        self.commit("base")

        started = time.monotonic()
        with patch.object(
            history_scanner, "GIT_AGGREGATE_TIMEOUT_SECONDS", 0.0, create=True
        ):
            with self.assertRaises(history_scanner.GitScanError) as raised:
                history_scanner.scan_history(self.repository)
        elapsed = time.monotonic() - started

        self.assertEqual(raised.exception.stage, "git-timeout")
        self.assertLess(elapsed, 1.0)

    def test_ref_added_after_object_enumeration_cannot_escape(self):
        self.write("README.md")
        self.commit("base")
        marker = text("token", "=late-ref-only\n").encode()
        object_id = subprocess.run(
            ["git", "-C", str(self.repository), "hash-object", "-w", "--stdin"],
            input=marker,
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        original_enumerate = history_scanner._enumerate_objects

        def enumerate_then_add(*args, **kwargs):
            objects = original_enumerate(*args, **kwargs)
            self.git("update-ref", "refs/tags/late", object_id)
            return objects

        with patch.object(
            history_scanner, "_enumerate_objects", side_effect=enumerate_then_add
        ):
            with self.assertRaises(history_scanner.GitScanError) as raised:
                history_scanner.scan_history(self.repository)

        self.assertEqual(raised.exception.stage, "git-ref-drift")
        self.assertNotIn(marker.decode().strip(), str(raised.exception))
        self.assertNotIn(str(self.repository), str(raised.exception))

    def test_ref_moved_after_object_enumeration_cannot_escape(self):
        self.write("README.md")
        self.commit("base")
        original = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("update-ref", "refs/tags/moving", original)
        marker = text("secret", "=moved-ref-only\n").encode()
        replacement = subprocess.run(
            ["git", "-C", str(self.repository), "hash-object", "-w", "--stdin"],
            input=marker,
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        original_enumerate = history_scanner._enumerate_objects

        def enumerate_then_move(*args, **kwargs):
            objects = original_enumerate(*args, **kwargs)
            self.git("update-ref", "refs/tags/moving", replacement)
            return objects

        with patch.object(
            history_scanner, "_enumerate_objects", side_effect=enumerate_then_move
        ):
            with self.assertRaises(history_scanner.GitScanError) as raised:
                history_scanner.scan_history(self.repository)

        self.assertEqual(raised.exception.stage, "git-ref-drift")
        self.assertNotIn(marker.decode().strip(), str(raised.exception))
        self.assertNotIn(str(self.repository), str(raised.exception))

    def test_unknown_stable_ref_target_fails_closed_without_paths(self):
        completed, _ = self.scan_with_fake_git("unknown-ref")

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            self.rows(completed),
            [{"error": "scan-failed", "kind": "git-ref-target"}],
        )
        self.assertEqual(completed.stderr, "history scan-error=1\n")
        self.assertNotIn(str(self.repository), completed.stdout + completed.stderr)

    def test_final_ref_reread_detects_add_delete_and_move_without_paths(self):
        for operation in ("add", "delete", "move"):
            with self.subTest(operation=operation):
                self.write("README.md")
                self.commit(f"base {operation}")
                original = self.git("rev-parse", "HEAD").stdout.strip()
                self.git("update-ref", "refs/tags/stable", original)
                replacement = self.git("rev-parse", "HEAD:README.md").stdout.strip()
                original_refs = history_scanner._enumerate_ref_targets
                calls = 0

                def snapshot_then_drift(*args, **kwargs):
                    nonlocal calls
                    snapshot = original_refs(*args, **kwargs)
                    calls += 1
                    if calls == 1:
                        if operation == "add":
                            self.git("update-ref", "refs/tags/added", replacement)
                        elif operation == "delete":
                            self.git("update-ref", "-d", "refs/tags/stable")
                        else:
                            self.git("update-ref", "refs/tags/stable", replacement)
                    return snapshot

                with patch.object(
                    history_scanner,
                    "_enumerate_ref_targets",
                    side_effect=snapshot_then_drift,
                ):
                    with self.assertRaises(history_scanner.GitScanError) as raised:
                        history_scanner.scan_history(self.repository)

                self.assertEqual(raised.exception.stage, "git-ref-drift")
                self.assertEqual(str(raised.exception), "git-ref-drift")
                if operation != "add":
                    self.git("update-ref", "refs/tags/stable", original)
                if operation == "add":
                    self.git("update-ref", "-d", "refs/tags/added")

    def test_malformed_and_truncated_protocol_fail_without_traceback(self):
        for mode in ("malformed-rev-list", "broken-check", "truncated-batch", "desynchronized-batch"):
            with self.subTest(mode=mode):
                completed, _ = self.scan_with_fake_git(mode)

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, "history scan-error=1\n")
                self.assertNotIn("Traceback", completed.stdout + completed.stderr)
                self.assertNotIn(str(self.repository), completed.stdout + completed.stderr)

    def test_deduplicates_one_blob_reachable_under_multiple_names(self):
        marker = text("password", "=same-object\n").encode()
        self.write("first.txt", marker)
        self.write("second.txt", marker)
        self.commit("same blob twice")
        object_id = self.git("rev-parse", "HEAD:first.txt").stdout.strip()

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        rows = self.rows(completed)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["object"], object_id)
        self.assertIn(rows[0].get("path"), {"first.txt", "second.txt"})

    def test_absolute_windows_user_path_is_private_but_never_echoed(self):
        private_path = text("C", ":\\", "Users\\Synthetic\\private.txt")
        self.write("path.txt", private_path.encode())
        self.commit("synthetic path")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stderr, "history findings=1\n")
        self.assertNotIn(private_path, completed.stdout + completed.stderr)
        self.assertNotIn(str(self.repository), completed.stdout + completed.stderr)

    def test_private_or_ambiguous_historical_name_is_omitted(self):
        private_name = text("recovery", "-key-synthetic.txt")
        self.write(private_name, text("secret", "=synthetic\n").encode())
        self.commit("private filename")

        completed = self.scan()

        self.assertEqual(completed.returncode, 1, completed.stderr)
        rows = self.rows(completed)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["rule"] for row in rows}, {"content", "path"})
        self.assertTrue(all("path" not in row for row in rows))
        self.assertNotIn(private_name, completed.stdout + completed.stderr)

    def test_non_repository_failure_is_bounded_and_path_private(self):
        not_a_repository = Path(self.temporary_directory.name) / "not-a-repository"
        not_a_repository.mkdir()

        completed = self.scan(not_a_repository)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stderr, "history scan-error=1\n")
        self.assertEqual(
            self.rows(completed),
            [{"error": "scan-failed", "kind": "git-show-ref"}],
        )
        self.assertNotIn(str(not_a_repository), completed.stdout + completed.stderr)

    def test_explicit_worktree_on_ownershipless_volume_is_scannable(self):
        completed = self.scan(ROOT)

        self.assertNotEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertNotIn("history scan-error=1", completed.stderr)
        self.assertNotIn(str(ROOT), completed.stdout + completed.stderr)

    def test_sha256_repository_object_ids_are_supported_when_available(self):
        sha_repository = Path(self.temporary_directory.name) / "sha256-repository"
        initialized = subprocess.run(
            ["git", "init", "--object-format=sha256", "-b", "main", str(sha_repository)],
            capture_output=True,
            text=True,
            check=False,
        )
        if initialized.returncode != 0:
            self.skipTest("Git SHA-256 repositories unavailable")
        subprocess.run(
            ["git", "-C", str(sha_repository), "config", "user.name", "Synthetic Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(sha_repository), "config", "user.email", "synthetic@example.invalid"],
            check=True,
        )
        (sha_repository / "README.md").write_text("public\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(sha_repository), "add", "README.md"], check=True)
        subprocess.run(
            ["git", "-C", str(sha_repository), "commit", "-m", "clean"],
            check=True,
            capture_output=True,
        )

        completed = self.scan(sha_repository)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "history findings=0\n")


if __name__ == "__main__":
    unittest.main()
