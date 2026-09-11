#!/usr/bin/env python3
"""Actual local ELF component tests, never installed Jankurai acceptance."""
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("jankurai-tool.py")
spec = importlib.util.spec_from_file_location("auditor_tool", SOURCE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
TRUE = Path("/usr/bin/true")
FALSE = Path("/usr/bin/false")
AUDIT = ["audit", ".", "--full", "--no-score-history", "--json", "report.json", "--md", "report.md"]
EVIDENCE = Path(tempfile.mkdtemp(prefix="bulletgit-auditor-admission-component."))


class Admission(unittest.TestCase):
    def setUp(self):
        self.root = EVIDENCE / self.id().rsplit(".", 1)[-1]
        self.root.mkdir()
        self.candidate = self.root / "candidate"
        shutil.copyfile(TRUE, self.candidate)
        self.candidate.chmod(0o755)
        self.record = self.root / "tool.jsonl"
        self.environment = mock.patch.dict(os.environ, {
            "PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C", "TZ": "UTC0"
        }, clear=True)
        self.invocations = 0
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @contextlib.contextmanager
    def fixture_profile(self):
        # Test-local globals only; production offers no caller pin override.
        content = self.candidate.read_bytes()
        with mock.patch.object(tool, "PINNED_SIZE", len(content)), \
                mock.patch.object(tool, "PINNED_SHA256", hashlib.sha256(content).hexdigest()):
            yield

    def invoke(self, command=None):
        out, err = io.BytesIO(), io.BytesIO()
        stdout, stderr = io.TextIOWrapper(out, write_through=True), io.TextIOWrapper(err, write_through=True)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = tool.main(["--candidate", str(self.candidate), "--record", str(self.record),
                                "--", *(AUDIT if command is None else command)])
        self.invocations += 1
        (self.root / f"helper.{self.invocations}.stdout").write_bytes(out.getvalue())
        (self.root / f"helper.{self.invocations}.stderr").write_bytes(err.getvalue())
        (self.root / f"helper.{self.invocations}.exit").write_text(str(status) + "\n")
        return status

    def rows(self):
        rows = [json.loads(line) for line in self.record.read_text().splitlines()]
        self.assertEqual([r["sequence"] for r in rows], list(range(len(rows))))
        return rows

    def no_start(self):
        self.assertNotIn("started", [row["event"] for row in self.rows()])

    def test_production_pin_refuses_marker_before_execution(self):
        marker = self.root / "WRONG_CANDIDATE_STARTED"
        self.candidate.write_text("#!/bin/sh\nprintf started > '" + str(marker) + "'\n")
        with self.candidate.open("r+b") as stream:
            stream.truncate(tool.PINNED_SIZE)
        os.environ["JANKURAI_SHA256"] = hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        self.assertEqual(self.invoke(["--version"]), 75)
        self.assertIn("CANDIDATE_SHA256_MISMATCH", self.rows()[-1]["reason"])
        readback = next(row for row in self.rows() if row["event"] == "candidate_read")
        self.assertEqual(readback["sha256"], os.environ["JANKURAI_SHA256"])
        self.no_start()
        self.assertFalse(marker.exists())
        self.assertEqual(self.rows()[0]["pinned_sha256"], "9e6b8857a26f6004d4c74e510e13b06d880f2e2ae0c89502698889ed690c5d6c")

    def test_actual_sealed_execution_and_one_use_record(self):
        with self.fixture_profile():
            self.assertEqual(self.invoke(), 0)
        rows = self.rows()
        self.assertEqual(rows[0]["record_path"], str(self.record))
        self.assertEqual(rows[-1]["event"], "complete")
        self.assertEqual(next(r for r in rows if r["event"] == "terminated")["native_returncode"], 0)
        original = self.record.read_bytes()
        with self.fixture_profile():
            self.assertEqual(self.invoke(), 75)
        self.assertEqual(self.record.read_bytes(), original)
        self.assertEqual(self.record.stat().st_mode & 0o777, 0o600)

    def test_actual_version_and_raw_output(self):
        expected = subprocess.run([str(TRUE), "--version"], capture_output=True, check=True).stdout.rstrip(b"\r\n")
        with self.fixture_profile(), mock.patch.object(tool, "EXPECTED_VERSION", expected):
            self.assertEqual(self.invoke(["--version"]), 0)
        self.assertEqual(Path(str(self.record) + ".stdout").read_bytes().rstrip(b"\r\n"), expected)
        self.assertEqual(Path(str(self.record) + ".stderr").read_bytes(), b"")
        self.assertTrue(any(row["event"] == "version_output" for row in self.rows()))

    def test_version_mismatch_after_actual_exit_zero(self):
        with self.fixture_profile():
            self.assertEqual(self.invoke(["--version"]), 75)
        self.assertEqual(self.rows()[-1]["native_status"], 0)
        self.assertIn("VERSION_OUTPUT_MISMATCH", self.rows()[-1]["reason"])

    def test_actual_doctor_refuses_wrong_tool_before_version(self):
        repo = self.root / "repo with spaces"
        (repo / "scripts").mkdir(parents=True)
        (repo / "ops/ci").mkdir(parents=True)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        marker = self.root / "WRONG_VERSION_STARTED"
        wrong = binary_dir / "jankurai"
        wrong.write_text("#!/bin/sh\nprintf started > '" + str(marker) + "'\n")
        wrong.chmod(0o755)
        doctor = SOURCE.parents[2] / "scripts/ci-doctor.sh"
        shutil.copyfile(doctor, repo / "scripts/ci-doctor.sh")
        shutil.copyfile(SOURCE, repo / "ops/ci/jankurai-tool.py")
        environment = dict(os.environ, PATH=str(binary_dir) + ":/usr/bin:/bin")
        result = subprocess.run(["/usr/bin/bash", "scripts/ci-doctor.sh", "audit"], cwd=repo,
                                env=environment, capture_output=True)
        (self.root / "doctor.stdout").write_bytes(result.stdout)
        (self.root / "doctor.stderr").write_bytes(result.stderr)
        (self.root / "doctor.exit").write_text(str(result.returncode) + "\n")
        self.assertEqual(result.returncode, 75)
        self.assertFalse(marker.exists())
        probes = list((repo / "target/jankurai/tool-probes").glob("probe.*/tool.jsonl"))
        self.assertEqual(len(probes), 1)
        rows = [json.loads(line) for line in probes[0].read_text().splitlines()]
        self.assertEqual(rows[0]["candidate"], str(wrong))
        self.assertEqual(rows[-1]["event"], "refused")
        self.assertNotIn("started", [row["event"] for row in rows])
        required = next(line for line in doctor.read_text().splitlines() if line.startswith("  required)"))
        self.assertNotIn("jankurai", required)
        self.assertIn("python3", required)

    def test_bound_doctor_retains_exact_refused_tool_record(self):
        repo = self.root / "repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "ops/ci").mkdir(parents=True)
        run = repo / "target/jankurai/audit-runs/run.ABCDef12"
        run.mkdir(parents=True, mode=0o700)
        invocation = run / "invocation.json"
        invocation.write_text(json.dumps({"schema": "bullet.audit-invocation.v1", "id": run.name,
            "repository": str(repo), "origin": "dispatcher", "parent_pid": os.getpid()}))
        invocation.chmod(0o600)
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        wrong = binary_dir / "jankurai"
        marker = self.root / "WRONG_VERSION_STARTED"
        wrong.write_text("#!/bin/sh\nprintf started > '" + str(marker) + "'\n")
        wrong.chmod(0o755)
        shutil.copyfile(SOURCE.parents[2] / "scripts/ci-doctor.sh", repo / "scripts/ci-doctor.sh")
        shutil.copyfile(SOURCE, repo / "ops/ci/jankurai-tool.py")
        result = subprocess.run(["/usr/bin/bash", "scripts/ci-doctor.sh", "audit", "--audit-run", str(run)],
            cwd=repo, env=dict(os.environ, PATH=str(binary_dir) + ":/usr/bin:/bin"), capture_output=True)
        (self.root / "doctor.stdout").write_bytes(result.stdout)
        (self.root / "doctor.stderr").write_bytes(result.stderr)
        (self.root / "doctor.exit").write_text(str(result.returncode) + "\n")
        self.assertEqual(result.returncode, 75)
        self.assertFalse(marker.exists())
        rows = [json.loads(line) for line in (run / "doctor.tool.jsonl").read_text().splitlines()]
        self.assertEqual(rows[0]["candidate"], str(wrong))
        self.assertEqual(rows[-1]["event"], "refused")
        self.assertNotIn("started", [row["event"] for row in rows])
        self.assertFalse((repo / "target/jankurai/tool-probes").exists())

    def test_corrupt_memfd_copy_refused_before_execution(self):
        write = os.write
        corrupted = False

        def corrupt(fd, data):
            nonlocal corrupted
            if os.fstat(fd).st_nlink == 0 and not corrupted:
                corrupted = True
                content = bytearray(data)
                content[-1] ^= 1
                return write(fd, content)
            return write(fd, data)

        with self.fixture_profile(), mock.patch.object(tool.os, "write", corrupt):
            self.assertEqual(self.invoke(), 75)
        self.assertTrue(corrupted)
        self.assertIn("SEALED_ARTIFACT_DIGEST_MISMATCH", self.rows()[-1]["reason"])
        self.no_start()

    def test_unsupported_audit_parser_refuses_before_candidate_execution(self):
        repo = self.root / "repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "ops/ci").mkdir(parents=True)
        binaries = self.root / "bin"
        binaries.mkdir()
        doctor = SOURCE.parents[2] / "scripts/ci-doctor.sh"
        shutil.copyfile(doctor, repo / "scripts/ci-doctor.sh")
        shutil.copyfile(SOURCE, repo / "ops/ci/jankurai-tool.py")
        parser_marker, native_marker = self.root / "PARSER_CHECKED", self.root / "CANDIDATE_STARTED"
        candidate = binaries / "jankurai"
        candidate.write_text("#!/bin/sh\nprintf started > '" + str(native_marker) + "'\n")
        candidate.chmod(0o755)
        python = binaries / "python3"
        python.write_text("#!/bin/sh\nif [ \"$1\" = -I ] && [ \"$2\" = -S ] && [ \"$3\" = -c ]; then\n"
            "printf checked > '" + str(parser_marker) + "'\nexit 1\nfi\n"
            "echo unexpected-python-invocation >&2\nexit 97\n")
        python.chmod(0o755)
        result = subprocess.run(["/usr/bin/bash", "scripts/ci-doctor.sh", "audit"], cwd=repo,
            env=dict(os.environ, PATH=str(binaries) + ":/usr/bin:/bin"), capture_output=True)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr),
                             ("exit", str(result.returncode).encode()+b"\n")):
            (self.root / ("parser-doctor." + suffix)).write_bytes(data)
        self.assertEqual(result.returncode, 75)
        self.assertTrue(parser_marker.exists())
        self.assertFalse(native_marker.exists())
        self.assertFalse((repo / "target").exists())
        self.assertIn(b"AUDIT_TOML_PARSER_UNAVAILABLE", result.stderr)
        self.assertNotIn(b"unexpected-python-invocation", result.stderr)

    def test_native_failure_preserved(self):
        shutil.copyfile(FALSE, self.candidate)
        with self.fixture_profile():
            self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.rows()[-1]["exit_status"], 1)

    def test_hash_mismatch_never_starts(self):
        with self.fixture_profile():
            content = bytearray(self.candidate.read_bytes())
            content[-1] ^= 1
            self.candidate.write_bytes(content)
            self.assertEqual(self.invoke(), 75)
        self.assertIn("CANDIDATE_SHA256_MISMATCH", self.rows()[-1]["reason"])
        self.no_start()

    def test_wrong_elf_architecture_refused(self):
        content = bytearray(self.candidate.read_bytes())
        content[18:20] = b"\xb7\x00"
        self.candidate.write_bytes(content)
        with self.fixture_profile():
            self.assertEqual(self.invoke(), 75)
        self.assertIn("CANDIDATE_ELF_PROFILE_MISMATCH", self.rows()[-1]["reason"])
        self.no_start()

    def test_fifo_refused_without_writer(self):
        self.candidate.unlink()
        os.mkfifo(self.candidate)
        self.assertEqual(self.invoke(), 75)
        self.no_start()

    def test_symlink_leaf_refused(self):
        self.candidate.unlink()
        self.candidate.symlink_to(TRUE)
        self.assertEqual(self.invoke(), 75)
        self.no_start()

    def test_symlink_ancestor_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.candidate = alias / "candidate"
        self.assertEqual(self.invoke(), 75)
        self.no_start()

    def test_directory_refused(self):
        self.candidate.unlink()
        self.candidate.mkdir()
        self.assertEqual(self.invoke(), 75)
        self.no_start()

    def test_changed_and_restored_during_read_refused(self):
        read = os.read
        original = self.candidate.read_bytes()
        changed = False

        def mutate(fd, size):
            nonlocal changed
            data = read(fd, size)
            if data and not changed:
                changed = True
                self.candidate.write_bytes(b"X" + original[1:])
                self.candidate.write_bytes(original)
            return data

        with self.fixture_profile(), mock.patch.object(tool.os, "read", mutate):
            self.assertEqual(self.invoke(), 75)
        self.assertTrue(changed)
        self.assertEqual(self.candidate.read_bytes(), original)
        self.assertIn("CANDIDATE_CHANGED_DURING_READ", self.rows()[-1]["reason"])
        self.no_start()

    def test_replacement_after_admission_executes_sealed_bytes(self):
        run = tool.run_child
        replacement = self.root / "false"
        shutil.copyfile(FALSE, replacement)
        replacement.chmod(0o755)
        original = self.candidate.read_bytes()

        def replace(fd, argv, record, state):
            self.candidate.rename(self.root / "original-true")
            os.replace(replacement, self.candidate)
            return run(fd, argv, record, state)

        with self.fixture_profile(), mock.patch.object(tool, "run_child", replace):
            self.assertEqual(self.invoke(), 0)
        self.assertEqual((self.root / "original-true").read_bytes(), original)
        self.assertEqual(self.candidate.read_bytes(), FALSE.read_bytes())
        self.assertEqual(next(r for r in self.rows() if r["event"] == "admitted")["sha256"], hashlib.sha256(original).hexdigest())

    def test_seals_refuse_writes_resize_and_removal(self):
        run = tool.run_child
        observed = []

        def inspect(fd, argv, record, state):
            for operation in (lambda: os.write(fd, b"X"), lambda: os.ftruncate(fd, 1),
                              lambda: fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 0)):
                with self.assertRaises(PermissionError):
                    operation()
                observed.append(True)
            return run(fd, argv, record, state)

        with self.fixture_profile(), mock.patch.object(tool, "run_child", inspect):
            self.assertEqual(self.invoke(), 0)
        self.assertEqual(len(observed), 3)

    def test_dynamic_loader_environment_refused(self):
        os.environ["LD_PRELOAD"] = str(self.root / "foreign.so")
        with self.fixture_profile():
            self.assertEqual(self.invoke(), 75)
        self.assertIn("DYNAMIC_LOADER_ENVIRONMENT_REFUSED", self.rows()[-1]["reason"])
        self.no_start()

    def test_update_opt_out_and_only_executable_fd_passed(self):
        popen = tool.subprocess.Popen
        observed = []

        def inspect(argv, **kwargs):
            self.assertEqual(kwargs["env"]["JANKURAI_NO_UPDATE_CHECK"], "1")
            self.assertTrue(kwargs["close_fds"])
            self.assertEqual(len(kwargs["pass_fds"]), 1)
            self.assertEqual(kwargs["executable"], "/proc/self/fd/" + str(kwargs["pass_fds"][0]))
            observed.append(argv)
            return popen(argv, **kwargs)

        os.environ["JANKURAI_NO_UPDATE_CHECK"] = "0"
        with self.fixture_profile(), mock.patch.object(tool.subprocess, "Popen", inspect):
            self.assertEqual(self.invoke(), 0)
        self.assertEqual(observed, [["jankurai", *AUDIT]])

    def test_unknown_audit_flags_refused_before_admission(self):
        self.assertEqual(self.invoke(AUDIT + ["--fail-under", "1"]), 75)
        self.assertEqual([row["event"] for row in self.rows()], ["request", "refused"])

    def test_cli_digest_override_is_not_an_option(self):
        with self.assertRaises(SystemExit) as raised:
            tool.main(["--candidate", str(self.candidate), "--record", str(self.record), "--sha256", "0" * 64])
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(self.record.exists())

    def test_record_failure_keeps_native_failure(self):
        shutil.copyfile(FALSE, self.candidate)
        append = tool.Record.append

        def fail(record, event, **fields):
            if event == "complete":
                raise OSError("injected final record failure")
            return append(record, event, **fields)

        with self.fixture_profile(), mock.patch.object(tool.Record, "append", fail):
            self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.rows()[-1]["event"], "refused")
        self.assertEqual(self.rows()[-1]["native_status"], 1)


if __name__ == "__main__":
    print("CI artifact component evidence retained:", EVIDENCE, flush=True)
    unittest.main(verbosity=2)
