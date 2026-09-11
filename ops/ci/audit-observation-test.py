#!/usr/bin/env python3
"""Real files and producer/consumer processes; native event rows are explicit fixtures."""
import base64
import hashlib
import importlib.util
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
SOURCE = Path(__file__).with_name("audit-observation.py")
spec = importlib.util.spec_from_file_location("audit_observation", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
EVIDENCE = Path(tempfile.mkdtemp(prefix="bulletgit-audit-observation-component."))
POLICY = b'minimum_score = 85\nfail_on = ["critical", "high"]\nadvisory_on = ["medium", "low"]\n'


class AuditObservation(unittest.TestCase):
    def setUp(self):
        self.home = EVIDENCE / self.id().rsplit(".", 1)[-1]
        self.root = self.home / "repo with spaces"
        self.root.mkdir(parents=True)
        self.run = self.root / "target/jankurai/audit-runs/run.ABCD1234"
        self.run.mkdir(parents=True, mode=0o700)
        self.counter = 0
        for source in (SOURCE, SOURCE.with_name("jankurai-tool.py"), SOURCE.with_name("artifact-check.sh"),
                       SOURCE.with_name("lib.sh"), SOURCE.parents[2] / "scripts/ci-observation.sh"):
            dest = self.root / source.relative_to(SOURCE.parents[2])
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
        self.put("agent/audit-policy.toml", POLICY, root=True)
        self.put(".gitignore", b'target/\n.ci-artifacts/\n.jankurai/\n', root=True)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                        GIT_AUTHOR_NAME="Component", GIT_AUTHOR_EMAIL="component@example.invalid",
                        GIT_COMMITTER_NAME="Component", GIT_COMMITTER_EMAIL="component@example.invalid")
        self.git("init", "--quiet", "--template=")
        self.git("add", ".")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "component input")
        self.commit = self.git("rev-parse", "HEAD").decode().strip()
        self.put("invocation.json", self.json(dict(schema="bullet.audit-invocation.v1", id=self.run.name,
            repository=str(self.root), origin="dispatcher", parent_pid=os.getpid())))
        self.report = dict(score=90, policy=dict(minimum_score=85, fail_on=["critical", "high"],
            advisory_on=["medium", "low"], mode="standard"),
            policy_fingerprint="sha256:" + hashlib.sha256(POLICY).hexdigest(),
            decision=dict(passed=True, status="pass", minimum_score=85, hard_findings=0),
            findings=[], caps_applied=[], report_fingerprint="sha256:" + "a" * 64,
            input_fingerprint="sha256:" + "b" * 64, schema_version="test-schema", standard_version="test-standard")
        self.stage("doctor", ["bash", "scripts/ci-doctor.sh", "audit", "--audit-run", str(self.run)])
        self.stage("lane", ["bash", "ops/ci/audit.sh", "--audit-run", str(self.run)])
        self.put("audit.started", b"pid=1234\n")
        self.put("result.txt", b"stage=complete\nprimary_status=0\nretention_status=0\nfinal_status=0\n")
        self.tool_rows("doctor", ["--version"])
        self.tool_rows("audit", ["audit", ".", "--full", "--no-score-history", "--repair-queue-jsonl",
            ".jankurai/repair-queue.jsonl", "--json", ".jankurai/repo-score.json", "--md", ".jankurai/repo-score.md"])
        for suffix, value in (("stdout", b"fixture native stdout\n"), ("stderr", b""), ("exit", b"0\n"),
                              ("validation.stdout", b"true\n"), ("validation.stderr", b""), ("validation.exit", b"0\n")):
            self.put("audit." + suffix, value)
        self.snapshot("before", {})
        self.refresh_reports()

    def json(self, value):
        return (json.dumps(value, sort_keys=True) + "\n").encode()

    def put(self, name, data, root=False):
        path = (self.root if root else self.run) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.root, env=self.env, capture_output=True, check=True)
        return result.stdout

    def stage(self, name, argv, status=0):
        self.put(name + ".argv", b"".join(s.encode() + b"\0" for s in argv))
        self.put(name + ".stdout", b"fixture stage stdout\n")
        self.put(name + ".stderr", b"")
        self.put(name + ".exit", str(status).encode() + b"\n")

    def tool_rows(self, name, argv, status=0):
        # Synthetic component records, never actual installed artifact execution evidence.
        t = audit.tool
        candidate = "/component/fixture/jankurai"
        events = [("request", dict(profile=t.PROFILE, record_path=str(self.run / (name + ".tool.jsonl")),
            candidate=candidate, argv=argv, pinned_sha256=t.PINNED_SHA256, pinned_size=t.PINNED_SIZE,
            install_receipt_sha256=t.INSTALL_RECEIPT, source_commit=t.SOURCE_COMMIT,
            provenance_is_distribution_acceptance=False)),
            ("candidate_opened", dict(path=candidate)),
            ("candidate_read", dict(path=candidate, sha256=t.PINNED_SHA256, copied_bytes=t.PINNED_SIZE)),
            ("admitted", dict(sha256=t.PINNED_SHA256, size=t.PINNED_SIZE, seals=15)),
            ("launch_intent", dict(argv=["jankurai", *argv], executable="/proc/self/fd/9", passed_executable_fd=9,
                update_check="disabled_by_JANKURAI_NO_UPDATE_CHECK_1")), ("started", dict(pid=1234)),
            ("terminated", dict(native_returncode=status, exit_status=status))]
        if name == "doctor":
            out = t.EXPECTED_VERSION + b"\n"
            events.append(("version_output", dict(stdout_base64=base64.b64encode(out).decode(), stderr_base64="")))
            self.put(name + ".tool.jsonl.stdout", out)
            self.put(name + ".tool.jsonl.stderr", b"")
        events.append(("complete", dict(exit_status=status)))
        rows = [dict(schema="bullet.local-auditor-tool.v1", sequence=i, time_ns=str(i+1),
                     event=e, evidence_class="LOCAL_TOOL_DIAGNOSTIC", **values)
                for i, (e, values) in enumerate(events)]
        self.put(name + ".tool.jsonl", b"".join(self.json(row) for row in rows))

    def snapshot(self, phase, files):
        for path, data in files.items():
            self.put(phase + "/" + path, data)
        self.put(phase + ".absent", "".join(p + "\n" for p in audit.ARTIFACTS if p not in files).encode())

    def refresh_reports(self):
        artifacts = {".jankurai/repo-score.json": self.json(self.report),
            ".jankurai/repo-score.md": b"fixture report\n", ".jankurai/repair-queue.jsonl": b""}
        self.snapshot("audit", artifacts)
        final = dict(artifacts)
        final.update({"target/jankurai/" + p: artifacts[".jankurai/" + p] for p in audit.REPORTS})
        self.snapshot("final", final)
        for path, data in final.items():
            self.put(path, data, root=True)

    def invoke(self, args, script="ops/ci/audit-observation.py"):
        argv = ["python3", "-I", "-S", script, *args]
        if script.endswith(".sh"):
            argv = ["bash", script, *args]
        result = subprocess.run(argv, cwd=self.root, env=self.env, capture_output=True, timeout=15)
        self.counter += 1
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr),
                             ("exit", str(result.returncode).encode()+b"\n")):
            (self.home / (str(self.counter) + "." + suffix)).write_bytes(data)
        return result

    def capture(self, status=0):
        return self.invoke(["capture", str(self.run), str(status)])

    def saved(self):
        return audit.decode((self.run / "observation.json").read_bytes())

    def refused(self, reason):
        result = self.capture()
        self.assertEqual(result.returncode, 75, result.stderr)
        saved = self.saved()
        self.assertEqual(saved["outcome"], "FAIL")
        self.assertIn(reason, " ".join(saved["integrity_issues"]))

    def test_actual_producer_consumer_and_one_use(self):
        self.assertEqual(self.capture().returncode, 0)
        self.assertEqual(self.invoke(["check", self.commit]).returncode, 0)
        self.assertEqual(self.saved()["tools"]["audit"]["native_returncode"], 0)
        original = (self.run / "observation.json").read_bytes()
        self.assertEqual(self.capture().returncode, 75)
        self.assertEqual((self.run / "observation.json").read_bytes(), original)

    def test_shell_route_executes_audit_consumer_without_optional_probes(self):
        result = self.invoke(["audit", "0", "--audit-run", str(self.run),
            "bash scripts/ci-doctor.sh audit", "bash ops/ci/audit.sh"], "scripts/ci-observation.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.saved()["evidence_class"], "LOCAL_AUDIT_DIAGNOSTIC")

    def test_canonical_artifact_checker_accepts_exact_local_subject(self):
        self.assertEqual(self.capture().returncode, 0)
        result = self.invoke(["audit", self.commit], "ops/ci/artifact-check.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"exact local diagnostic artifacts passed", result.stdout)

    def test_canonical_artifact_checker_rejects_stale_native_report(self):
        self.assertEqual(self.capture().returncode, 0)
        self.put("audit/.jankurai/repo-score.json", b"{}\n")
        result = self.invoke(["audit", self.commit], "ops/ci/artifact-check.sh")
        self.assertEqual(result.returncode, 75)
        self.assertIn(b"OBSERVATION_OR_ARTIFACT_DRIFT", result.stderr)

    def test_canonical_artifact_checker_rejects_transferred_root(self):
        self.assertEqual(self.capture().returncode, 0)
        transfer = self.home / "transferred"
        shutil.copytree(self.root / ".ci-artifacts", transfer)
        result = self.invoke(["audit", self.commit, str(transfer)], "ops/ci/artifact-check.sh")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"AUDIT_LOCAL_ARTIFACT_SUBJECT_REQUIRED", result.stderr)

    def test_copied_foreign_run_doctor_record_refused(self):
        path = self.run / "doctor.tool.jsonl"
        rows = [audit.decode(x) for x in path.read_bytes().splitlines()]
        rows[0]["record_path"] = str(self.run.with_name("run.FOREIGN1") / path.name)
        self.put(path.name, b"".join(self.json(row) for row in rows))
        self.refused("TOOL_REQUEST_BINDING_MISMATCH:doctor")

    def test_duplicate_tool_event_refused(self):
        path = self.run / "audit.tool.jsonl"
        rows = path.read_bytes().splitlines(keepends=True)
        self.put(path.name, b"".join(rows[:4] + [rows[3]] + rows[4:]))
        self.refused("TOOL_RECORD_ORDER_OR_SCHEMA")

    def test_missing_native_record_refused(self):
        (self.run / "audit.tool.jsonl").unlink()
        self.refused("audit.tool.jsonl")

    def test_extra_report_refused(self):
        self.put("audit-extra.json", b"{}\n")
        self.refused("EXTRA_ARTIFACT")

    def test_missing_snapshot_entry_refused(self):
        (self.run / "audit/.jankurai/repo-score.md").unlink()
        self.refused("SNAPSHOT_INCOMPLETE:audit")

    def test_duplicate_absence_refused(self):
        p = self.run / "before.absent"
        self.put(p.name, p.read_bytes() + p.read_bytes().splitlines(keepends=True)[0])
        self.refused("SNAPSHOT_INCOMPLETE:before")

    def test_lowered_report_policy_refused(self):
        self.report["policy"]["minimum_score"] = 70
        self.report["decision"]["minimum_score"] = 70
        self.refresh_reports()
        self.refused("REPORT_POLICY_MISMATCH:minimum_score")

    def test_weakened_severity_policy_refused(self):
        self.report["policy"]["fail_on"] = ["critical"]
        self.refresh_reports()
        self.refused("REPORT_POLICY_MISMATCH:fail_on")

    def test_wrong_policy_fingerprint_refused(self):
        self.report["policy_fingerprint"] = "sha256:" + "0" * 64
        self.refresh_reports()
        self.refused("POLICY_FINGERPRINT_MISMATCH")

    def test_failed_process_valid_proposal_not_promoted(self):
        path = self.run / "audit.tool.jsonl"
        rows = [audit.decode(x) for x in path.read_bytes().splitlines()]
        rows[-2].update(native_returncode=23, exit_status=23)
        rows[-1]["exit_status"] = 23
        self.put(path.name, b"".join(self.json(row) for row in rows))
        self.refused("TOOL_EXIT_CONTRADICTION")

    def test_native_failure_diagnostic_keeps_primary(self):
        path = self.run / "audit.tool.jsonl"
        rows = [audit.decode(x) for x in path.read_bytes().splitlines()]
        rows[-2].update(native_returncode=23, exit_status=23)
        rows[-1]["exit_status"] = 23
        self.put(path.name, b"".join(self.json(row) for row in rows))
        self.put("audit.exit", b"23\n")
        self.put("lane.exit", b"23\n")
        self.put("result.txt", b"stage=audit\nprimary_status=23\nretention_status=0\nfinal_status=23\n")
        self.assertEqual(self.capture(23).returncode, 0)
        self.assertEqual(self.saved()["outcome"], "FAIL")
        self.assertEqual(self.saved()["primary_status"], 23)
        self.assertEqual(self.invoke(["check", self.commit]).returncode, 75)

    def test_changed_report_after_capture_refused(self):
        self.assertEqual(self.capture().returncode, 0)
        self.put("final/.jankurai/repo-score.md", b"replacement\n")
        self.assertEqual(self.invoke(["check", self.commit]).returncode, 75)

    def test_current_staged_report_drift_refused(self):
        self.put("target/jankurai/repo-score.md", b"stale different report\n", root=True)
        self.refused("CURRENT_ARTIFACT_DRIFT")

    def test_fifo_report_does_not_block(self):
        p = self.run / "audit/.jankurai/repo-score.md"
        p.unlink()
        os.mkfifo(p)
        self.refused("ARTIFACT_KIND_OR_LIMIT")

    def test_staging_failure_preserves_original_diagnostic(self):
        (self.root / ".ci-artifacts/observations").mkdir(parents=True)
        self.put(".ci-artifacts/observations/audit.json", b"foreign existing\n", root=True)
        result = self.capture()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(self.saved()["outcome"], "PASS")
        self.assertEqual((self.root / ".ci-artifacts/observations/audit.json").read_bytes(), b"foreign existing\n")
        self.assertNotIn(b"unsigned local diagnostic", result.stdout)
        self.assertEqual(self.invoke(["check", self.commit]).returncode, 75)

    def test_changed_and_restored_regular_read_refused(self):
        p = self.home / "input"
        p.write_bytes(b"old bytes")
        # A deterministic initial timestamp makes actual replacement writes
        # distinguishable even on a filesystem with coarse timestamp updates.
        os.utime(p, ns=(1, 1))
        read = os.read
        done = False
        def restore(fd, size):
            nonlocal done
            data = read(fd, size)
            if data and not done:
                done = True
                p.write_bytes(b"new bytes")
                p.write_bytes(b"old bytes")
            return data
        with mock.patch.object(audit.os, "read", restore):
            with self.assertRaisesRegex(audit.tool.Refusal, "CHANGED_DURING_READ"):
                audit.read(p)
        self.assertEqual(p.read_bytes(), b"old bytes")

    def test_ratchet_raise_preserved_and_drop_refused(self):
        baseline = json.loads(json.dumps(self.report))
        baseline["score"] = 89
        report = json.loads(json.dumps(self.report))
        report["policy"]["mode"] = "ratchet"
        report["decision"]["ratchet"] = dict(passed=True, allowed_drop=0, baseline_score=89,
            score_delta=1, new_caps=[], new_hard_findings=[], policy_changed=False,
            **{"baseline_" + k: baseline[k] for k in ("report_fingerprint", "input_fingerprint", "policy_fingerprint")})
        audit.policy_report(report, POLICY, baseline)
        report["score"] = 88  # Still above85, but below this exact accepted baseline89.
        with self.assertRaisesRegex(audit.tool.Refusal, "RATCHET_SCORE_DROP"):
            audit.policy_report(report, POLICY, baseline)

    def test_duplicate_json_policy_key_refused(self):
        p = self.run / "audit/.jankurai/repo-score.json"
        self.put(str(p.relative_to(self.run)), p.read_bytes().replace(b'"score": 90', b'"score": 90, "score": 70'))
        self.refused("DUPLICATE_JSON_KEY:score")

    def test_full_ratchet_run_binds_distinct_native_record_and_baseline(self):
        baseline = json.loads(json.dumps(self.report))
        baseline["score"] = 89
        path = "target/jankurai/accepted-baseline.json"
        previous = {path: self.json(baseline)}
        self.put(path, previous[path], root=True)
        self.snapshot("before", previous)
        self.snapshot("ratchet", previous)
        for phase in ("audit", "final"):
            current = {p: (self.run / phase / p).read_bytes() for p in audit.ARTIFACTS if (self.run / phase / p).exists()}
            self.snapshot(phase, {**current, **previous})
        report = json.loads(json.dumps(self.report))
        report["policy"]["mode"] = "ratchet"
        report["decision"]["ratchet"] = dict(passed=True, allowed_drop=0, baseline_score=89,
            score_delta=1, new_caps=[], new_hard_findings=[], policy_changed=False,
            **{"baseline_" + k: baseline[k] for k in ("report_fingerprint", "input_fingerprint", "policy_fingerprint")})
        self.put("ratchet.json", self.json(report))
        self.put("ratchet.md", b"fixture ratchet report\n")
        self.tool_rows("ratchet", ["audit", ".", "--full", "--no-score-history", "--mode", "ratchet",
            "--baseline", path, "--json", str(self.run / "ratchet.json"), "--md", str(self.run / "ratchet.md")])
        for suffix in ("stdout", "stderr", "validation.stdout", "validation.stderr"):
            self.put("ratchet." + suffix, b"")
        self.put("ratchet.exit", b"0\n")
        self.put("ratchet.validation.exit", b"0\n")
        self.assertEqual(self.capture().returncode, 0)
        self.assertEqual(set(self.saved()["tools"]), {"doctor", "ratchet", "audit"})
        self.assertEqual(self.invoke(["check", self.commit]).returncode, 0)

    def test_shared_report_entry_rejects_lowered_policy(self):
        path = "audit/.jankurai/repo-score.json"
        self.assertEqual(self.invoke(["report", str(self.run / path)]).returncode, 0)
        self.report["policy"]["minimum_score"] = 70
        self.refresh_reports()
        result = self.invoke(["report", str(self.run / path)])
        self.assertEqual(result.returncode, 75)
        self.assertIn(b"REPORT_POLICY_MISMATCH:minimum_score", result.stderr)

    def test_doctor_refusal_has_no_native_or_lane_completion(self):
        request = audit.decode((self.run / "doctor.tool.jsonl").read_bytes().splitlines()[0])
        for p in list(self.run.iterdir()):
            if p.name not in ("invocation.json", "doctor.argv", "doctor.stdout", "doctor.stderr"):
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
        self.put("doctor.exit", b"75\n")
        refusal = dict(schema="bullet.local-auditor-tool.v1", event="refused", sequence=1,
            time_ns="2", evidence_class="LOCAL_TOOL_DIAGNOSTIC", reason="fixture checksum refusal",
            native_status=None, exit_status=75)
        self.put("doctor.tool.jsonl", self.json(request) + self.json(refusal))
        self.assertEqual(self.capture(75).returncode, 0)
        self.assertEqual(self.saved()["outcome"], "FAIL")
        self.assertEqual(set(self.saved()["tools"]), {"doctor"})
        self.assertIsNone(self.saved()["tools"]["doctor"]["native_returncode"])

    def test_failed_capture_preserves_other_report_hashes(self):
        self.put("unexpected-report.json", b"unexpected retained report\n")
        self.refused("EXTRA_ARTIFACT")
        paths = {f["path"] for f in self.saved()["artifact_hashes"]}
        self.assertIn("unexpected-report.json", paths)
        self.assertIn("final/.jankurai/repo-score.json", paths)

    def test_missing_policy_still_retains_failed_diagnostic(self):
        (self.root / "agent/audit-policy.toml").unlink()
        self.assertEqual(self.capture().returncode, 75)
        self.assertEqual(self.saved()["outcome"], "FAIL")
        self.assertTrue(self.saved()["artifact_hashes"])


if __name__ == "__main__":
    print("Local observation component fixtures retained:", EVIDENCE, flush=True)
    unittest.main(verbosity=2)
