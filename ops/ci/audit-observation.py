#!/usr/bin/env python3
"""Unsigned local audit diagnostics, beneath the existing lane and artifact checker."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("auditor_tool", Path(__file__).with_name("jankurai-tool.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
SCHEMA = "bullet.local-audit-observation.v1"
CLASS = "LOCAL_AUDIT_DIAGNOSTIC"
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 256 * 1024**2, 256
REPORTS = ("repo-score.json", "repo-score.md", "repair-queue.jsonl")
ARTIFACTS = (".ci-artifacts/observations/audit.json", "target/jankurai/audit-state.json",
    "target/jankurai/update/state.json", "target/jankurai/accepted-baseline.json",
    *("target/jankurai/" + p for p in REPORTS),
    *(".jankurai/" + p for p in (*REPORTS, "repo-score-current.json", "repo-score-current.md", "score-history.jsonl")))
PHASES = ("before", "ratchet", "audit", "final")
# These belong to the still-running observation stage, never to native evidence.
PRODUCER_OUTPUTS = ("observation.argv", "observation.stdout", "observation.stderr",
                    "observation.exit", "observation.json")
FIXED = {"invocation.json", "previous-observation.json", "audit.started", "result.txt",
         "retention.stderr", "staging.stderr", "ratchet.json", "ratchet.md"}
FIXED.update(n + "." + s for n in ("doctor", "lane", "audit", "ratchet")
             for s in ("stdout", "stderr", "exit"))
FIXED.update(n + ".argv" for n in ("doctor", "lane"))
FIXED.update(n + ".tool.jsonl" for n in ("doctor", "audit", "ratchet"))
FIXED.update("doctor.tool.jsonl." + s for s in ("stdout", "stderr"))
FIXED.update(n + ".validation." + s for n in ("audit", "ratchet") for s in ("stdout", "stderr", "exit"))
FIXED.update(p + ".absent" for p in PHASES)
FIXED.update(p + "/" + a for p in PHASES for a in ARTIFACTS)


def require(condition, reason):
    if not condition:
        raise tool.Refusal(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY:" + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, "NONFINITE_JSON"))


def read(path):
    fd, ancestors = tool.open_candidate(str(path))
    try:
        before = tool.identity(os.fstat(fd))
        require(stat.S_ISREG(before["mode"]) and before["size"] <= MAX_FILE, "ARTIFACT_KIND_OR_LIMIT")
        chunks, count = [], 0
        while chunk := os.read(fd, min(1024**2, MAX_FILE + 1 - count)):
            count += len(chunk)
            require(count <= MAX_FILE, "ARTIFACT_LIMIT")
            chunks.append(chunk)
        require(before == tool.identity(os.fstat(fd)), "ARTIFACT_CHANGED_DURING_READ")
        check, current = tool.open_candidate(str(path))
        try:
            require(before == tool.identity(os.fstat(check)) and ancestors == current, "ARTIFACT_LOOKUP_CHANGED")
        finally:
            os.close(check)
        data = b"".join(chunks)
        return data, dict(sha256=hashlib.sha256(data).hexdigest(), size=len(data), identity=before)
    finally:
        os.close(fd)


def publish(path, data):
    # Exclusive outputs preserve any interrupted predecessor for reconciliation.
    parent, leaf, _ = tool.open_parent(str(path))
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                require(count > 0, "OUTPUT_WRITE_NO_PROGRESS")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    require(read(path)[0] == data, "OUTPUT_READBACK_MISMATCH")


def integer(value):
    return type(value) is int and 0 <= value <= 255


def policy_report(report, policy_bytes, baseline=None):
    # Matches pinned native load_policy and raw-byte file_fingerprint; no CLI override.
    policy = tomllib.loads(policy_bytes.decode())
    minimum = policy["minimum_score"]
    require(type(minimum) is int and minimum >= 65, "SOURCE_POLICY_BELOW_FLOOR")
    observed = report["policy"]
    for key in ("minimum_score", "fail_on", "advisory_on"):
        require(observed[key] == policy[key], "REPORT_POLICY_MISMATCH:" + key)
    require(report["policy_fingerprint"] == "sha256:" + hashlib.sha256(policy_bytes).hexdigest(), "POLICY_FINGERPRINT_MISMATCH")
    decision = report["decision"]
    require(type(report["score"]) is int and report["score"] >= minimum
            and decision["passed"] is True and decision["status"] == "pass"
            and type(decision["minimum_score"]) is int and decision["minimum_score"] == minimum
            and type(decision["hard_findings"]) is int and decision["hard_findings"] == 0,
            "REPORT_DECISION_NOT_PASSING")
    require(not any(f["severity"] in policy["fail_on"] for f in report["findings"]), "HARD_FINDING_IN_PASS")
    require(observed["mode"] == ("ratchet" if baseline is not None else "standard"), "REPORT_MODE_MISMATCH")
    if baseline is not None:
        ratchet = decision["ratchet"]
        require(type(baseline["score"]) is int and report["score"] >= baseline["score"], "RATCHET_SCORE_DROP")
        require(ratchet["passed"] is True and ratchet["allowed_drop"] == 0
                and ratchet["baseline_score"] == baseline["score"]
                and ratchet["score_delta"] == report["score"] - baseline["score"]
                and ratchet["new_caps"] == [] and ratchet["new_hard_findings"] == []
                and ratchet["policy_changed"] is False, "RATCHET_DECISION_MISMATCH")
        for key in ("report_fingerprint", "input_fingerprint", "policy_fingerprint"):
            require(ratchet["baseline_" + key] == baseline[key], "RATCHET_BASELINE_MISMATCH")
        for key in ("policy_fingerprint", "schema_version", "standard_version"):
            require(report[key] == baseline[key], "RATCHET_POLICY_OR_VERSION_DRIFT")
        require(set(report["caps_applied"]) <= set(baseline["caps_applied"]), "RATCHET_NEW_CAP")
        old = {f["fingerprint"] for f in baseline["findings"] if f["severity"] in ("critical", "high")}
        require(all(f["fingerprint"] in old for f in report["findings"] if f["severity"] in ("critical", "high")), "RATCHET_NEW_HARD_FINDING")


class Observation:
    def __init__(self, root, run, status, parent=None):
        self.root, self.run, self.status = root, run, status
        tool.absolute_parts(str(root))
        require(run.parent == root / "target/jankurai/audit-runs"
                and re.fullmatch(r"run\.[A-Za-z0-9]{8}", run.name), "AUDIT_RUN_PATH_INVALID")
        fd, _, _ = tool.open_parent(str(run / "invocation.json"))
        try:
            s = os.fstat(fd)
            require(stat.S_IMODE(s.st_mode) == 0o700 and s.st_uid == os.getuid(), "AUDIT_RUN_OWNER_INVALID")
        finally:
            os.close(fd)
        raw, item = read(run / "invocation.json")
        self.invocation = decode(raw)
        pid = self.invocation.get("parent_pid")
        require(type(pid) is int and pid > 0 and (parent is None or pid == parent), "AUDIT_RUN_PARENT_MISMATCH")
        require(self.invocation == dict(schema="bullet.audit-invocation.v1", id=run.name,
                repository=str(root), origin="dispatcher", parent_pid=pid)
                and stat.S_IMODE(item["identity"]["mode"]) == 0o600
                and item["identity"]["uid"] == os.getuid() and integer(status), "AUDIT_INVOCATION_INVALID")
        self.files, self.data, self.issues, self.tools, self.omissions = [], {}, [], {}, []

    def inventory(self):
        allowed = FIXED | set(PRODUCER_OUTPUTS)
        directories = {str(Path(p).parent) for p in allowed}
        directories |= {str(a) for p in allowed for a in Path(p).parents}
        pending, total, entries = [self.run], 0, 0
        while pending:
            directory = pending.pop()
            for path in sorted(directory.iterdir()):
                entries += 1
                require(entries <= MAX_FILES, "INVENTORY_ENTRY_LIMIT")
                relative = path.relative_to(self.run).as_posix()
                kind = path.lstat().st_mode
                if stat.S_ISDIR(kind):
                    if relative not in directories:
                        self.issues.append("EXTRA_DIRECTORY:" + relative)
                        self.omissions.append(relative + "/")
                        continue
                    pending.append(path)
                else:
                    if relative not in allowed:
                        self.issues.append("EXTRA_ARTIFACT:" + relative)
                    if relative in PRODUCER_OUTPUTS:
                        require(stat.S_ISREG(kind), "PRODUCER_OUTPUT_NOT_REGULAR")
                        continue
                    try:
                        require(not stat.S_ISLNK(kind), "ARTIFACT_SYMLINK:" + relative)
                        data, item = read(path)
                    except (OSError, tool.Refusal) as error:
                        self.issues.append(type(error).__name__ + ": " + str(error))
                        self.omissions.append(relative)
                        continue
                    total += len(data)
                    require(total <= MAX_TOTAL, "INVENTORY_BYTE_LIMIT")
                    self.files.append(dict(path=relative, **item))
                    self.data[relative] = data
        self.files.sort(key=lambda item: item["path"])

    def exit(self, path):
        value = self.data[path]
        require(re.fullmatch(rb"(0|[1-9][0-9]{0,2})\n", value) is not None, "EXIT_RECORD_INVALID:" + path)
        result = int(value)
        require(integer(result), "EXIT_RECORD_RANGE")
        return result

    def argv(self, name, expected):
        require(self.data[name + ".argv"] == b"".join(s.encode() + b"\0" for s in expected), "STAGE_ARGV_MISMATCH:" + name)
        for suffix in ("stdout", "stderr"):
            require(name + "." + suffix in self.data, "STAGE_STREAM_MISSING:" + name)

    def tool_record(self, name, argv, expected_status):
        path = name + ".tool.jsonl"
        raw = self.data[path]
        require(raw.endswith(b"\n"), "TRUNCATED_TOOL_RECORD")
        rows = [decode(line) for line in raw.splitlines()]
        require(1 <= len(rows) <= 10, "TOOL_RECORD_BOUND")
        events = [r["event"] for r in rows]
        for i, row in enumerate(rows):
            require(row["schema"] == "bullet.local-auditor-tool.v1" and type(row["sequence"]) is int and row["sequence"] == i
                    and row["evidence_class"] == "LOCAL_TOOL_DIAGNOSTIC"
                    and re.fullmatch(r"[0-9]{1,24}", row["time_ns"]), "TOOL_RECORD_ORDER_OR_SCHEMA")
        order = ["request", "candidate_opened", "candidate_read", "admitted", "launch_intent", "started", "terminated"]
        if name == "doctor":
            order.append("version_output")
        terminal = events[-1]
        require(terminal in ("complete", "refused") and events[:-1] == order[:len(events)-1], "TOOL_EVENTS_INVALID")
        require(terminal != "complete" or events[:-1] == order, "TOOL_COMPLETION_INCOMPLETE")
        require(terminal != "refused" or expected_status != 0, "REFUSED_TOOL_REPORTED_PASS")
        request = rows[0]
        expected = dict(profile=tool.PROFILE, record_path=str(self.run / path), argv=argv,
            pinned_sha256=tool.PINNED_SHA256, pinned_size=tool.PINNED_SIZE,
            install_receipt_sha256=tool.INSTALL_RECEIPT, source_commit=tool.SOURCE_COMMIT,
            provenance_is_distribution_acceptance=False)
        require(all(request[k] == v for k, v in expected.items()), "TOOL_REQUEST_BINDING_MISMATCH:" + name)
        tool.absolute_parts(request["candidate"])
        by_event = {r["event"]: r for r in rows}
        if "admitted" in by_event:
            admitted = by_event["admitted"]
            require(admitted["sha256"] == tool.PINNED_SHA256 and admitted["size"] == tool.PINNED_SIZE
                    and admitted["seals"] == 15, "ADMITTED_TOOL_MISMATCH")
            candidate_read = by_event["candidate_read"]
            require(candidate_read["path"] == request["candidate"]
                    and by_event["candidate_opened"]["path"] == request["candidate"]
                    and candidate_read["sha256"] == tool.PINNED_SHA256
                    and candidate_read["copied_bytes"] == tool.PINNED_SIZE, "CANDIDATE_READ_MISMATCH")
        if "launch_intent" in by_event:
            launch = by_event["launch_intent"]
            require(launch["argv"] == ["jankurai", *argv]
                    and launch["executable"] == "/proc/self/fd/" + str(launch["passed_executable_fd"])
                    and type(launch["passed_executable_fd"]) is int and launch["passed_executable_fd"] >= 3
                    and launch["update_check"] == "disabled_by_JANKURAI_NO_UPDATE_CHECK_1", "TOOL_LAUNCH_MISMATCH")
        native = by_event.get("terminated", {}).get("native_returncode")
        if "started" in by_event:
            require(type(by_event["started"]["pid"]) is int and by_event["started"]["pid"] > 0, "NATIVE_PID_INVALID")
        if "terminated" in by_event:
            require(type(native) is int and by_event["terminated"]["exit_status"] == (native if native >= 0 else 128-native), "NATIVE_STATUS_CONTRADICTION")
        require(rows[-1]["exit_status"] == expected_status, "TOOL_EXIT_CONTRADICTION")
        if terminal == "complete":
            require(by_event["terminated"]["exit_status"] == expected_status, "COMPLETE_EXIT_CONTRADICTION")
        else:
            native_status = by_event.get("terminated", {}).get("exit_status")
            require(rows[-1]["native_status"] == native_status
                    and expected_status == (native_status if native_status not in (None, 0) else 75), "REFUSAL_STATUS_CONTRADICTION")
        if name == "doctor" and expected_status == 0:
            version = by_event["version_output"]
            stdout = base64.b64decode(version["stdout_base64"], validate=True)
            stderr = base64.b64decode(version["stderr_base64"], validate=True)
            require(stdout == self.data[path + ".stdout"] and stderr == self.data[path + ".stderr"]
                    and stdout.rstrip(b"\r\n") == tool.EXPECTED_VERSION and stderr == b"", "ACTUAL_VERSION_MISMATCH")
        self.tools[name] = dict(record=path, candidate=request["candidate"],
            admitted_sha256=by_event.get("admitted", {}).get("sha256"), native_returncode=native,
            helper_exit=expected_status, version=tool.EXPECTED_VERSION.decode() if name == "doctor" and expected_status == 0 else None)

    def snapshot(self, phase):
        present = {a for a in ARTIFACTS if phase + "/" + a in self.data}
        absent = self.data.get(phase + ".absent", b"").decode().splitlines()
        require(len(absent) == len(set(absent)) and present.isdisjoint(absent)
                and present | set(absent) == set(ARTIFACTS), "SNAPSHOT_INCOMPLETE:" + phase)
        return present

    def validate(self, policy):
        self.argv("doctor", ["bash", "scripts/ci-doctor.sh", "audit", "--audit-run", str(self.run)])
        doctor = self.exit("doctor.exit")
        self.tool_record("doctor", ["--version"], doctor)
        if doctor:
            require(self.status == doctor and not any(p.startswith(("lane.", "audit.", "ratchet.", "before/", "final/")) for p in self.data), "DOCTOR_FAILURE_LAUNCHED_LANE")
            return
        self.argv("lane", ["bash", "ops/ci/audit.sh", "--audit-run", str(self.run)])
        lane = self.exit("lane.exit")
        require(lane == self.status and re.fullmatch(rb"pid=[1-9][0-9]*\n", self.data["audit.started"]), "LANE_STATUS_OR_START_MISMATCH")
        result = unique(line.split("=", 1) for line in self.data["result.txt"].decode().splitlines())
        require(set(result) == {"stage", "primary_status", "retention_status", "final_status"}, "RESULT_FIELDS_INVALID")
        require(all(re.fullmatch(r"0|[1-9][0-9]{0,2}", result[k]) and integer(int(result[k]))
                    for k in ("primary_status", "retention_status", "final_status")), "RESULT_STATUS_INVALID")
        require(result["final_status"] == str(lane), "RESULT_EXIT_CONTRADICTION")
        self.snapshot("before")
        self.snapshot("final")
        baseline_path = "target/jankurai/accepted-baseline.json"
        baseline = decode(self.data["before/" + baseline_path]) if "before/" + baseline_path in self.data else None
        for name in ("ratchet", "audit"):
            if name == "ratchet" and baseline is None:
                require(not any(p.startswith("ratchet") for p in self.data), "UNEXPECTED_RATCHET")
                continue
            if name + ".exit" not in self.data:
                require(lane != 0, "MISSING_NATIVE_RUN:" + name)
                continue
            status = self.exit(name + ".exit")
            argv = ["audit", ".", "--full", "--no-score-history"]
            argv += (["--mode", "ratchet", "--baseline", baseline_path, "--json", str(self.run / "ratchet.json"), "--md", str(self.run / "ratchet.md")]
                     if name == "ratchet" else ["--repair-queue-jsonl", ".jankurai/repair-queue.jsonl", "--json", ".jankurai/repo-score.json", "--md", ".jankurai/repo-score.md"])
            self.tool_record(name, argv, status)
            self.snapshot(name)
            require(status == 0 or (lane == status and result["primary_status"] == str(status)), "NATIVE_FAILURE_PROMOTED")
            if status == 0:
                require(self.exit(name + ".validation.exit") == 0 or lane != 0, "VALIDATION_FAILURE_PROMOTED")
                report = decode(self.data["ratchet.json" if name == "ratchet" else "audit/.jankurai/repo-score.json"])
                policy_report(report, policy, baseline if name == "ratchet" else None)
        if lane == 0:
            require(result == dict(stage="complete", primary_status="0", retention_status="0", final_status="0"), "PASS_WITH_INCOMPLETE_SETTLEMENT")
            for name in REPORTS:
                original = self.data["audit/.jankurai/" + name]
                require(original == self.data["final/.jankurai/" + name]
                        == self.data["final/target/jankurai/" + name], "STAGED_REPORT_MISMATCH")
            for name in ("target/jankurai/update/state.json", baseline_path):
                require(self.data.get("before/" + name) == self.data.get("final/" + name), "STATE_OR_BASELINE_CHANGED")
            require("final/.jankurai/score-history.jsonl" not in self.data, "UNEXPECTED_SCORE_HISTORY_WRITE")
            for path in ARTIFACTS:
                if path == ".ci-artifacts/observations/audit.json":
                    continue  # This producer publishes it after native settlement.
                try:
                    current = read(self.root / path)[0]
                except FileNotFoundError:
                    current = None
                require(self.data.get("final/" + path) == current, "CURRENT_ARTIFACT_DRIFT:" + path)


def git(root, *argv):
    result = subprocess.run(["git", *argv], cwd=root, capture_output=True, timeout=15, check=True)
    require(len(result.stdout) <= MAX_FILE and len(result.stderr) <= MAX_FILE, "GIT_OUTPUT_LIMIT")
    return result.stdout


def collect(root, run, status, parent=None):
    observation = Observation(root, run, status, parent)
    commit, tree, clean, policy_subject = None, None, False, None
    try:
        observation.inventory()
        source, policy_subject = read(root / "agent/audit-policy.toml")
        commit = git(root, "rev-parse", "HEAD").decode().strip()
        tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
        clean = not git(root, "status", "--porcelain", "--untracked-files=normal")
        require(git(root, "show", "HEAD:agent/audit-policy.toml") == source, "UNCOMMITTED_POLICY")
        observation.validate(source)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tool.Refusal) as error:
        observation.issues.append(type(error).__name__ + ": " + str(error))
    return dict(schema_version=SCHEMA, repository="bullet-git", commit_oid=commit, tree_oid=tree,
        clean=clean, invocation=observation.invocation, run_path=str(run), signed=False,
        evidence_class=CLASS, artifact_hashes=observation.files, tools=observation.tools,
        policy_subject=policy_subject, primary_status=status, integrity_issues=observation.issues,
        omitted_artifacts=observation.omissions,
        outcome="PASS" if status == 0 and not observation.issues else "FAIL",
        producer_outputs_excluded=list(PRODUCER_OUTPUTS),
        limitations="Unsigned local point-in-time diagnostics; no continuous source/runtime custody, installed distribution or aggregate event acceptance")


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    root = Path(__file__).absolute().parents[2]
    try:
        if len(args) in (2, 3) and args[0] == "report":
            policy = read(root / "agent/audit-policy.toml")[0]
            require(git(root, "show", "HEAD:agent/audit-policy.toml") == policy, "UNCOMMITTED_POLICY")
            report = decode(read(root / args[1])[0])
            baseline = decode(read(root / args[2])[0]) if len(args) == 3 else None
            policy_report(report, policy, baseline)
            print("audit-observation: native report matches committed policy")
            return 0
        if len(args) == 3 and args[0] == "capture":
            run, status = Path(args[1]), int(args[2])
            report = collect(root, run, status, os.getppid())
            data = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
            publish(run / "observation.json", data)
            for directory in (root / ".ci-artifacts", root / ".ci-artifacts/observations"):
                try:
                    directory.mkdir(mode=0o700)
                except FileExistsError:
                    require(stat.S_ISDIR(directory.lstat().st_mode), "OUTPUT_DIRECTORY_INVALID")
            publish(root / ".ci-artifacts/observations/audit.json", data)
            print("audit-observation: " + report["outcome"] + " (unsigned local diagnostic)")
            return 75 if report["integrity_issues"] else 0
        if len(args) == 2 and args[0] == "check":
            path = root / ".ci-artifacts/observations/audit.json"
            raw = read(path)[0]
            saved = decode(raw)
            run = Path(saved["run_path"])
            require(read(run / "observation.json")[0] == raw, "PUBLISHED_OBSERVATION_MISMATCH")
            current = collect(root, run, saved["primary_status"])
            require(saved == current, "OBSERVATION_OR_ARTIFACT_DRIFT")
            require(saved["commit_oid"] == args[1] and saved["clean"] is True
                    and saved["outcome"] == "PASS", "LOCAL_AUDIT_NOT_PASSING")
            print("audit-observation: exact local diagnostic artifacts passed")
            return 0
        raise tool.Refusal("usage: audit-observation.py capture <run> <status> | check <commit> | report <json> [baseline]")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tool.Refusal) as error:
        print("audit-observation: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
