#!/usr/bin/env python3
"""CI-only Linux artifact admission beneath ci-local; no proof/release authority."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

PROFILE = "local-linux-x86_64-gnu-jankurai-1.6.11"
PINNED_SHA256 = "9e6b8857a26f6004d4c74e510e13b06d880f2e2ae0c89502698889ed690c5d6c"
PINNED_SIZE = 19484592
EXPECTED_VERSION = b"jankurai 1.6.11"
INSTALL_RECEIPT = "40749914e412bc54f62c872884a76d287d48e359a4a7b3ddb0efc9d4ffbdd43a"
SOURCE_COMMIT = "b88562fdb124aa86dedd70ab972e7d0d87e58be1"
MAX_VERSION_BYTES = 65536


class Refusal(Exception):
    pass


def identity(value):
    return dict(device=str(value.st_dev), inode=str(value.st_ino), mode=value.st_mode,
                uid=value.st_uid, gid=value.st_gid, size=value.st_size,
                links=value.st_nlink, mtime_ns=str(value.st_mtime_ns),
                ctime_ns=str(value.st_ctime_ns))


def absolute_parts(path):
    if (not path.startswith("/") or len(path) > 4096 or "\0" in path
            or any(part in ("", ".", "..") for part in path.split("/")[1:])):
        raise Refusal("NONNORMAL_ABSOLUTE_PATH")
    return path.split("/")[1:]


def open_parent(path):
    parts = absolute_parts(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    lookups = []
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            item = identity(os.fstat(fd))
            lookups.append({key: item[key] for key in ("device", "inode", "mode", "uid", "gid")})
        return fd, parts[-1], lookups
    except BaseException:
        os.close(fd)
        raise


def open_candidate(path):
    parent, name, lookups = open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        return fd, lookups
    finally:
        os.close(parent)


class Record:
    def __init__(self, path):
        self.path = path
        self.parent, self.name, _ = open_parent(path)
        try:
            self.fd = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                              | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
            os.fsync(self.parent)
        except BaseException:
            os.close(self.parent)
            raise
        self.sequence = 0

    def append(self, event, **fields):
        row = {"schema": "bullet.local-auditor-tool.v1", "sequence": self.sequence,
               "time_ns": str(time.time_ns()), "event": event,
               "evidence_class": "LOCAL_TOOL_DIAGNOSTIC", **fields}
        data = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        while data:
            count = os.write(self.fd, data)
            if count <= 0:
                raise OSError("record write made no progress")
            data = data[count:]
        os.fsync(self.fd)
        self.sequence += 1

    def stream(self, suffix):
        fd = os.open(self.name + suffix, os.O_RDWR | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
        return os.fdopen(fd, "w+b")

    def close(self):
        os.close(self.fd)
        os.close(self.parent)


def validate_argv(argv):
    if argv == ["--version"]:
        return
    if argv[:4] != ["audit", ".", "--full", "--no-score-history"]:
        raise Refusal("UNSUPPORTED_TOOL_ARGV")
    rest = argv[4:]
    if len(rest) % 2 or len(rest) > 10:
        raise Refusal("UNSUPPORTED_TOOL_ARGV")
    values = {}
    for option, value in zip(rest[::2], rest[1::2]):
        if (option not in ("--json", "--md", "--repair-queue-jsonl", "--mode", "--baseline")
                or option in values or not value or len(value) > 4096 or "\0" in value):
            raise Refusal("UNSUPPORTED_TOOL_ARGV")
        values[option] = value
    if not {"--json", "--md"}.issubset(values):
        raise Refusal("AUDIT_REPORT_PATHS_REQUIRED")
    if ("--mode" in values) != ("--baseline" in values):
        raise Refusal("INCOMPLETE_RATCHET_ARGV")
    if "--mode" in values and values["--mode"] != "ratchet":
        raise Refusal("UNSUPPORTED_AUDIT_MODE")


def admit(candidate, record):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise Refusal("UNSUPPORTED_LOCAL_TOOL_PROFILE")
    if not all(hasattr(os, name) for name in ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")):
        raise Refusal("SEALED_EXECUTABLE_UNAVAILABLE")
    source, lookups = open_candidate(candidate)
    sealed = None
    try:
        before = os.fstat(source)
        record.append("candidate_opened", path=candidate, identity=identity(before),
                      ancestor_identities=lookups)
        if (not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111
                or before.st_size != PINNED_SIZE):
            raise Refusal("CANDIDATE_KIND_MODE_OR_SIZE_MISMATCH")
        sealed = os.memfd_create("bullet-auditor", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        digest = hashlib.sha256()
        copied = 0
        header = b""
        while chunk := os.read(source, 1024 * 1024):
            if not header:
                header = chunk[:20]
            copied += len(chunk)
            if copied > PINNED_SIZE:
                raise Refusal("CANDIDATE_SIZE_CHANGED")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(sealed, view)
                if count <= 0:
                    raise OSError("memfd write made no progress")
                view = view[count:]
        observed = digest.hexdigest()
        record.append("candidate_read", path=candidate, identity=identity(before),
                      ancestor_identities=lookups, sha256=observed, copied_bytes=copied)
        if (copied != PINNED_SIZE or identity(before) != identity(os.fstat(source))):
            raise Refusal("CANDIDATE_CHANGED_DURING_READ")
        check, current_lookups = open_candidate(candidate)
        try:
            if identity(before) != identity(os.fstat(check)) or lookups != current_lookups:
                raise Refusal("CANDIDATE_LOOKUP_CHANGED")
        finally:
            os.close(check)
        if observed != PINNED_SHA256:
            raise Refusal("CANDIDATE_SHA256_MISMATCH")
        if header[:7] != b"\x7fELF\x02\x01\x01" or header[18:20] != b"\x3e\x00":
            raise Refusal("CANDIDATE_ELF_PROFILE_MISMATCH")
        os.fchmod(sealed, 0o500)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(sealed, fcntl.F_GET_SEALS) != seals:
            raise Refusal("EXECUTABLE_SEAL_MISMATCH")
        os.lseek(sealed, 0, os.SEEK_SET)
        readback = hashlib.sha256()
        while chunk := os.read(sealed, 1024 * 1024):
            readback.update(chunk)
        if readback.hexdigest() != PINNED_SHA256:
            raise Refusal("SEALED_ARTIFACT_DIGEST_MISMATCH")
        record.append("admitted", sha256=readback.hexdigest(), size=copied, seals=seals,
                      executable_identity=identity(os.fstat(sealed)))
        result, sealed = sealed, None
        return result
    finally:
        os.close(source)
        if sealed is not None:
            os.close(sealed)


def run_child(executable, argv, record, state):
    environment = dict(os.environ)
    if any(key.startswith("LD_") or key in ("GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH")
           for key in environment):
        raise Refusal("DYNAMIC_LOADER_ENVIRONMENT_REFUSED")
    environment["JANKURAI_NO_UPDATE_CHECK"] = "1"
    version = argv == ["--version"]
    streams = [record.stream(".stdout"), record.stream(".stderr")] if version else []
    child = None
    try:
        record.append("launch_intent", argv=["jankurai", *argv],
                      executable=f"/proc/self/fd/{executable}",
                      inherited_environment_keys=sorted(environment),
                      update_check="disabled_by_JANKURAI_NO_UPDATE_CHECK_1",
                      inherited_fds=[0, 1, 2] if not version else [0],
                      passed_executable_fd=executable, streams="retained" if version else "caller_owned",
                      limitations="No source/runtime closure, process-tree supervision, network containment or release authority")
        child = subprocess.Popen(["jankurai", *argv], executable=f"/proc/self/fd/{executable}",
                                 pass_fds=(executable,), close_fds=True, env=environment,
                                 stdout=streams[0] if version else None,
                                 stderr=streams[1] if version else None)
        record.append("started", pid=child.pid)
        native = child.wait(timeout=15 if version else None)
        state["native_status"] = native if native >= 0 else 128 - native
        record.append("terminated", native_returncode=native, exit_status=state["native_status"])
        if version:
            output = []
            for stream in streams:
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
                data = stream.read(MAX_VERSION_BYTES + 1)
                if len(data) > MAX_VERSION_BYTES:
                    raise Refusal("VERSION_OUTPUT_LIMIT")
                output.append(data)
            record.append("version_output", stdout_base64=base64.b64encode(output[0]).decode(),
                          stderr_base64=base64.b64encode(output[1]).decode())
            sys.stdout.buffer.write(output[0])
            sys.stderr.buffer.write(output[1])
            if native == 0 and (output[0].rstrip(b"\r\n") != EXPECTED_VERSION or output[1]):
                raise Refusal("VERSION_OUTPUT_MISMATCH")
        return state["native_status"]
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("jankurai-tool: CHILD_TERMINATION_UNKNOWN", file=sys.stderr)
        for stream in streams:
            stream.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    record = None
    executable = None
    state = {"native_status": None}
    try:
        record = Record(args.record)
        record.append("request", profile=PROFILE, candidate=args.candidate, argv=command,
                      record_path=args.record,
                      pinned_sha256=PINNED_SHA256, pinned_size=PINNED_SIZE,
                      install_receipt_sha256=INSTALL_RECEIPT, source_commit=SOURCE_COMMIT,
                      provenance_is_distribution_acceptance=False)
        validate_argv(command)
        executable = admit(args.candidate, record)
        status = run_child(executable, command, record, state)
        record.append("complete", exit_status=status)
        return status
    except (OSError, Refusal, subprocess.TimeoutExpired) as error:
        code = type(error).__name__ + ": " + str(error)
        primary = state["native_status"]
        status = primary if primary not in (None, 0) else 75
        if record is not None:
            try:
                record.append("refused", reason=code, native_status=primary, exit_status=status)
            except OSError:
                print("jankurai-tool: RECORD_PERSISTENCE_FAILED", file=sys.stderr)
        print("jankurai-tool: " + code, file=sys.stderr)
        return status
    finally:
        if executable is not None:
            os.close(executable)
        if record is not None:
            record.close()


if __name__ == "__main__":
    sys.exit(main())
