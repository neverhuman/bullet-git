#!/usr/bin/env python3
"""Isolate only an observed Actions Runner.Worker channel before CI exec.

Runner v2.337.0 ProcessChannel/JobDispatcher pass two inheritable anonymous
pipes as `Runner.Worker spawnclient <input> <output>`. Hosted diagnostics bound
those exact pipes across the ancestor chain. This launcher marks only matching
copies CLOEXEC; it neither changes the runner's copies nor admits an auditor FD.
Unknown descriptors remain untouched for the production refusal/hostile tests.
"""
import fcntl
import os
from pathlib import Path
import stat
import sys


class Refusal(Exception):
    pass


def require(condition):
    if not condition:
        raise Refusal()


def bounded(path):
    with open(path, "rb") as stream:
        value = stream.read(65537)
    require(len(value) <= 65536)
    return value


def process(pid):
    fields = bounded(f"/proc/{pid}/stat").rsplit(b")", 1)[1].split()
    return int(fields[1]), int(fields[19])


def identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def remote_fd(pid, fd):
    before = os.stat(f"/proc/{pid}/fd/{fd}")
    fields = [line[6:].strip() for line in bounded(f"/proc/{pid}/fdinfo/{fd}").splitlines()
              if line.startswith(b"flags:")]
    require(len(fields) == 1 and fields[0] and all(c in b"01234567" for c in fields[0]))
    flags = int(fields[0], 8)
    require(identity(before) == identity(os.stat(f"/proc/{pid}/fd/{fd}")))
    return identity(before), flags


def worker_pair(pid):
    # Values are classified internally, never logged. No target content is read.
    if Path(os.readlink(f"/proc/{pid}/exe")).name != "Runner.Worker":
        return None
    arguments = bounded(f"/proc/{pid}/cmdline").split(b"\0")
    require(len(arguments) == 5 and arguments[-1] == b"" and arguments[1] == b"spawnclient")
    require(Path(os.fsdecode(arguments[0])).name == "Runner.Worker")
    pair = arguments[2:4]
    require(all(value and value.isdigit() and len(value) <= 10 for value in pair))
    pair = tuple(int(value) for value in pair)
    require(pair[0] != pair[1] and all(3 <= fd <= 2147483647 for fd in pair))
    return pair


def isolate():
    # No discovery inputs or FD numbers are accepted from environment/arguments.
    parent = os.getppid()
    chain = []
    for _ in range(16):
        if not parent:
            return 0
        try:
            before = process(parent)
            pair = worker_pair(parent)
            require(process(parent) == before)
        except OSError:
            # Unobservable ancestry authorizes no cleanup. Any inherited FD
            # remains visible to the unchanged production refusal downstream.
            return 0
        chain.append((parent, before))
        if pair is not None:
            return isolate_pair(parent, pair, chain)
        require(before[0] != parent)
        parent = before[0]
    raise Refusal()


def isolate_pair(pid, pair, chain):
    metadata = []
    absent = []
    for fd, access in zip(pair, (os.O_RDONLY, os.O_WRONLY)):
        try:
            local = os.fstat(fd)
        except OSError as error:
            if error.errno != 9:  # EBADF only; permission/other errors are refusals.
                raise
            absent.append(fd)
            continue
        remote, flags = remote_fd(pid, fd)
        require(identity(local) == remote and stat.S_ISFIFO(local.st_mode))
        require(local.st_uid == os.getuid() and local.st_gid == os.getgid())
        require(flags & os.O_ACCMODE == access)
        require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == access)
        metadata.append((fd, identity(local), flags))
    # An already isolated launch may have neither pipe. Partial presence refuses.
    if absent:
        require(len(absent) == 2)
        return 0
    require(metadata[0][1][:2] != metadata[1][1][:2])
    require(worker_pair(pid) == pair)
    for ancestor, expected in chain:
        require(process(ancestor) == expected)
    for fd, expected, flags in metadata:
        require(identity(os.fstat(fd)) == expected)
        require(remote_fd(pid, fd) == (expected, flags))
    # Single-threaded process: validation and CLOEXEC cannot race local FD writers.
    # Both identities validate before either local descriptor flag is changed.
    for fd, _, _ in metadata:
        fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.fcntl(fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
    for fd, expected, _ in metadata:
        require(identity(os.fstat(fd)) == expected)
        require(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
    return 2


def main():
    try:
        require(len(sys.argv) > 1)
        changed = isolate()
        if changed:
            print("[ci] isolated exact Runner.Worker transport pair", file=sys.stderr)
        os.execvp(sys.argv[1], sys.argv[1:])
    except (Refusal, OSError, ValueError, IndexError):
        print("[ci] RUNNER_TRANSPORT_ISOLATION_REFUSED", file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
