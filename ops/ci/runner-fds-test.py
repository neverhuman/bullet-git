#!/usr/bin/env python3
"""Actual exec/pipe controls for CI transport isolation; no provider processes."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

LAUNCHER = Path(__file__).with_name("runner-fds.py").resolve()


class TransportTests(unittest.TestCase):
    def run_worker(self, scenario):
        with tempfile.TemporaryDirectory(prefix="bullet-runner-fds-") as directory:
            root = Path(directory)
            worker = root / "Runner.Worker"
            shutil.copy2(sys.executable, worker)
            inbound, inbound_writer = os.pipe()
            outbound_reader, outbound = os.pipe()
            foreign = os.open("/dev/null", os.O_RDONLY)
            descriptors = (inbound, inbound_writer, outbound_reader, outbound, foreign)
            try:
                for fd in (inbound, outbound, foreign):
                    os.set_inheritable(fd, True)
                pair = [inbound, outbound]
                if scenario == "wrong-direction":
                    pair.reverse()
                arguments = [str(value) for value in pair]
                if scenario == "malformed":
                    arguments.append("unexpected")
                # Python keeps the native executable's spawnclient argv. The
                # fixture script drives the real launcher and actual exec child.
                child = f"""
import errno,json,os,sys
observed=[]
for fd in {list((inbound, outbound))!r}:
    try: os.fstat(fd); observed.append(True)
    except OSError as error:
        assert error.errno==errno.EBADF; observed.append(False)
assert observed==[False,False], observed
assert os.get_inheritable({foreign})
print('EXACT_PAIR_CLOSED_FOREIGN_RETAINED')
sys.exit(75 if {scenario == 'foreign-refusal'!r} else 0)
"""
                script = f"""
import fcntl,json,os,subprocess,sys
before=[os.fstat(fd) for fd in {list((inbound,outbound))!r}]
replace={scenario == 'replacement'!r}
preexec=(lambda: os.dup2({foreign},{inbound})) if replace else None
if {scenario == 'partial'!r}: preexec=lambda: os.close({inbound})
if {scenario == 'already-isolated'!r}: preexec=lambda: (os.close({inbound}),os.close({outbound}))
result=subprocess.run([{sys.executable!r},{str(LAUNCHER)!r},{sys.executable!r},'-c',{child!r}],
    close_fds=False,preexec_fn=preexec,capture_output=True,timeout=5)
after=[os.fstat(fd) for fd in {list((inbound,outbound))!r}]
assert [(x.st_dev,x.st_ino) for x in before]==[(x.st_dev,x.st_ino) for x in after]
assert all(os.get_inheritable(fd) for fd in {list((inbound,outbound))!r})
print(json.dumps({{'exit':result.returncode,'stdout':result.stdout.decode(),'stderr':result.stderr.decode()}}))
"""
                (root / "spawnclient").write_text(script)
                result = subprocess.run([str(worker), "spawnclient", *arguments], cwd=root,
                                        pass_fds=(inbound, outbound, foreign), capture_output=True,
                                        timeout=8, check=True)
                self.assertEqual(result.stderr, b"")
                return json.loads(result.stdout)
            finally:
                for fd in descriptors:
                    os.close(fd)

    def test_exact_pair_exec_closure_retains_foreign_and_parent_handles(self):
        result = self.run_worker("valid")
        self.assertEqual(result["exit"], 0, result)
        self.assertEqual(result["stdout"], "EXACT_PAIR_CLOSED_FOREIGN_RETAINED\n")
        self.assertIn("isolated exact Runner.Worker transport pair", result["stderr"])
        isolated = self.run_worker("already-isolated")
        self.assertEqual(isolated["exit"], 0, isolated)
        self.assertEqual(isolated["stderr"], "")

    def test_unrelated_descriptor_still_reaches_downstream_refusal(self):
        result = self.run_worker("foreign-refusal")
        self.assertEqual(result["exit"], 75, result)
        self.assertIn("EXACT_PAIR_CLOSED_FOREIGN_RETAINED", result["stdout"])

    def test_replacement_direction_and_malformed_worker_refuse_before_exec(self):
        for scenario in ("replacement", "wrong-direction", "malformed", "partial"):
            with self.subTest(scenario=scenario):
                result = self.run_worker(scenario)
                self.assertEqual(result["exit"], 75, result)
                self.assertEqual(result["stdout"], "")
                self.assertEqual(result["stderr"], "[ci] RUNNER_TRANSPORT_ISOLATION_REFUSED\n")

    def test_no_worker_leaves_unknown_descriptor_inheritable(self):
        fd = os.open("/dev/null", os.O_RDONLY)
        try:
            result = subprocess.run([sys.executable, str(LAUNCHER), sys.executable, "-c",
                                     f"import os;assert os.get_inheritable({fd})"],
                                    pass_fds=(fd,), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
