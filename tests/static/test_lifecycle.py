"""Executable kernel and C helper liveness regressions; no mount privileges."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class Lifecycle(unittest.TestCase):
    def test_kernel_notification_and_pidfd_lifecycle(self):
        with tempfile.TemporaryDirectory() as work:
            binary = str(Path(work) / "lifecycle")
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                            str(ROOT / "tests/unit/lifecycle.c"), "-o", binary], check=True)
            subprocess.run([binary], check=True, timeout=25)

    def test_checkpoint_helper_compiles(self):
        with tempfile.TemporaryDirectory() as work:
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(ROOT / "tests/unit/helper-checkpoint.c"), "-o", str(Path(work) / "helper")], check=True)

    def test_helper_liveness_and_cleanup(self):
        with tempfile.TemporaryDirectory() as work:
            binary = str(Path(work) / "liveness")
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(ROOT / "tests/unit/helper-liveness.c"), "-o", binary], check=True)
            subprocess.run([binary], check=True, timeout=35)

    def test_runtime_probes_compile(self):
        with tempfile.TemporaryDirectory() as work:
            for name in ("thread-proc", "checkpoint-requester"):
                subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                                str(ROOT / ("tests/runtime/" + name + ".c")),
                                "-o", str(Path(work) / name)], check=True)
