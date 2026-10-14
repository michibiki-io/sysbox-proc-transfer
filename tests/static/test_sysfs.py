"""Focused executable sysfs helper validation, without mount privileges."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class Sysfs(unittest.TestCase):
    def test_helper_rejects_invalid_protocol_and_flags(self):
        with tempfile.TemporaryDirectory() as work:
            binary = str(Path(work) / 'sysfs')
            subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(ROOT/'helper/sysfs-mount-helper.c'),'-o',binary],check=True)
            for args in ([], ['0','0','4096'], ['0','0','0'], ['0','0','0','--open=kernel/security'], ['4294967295','0','0']):
                p = subprocess.run([binary,*args],capture_output=True,timeout=5)
                self.assertNotEqual(p.returncode,0)
                self.assertIn(b'sysfs-transfer:',p.stderr)
                self.assertNotIn(b'commit locked',p.stderr)

    def test_lifecycle_and_fixture_compilation(self):
        with tempfile.TemporaryDirectory() as work:
            for source in ('tests/unit/sysfs-checkpoint.c','tests/unit/sysfs-liveness.c','tests/unit/sysfs-failure-helper.c','tests/runtime/thread-sysfs.c','tests/runtime/checkpoint-sysfs.c'):
                binary = str(Path(work)/Path(source).stem)
                subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror','-pthread',str(ROOT/source),'-o',binary],check=True)
                if source.endswith('sysfs-liveness.c'):
                    subprocess.run([binary],check=True,timeout=35)
