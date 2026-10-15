"""Execute real verify.c entry points with compile-time, unprivileged syscall stubs.

Standalone checksum consumers need this file, tests/unit/proc-verifier.c and
tests/runtime/verify.c in their original relative layout. No daemon is used.
"""
import errno
from itertools import combinations
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
NAMES = 'uptime swaps sys bus fs irq sysrq-trigger asound interrupts keys timer_list'.split()

OPTIONALS = ('asound', 'sysrq-trigger', 'swaps')
ABSENCES = tuple(group for count in range(4) for group in combinations(OPTIONALS, count))


def baseline(absent=()):
    return ''.join(f'{n} absent\n' if n in absent
                   else f'{n} present 10 20 1\n' for n in NAMES)


class ProcVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.binary = str(Path(cls.work.name) / 'verify')
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'tests/unit/proc-verifier.c'), '-o', cls.binary], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def run_mode(self, mode, data=None, **env):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest'
            if data is not None:
                path.write_bytes(data.encode() if isinstance(data, str) else data)
            args = [mode, str(path)]
            if mode == 'readonly':
                args = [mode, '/fixture/proc', str(path)]
            elif mode == 'sandbox':
                args.append('pid:[1]')
            # No ambient injection switches from the invoking environment.
            clean = {k: v for k, v in os.environ.items()
                     if k not in ('FAULT', 'TARGET', 'ERROR', 'ABSENT', 'MASK_DATA')}
            result = subprocess.run([self.binary, *args], env={**clean, **env},
                                    capture_output=True, text=True, timeout=5)
            return result, path.read_bytes() if path.is_file() else None

    def assert_failure(self, mode, data, **env):
        result, _ = self.run_mode(mode, data, **env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('PASS', result.stdout)
        return result

    def test_optional_present_and_absent(self):
        for absent in ABSENCES:
            for mode in ('readonly', 'sandbox'):
                with self.subTest(absent=absent, mode=mode):
                    result, _ = self.run_mode(mode, baseline(absent), ABSENT=','.join(absent))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('PASS', result.stdout)
                    prefix = '/fixture/proc' if mode == 'readonly' else '/proc'
                    for name in NAMES:
                        self.assertIn(f'CALL stat {prefix}/{name}\n', result.stderr)
                        if name in absent:
                            for op in ('statvfs', 'detach', 'remount'):
                                self.assertNotIn(f'CALL {op} {prefix}/{name}\n', result.stderr)
                            continue
                        self.assertIn(f'CALL statvfs {prefix}/{name}\n', result.stderr)
                        if mode == 'sandbox':
                            for op in ('detach', 'remount'):
                                self.assertIn(f'CALL {op} /proc/{name}\n', result.stderr)
                    if mode == 'sandbox':
                        for name in ('interrupts', 'keys', 'timer_list'):
                            self.assertIn(f'CALL mask /proc/{name}\n', result.stderr)

    def test_capture_complete_and_roundtrip(self):
        for absent in ABSENCES:
            env = {'ABSENT': ','.join(absent)}
            result, data = self.run_mode('capture', **env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(data.decode(), baseline(absent))
            for mode in ('readonly', 'sandbox'):
                result, _ = self.run_mode(mode, data, **env)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_capture_errors_do_not_publish_partial_baseline(self):
        for name in NAMES:
            for op in ('stat', 'statvfs'):
                for error in (errno.ENOENT, errno.EACCES, errno.EIO, errno.ENOTDIR):
                    if name in OPTIONALS and op == 'stat' and error == errno.ENOENT:
                        continue
                    with self.subTest(name=name, op=op, error=error):
                        result, data = self.run_mode('capture', FAULT=op, TARGET=f'/proc/{name}', ERROR=str(error))
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIsNone(data)

    def test_invalid_baselines_rejected_before_operations(self):
        valid = baseline(('asound',))
        rows = valid.splitlines(keepends=True)
        cases = {
            'empty': '', 'root-only': 'root present 10 20 1\n',
            'missing': ''.join(rows[:-1]), 'duplicate': valid.replace(rows[-1], rows[0]),
            'extra': valid + rows[0], 'unknown': valid.replace('asound absent', 'unknown absent'),
            'traversal': valid.replace('asound absent', '../asound absent'),
            'malformed-before-later-present': valid.replace('asound absent', 'asound invalid'),
            'absent-extra-fields': valid.replace('asound absent', 'asound absent 0 0 0'),
            'present-missing-fields': valid.replace('asound absent', 'asound present'),
            'legacy': valid.replace('present ', ''),
            'only-three': ''.join(rows[:3]),
            'all-absent': ''.join(f'{n} absent\n' for n in NAMES),
            'whitespace-only': '   \n',
            'many-fields': valid.replace('asound absent', 'asound present 1 2 3 4 5'),
            'extra-field': valid.replace('asound absent', 'asound present 10 20 1 extra'),
            'negative': valid.replace('10 20 1', '-1 20 1'),
            'positive-sign': valid.replace('10 20 1', '+1 20 1'),
            'overflow': valid.replace('10 20 1', '9' * 100 + ' 20 1'),
            'bad-number': valid.replace('10 20 1', '10x 20 1'),
            'nul': valid.encode() + b'\0', 'embedded-nul': valid.replace('asound absent', 'asound\0 absent'),
            'blank-row': valid + '\n', 'unterminated': valid[:-1],
            'overlong-row': 'x' * 256 + '\n' + valid,
            'oversize': ' ' * 4097, 'missing-file': None,
        }
        for field in range(3):
            values = ['10', '20', '1']
            values[field] = '9' * 100
            cases[f'overflow-field-{field}'] = valid.replace('10 20 1', ' '.join(values))
        for row in rows:
            cases['missing-' + row.split()[0]] = valid.replace(row, '')
        for name in OPTIONALS:
            # Even optional absence needs an explicit row; omission is unusable.
            cases['missing-absent-' + name] = baseline(OPTIONALS).replace(f'{name} absent\n', '')
        for name in NAMES:
            if name not in OPTIONALS:
                cases['required-absent-' + name] = valid.replace(f'{name} present 10 20 1', f'{name} absent')
        for mode in ('readonly', 'sandbox'):
            for label, data in cases.items():
                with self.subTest(mode=mode, label=label):
                    result = self.assert_failure(mode, data)
                    self.assertNotIn('CALL ', result.stderr)
            # Directory streams report an actual read error, rather than clean EOF.
            args = ['readonly', '/fixture/proc', self.work.name] if mode == 'readonly' else ['sandbox', self.work.name, 'pid:[1]']
            result = subprocess.run([self.binary, *args], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('manifest read', result.stderr)
            self.assertNotIn('CALL ', result.stderr)

    def test_observation_errors_and_loss(self):
        for mode in ('readonly', 'sandbox'):
            root = '/fixture/proc' if mode == 'readonly' else '/proc'
            for name in NAMES:
                for op in ('stat', 'statvfs'):
                    for error in (errno.ENOENT, errno.EACCES, errno.EIO, errno.ENOTDIR):
                        with self.subTest(mode=mode, name=name, op=op, error=error):
                            self.assert_failure(mode, baseline(), FAULT=op, TARGET=f'{root}/{name}', ERROR=str(error))
            # Baseline absence must match observed ENOENT, not success or other errors.
            for name in OPTIONALS:
                with self.subTest(mode=mode, absent=name):
                    self.assert_failure(mode, baseline((name,)))
                    for error in (errno.EACCES, errno.EIO, errno.ENOTDIR):
                        self.assert_failure(mode, baseline((name,)), FAULT='stat',
                                            TARGET=f'{root}/{name}', ERROR=str(error))

    def test_readonly_root_and_every_present_entry(self):
        for name in ['', *NAMES]:
            target = '/fixture/proc' + ('/' + name if name else '')
            for op in ('writable', 'statvfs'):
                with self.subTest(name=name, op=op):
                    self.assert_failure('readonly', baseline(), FAULT=op, TARGET=target, ERROR=str(errno.EIO))
        self.assert_failure('readonly', baseline(), FAULT='mount', TARGET='/fixture/proc')
        # Every present RO check survives all optional-absence combinations,
        # including the original regressions after absent asound.
        for absent in ABSENCES:
            for name in NAMES:
                if name not in absent:
                    with self.subTest(absent=absent, name=name):
                        self.assert_failure('readonly', baseline(absent), ABSENT=','.join(absent),
                                            FAULT='writable', TARGET=f'/fixture/proc/{name}')

    def test_sandbox_all_checks_after_absence(self):
        for absent in ABSENCES:
            for name in NAMES:
                if name in absent:
                    continue
                for op in ('device', 'inode', 'writable', 'detach', 'remount'):
                    with self.subTest(absent=absent, name=name, op=op):
                        self.assert_failure('sandbox', baseline(absent), ABSENT=','.join(absent),
                                            FAULT=op, TARGET=f'/proc/{name}')
            self.assert_failure('sandbox', baseline(absent), ABSENT=','.join(absent), MASK_DATA='1')

    def test_no_readonly_requirement_added_to_rw_source(self):
        # Existing sandbox policy requires RO retention only when captured RO.
        data = baseline(('asound',)).replace('10 20 1', '10 20 0')
        result, _ = self.run_mode('sandbox', data, ABSENT='asound', FAULT='writable', TARGET='/proc/keys')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('CALL remount ', result.stderr)


if __name__ == '__main__':
    unittest.main()
