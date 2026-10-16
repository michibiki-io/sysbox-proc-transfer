"""Unprivileged fixtures for the actual runtime oracle; no mounts or net changes."""
import ast
import errno
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / 'tests/runtime'
sys.path.insert(0, str(RUNTIME))
import sysfs_oracle as oracle


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), RUNTIME / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('sysfs-write-policy')


def record(name, kind=4):
    name = os.fsencode(name) + b'\0'
    size = (19 + len(name) + 7) & ~7
    return struct.pack('=QqHB', 1, 1, size, kind) + name + bytes(size - 19 - len(name))


def attribute(kind, payload):
    size = 4 + len(payload)
    return struct.pack('=HH', size, kind) + payload + bytes(oracle.aligned(size) - size)


def link(name='lo', index=1, mtu=65536):
    return (struct.pack('=BBHiII', 0, 0, 0, index, 0, 0) +
            attribute(3, name.encode() + b'\0') + attribute(4, struct.pack('=I', mtu)))


def message(kind, payload=b'', flags=2, seq=1, pid=42):
    size = 16 + len(payload)
    return struct.pack('=IHHII', size, kind, flags, seq, pid) + payload + bytes(oracle.aligned(size) - size)


class Tree(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.base = Path(self.work.name)
        self.snapshot = {'lo': (1, 65536), 'tunl0': (7, 1480)}
        self.build(self.snapshot)

    def build(self, snapshot, attr=False):
        for view in oracle.VIEWS:
            shutil.rmtree(self.base / view, ignore_errors=True)
            (self.base / view).mkdir(parents=True)
        for name, (index, mtu) in snapshot.items():
            entry = self.base / 'devices/virtual/net' / name
            entry.mkdir()
            (entry / 'ifindex').write_text(str(index))
            (entry / 'mtu').write_text(str(mtu))
            (entry / 'subsystem').symlink_to(self.base / 'class/net')
            (self.base / 'class/net' / name).symlink_to(entry)
        if attr:
            for view in oracle.VIEWS:
                (self.base / view / 'bonding_masters').write_text('')

    def inherited_native(self, snapshot=None):
        # Independent backing, not aliases into the current virtual-net fixture.
        native = self.base / 'mount-network'
        native.mkdir()
        view = self.base / 'class/net'
        shutil.rmtree(view)
        view.mkdir()
        snapshot = snapshot if snapshot is not None else {'lo': (91, 9000), 'mount-only': (92, 1400)}
        for name, (index, mtu) in snapshot.items():
            entry = native / name
            entry.mkdir()
            (entry / 'ifindex').write_text(str(index))
            (entry / 'mtu').write_text(str(mtu))
            (entry / 'subsystem').symlink_to(view)
            (view / name).symlink_to(entry)

    def check(self):
        return oracle.check_fresh_network(self.base, observer=lambda: self.snapshot)

    def test_layouts_defaults_optional_attribute(self):
        for snapshot in ({'lo': (1, 65536)}, self.snapshot,
                         {'lo': (1, 65536), 'bonding_masters': (2, 1500)}):
            for attr in (False, True) if 'bonding_masters' not in snapshot else (False,):
                with self.subTest(snapshot=snapshot, attr=attr):
                    self.snapshot = snapshot
                    self.build(snapshot, attr)
                    self.assertEqual(self.check(), snapshot)

    def test_optional_attribute_in_either_alias(self):
        for views in ((), ('class/net',), ('devices/virtual/net',), oracle.VIEWS):
            self.build(self.snapshot)
            for view in views:
                (self.base / view / 'bonding_masters').write_text('')
            self.check()

    def test_reject_foreign_names_and_missing_interfaces(self):
        for view in oracle.VIEWS:
            p = self.base / view / 'foreign'
            p.mkdir()
            with self.assertRaises(AssertionError):
                self.check()
            p.rmdir()
        (self.base / 'class/net/tunl0').unlink()
        with self.assertRaises(AssertionError):
            self.check()

    def test_wrong_metadata_on_every_interface(self):
        for name in self.snapshot:
            for attr in ('ifindex', 'mtu'):
                p = self.base / 'devices/virtual/net' / name / attr
                before = p.read_text()
                p.write_text('999')
                with self.assertRaises(AssertionError):
                    self.check()
                p.unlink()
                p.symlink_to(self.base / 'missing')
                with self.assertRaises(AssertionError):
                    self.check()
                p.unlink()
                p.write_text(before)

    def test_malformed_attribute_types_and_interface_disguise(self):
        for view in oracle.VIEWS:
            p = self.base / view / 'bonding_masters'
            for kind in ('directory', 'symlink', 'dangling', 'fifo'):
                if kind == 'directory':
                    p.mkdir()
                elif kind == 'fifo':
                    os.mkfifo(p)
                else:
                    p.symlink_to(self.base / ('missing' if kind == 'dangling' else 'devices/virtual/net/lo/mtu'))
                with self.assertRaises(AssertionError):
                    self.check()
                p.rmdir() if kind == 'directory' else p.unlink()
        self.snapshot = {'lo': (1, 65536), 'bonding_masters': (2, 1500)}
        self.build(self.snapshot)
        p = self.base / 'class/net/bonding_masters'
        p.unlink()
        p.write_text('')
        with self.assertRaises(AssertionError):
            self.check()

    def test_path_type_symlink_and_traversal_errors(self):
        p = self.base / 'class/net/lo'
        p.unlink()
        p.symlink_to(self.base / 'missing')
        with self.assertRaises(FileNotFoundError):
            self.check()
        p.unlink()
        p.mkdir()
        with self.assertRaises(AssertionError):
            self.check()
        p.rmdir()
        p.symlink_to(self.base / 'devices/virtual/net/lo')
        with patch.object(oracle.os, 'listdir', side_effect=PermissionError(errno.EACCES, 'observer')):
            with self.assertRaises(PermissionError):
                self.check()
        with self.assertRaises(AssertionError):
            oracle.check_absent(self.base / 'class/net', ('lo',))

    def test_observer_failure_and_stale_snapshot(self):
        for error in (OSError(errno.EIO, 'netlink'), TimeoutError('netlink')):
            with self.assertRaises(type(error)):
                oracle.check_fresh_network(self.base, observer=Mock(side_effect=error))
        with self.assertRaises(AssertionError):
            oracle.check_fresh_network(self.base, observer=lambda: {})
        stale = dict(self.snapshot, tunl0=(9, 1481))
        with self.assertRaises(AssertionError):
            oracle.check_fresh_network(self.base, observer=lambda: stale)

    def test_raw_full_list_and_types(self):
        path = self.base / 'devices/virtual/net'
        chunks = [[('lo', 4)], [('tunl0', 4)], []]
        reader = Mock(side_effect=chunks)
        oracle.check_view(path, self.snapshot, reader=reader)
        self.assertEqual(reader.call_count, 3)
        for chunks in ([ [('lo', 4)], [] ],
                       [ [('lo', 4), ('tunl0', 4), ('foreign', 4)], [] ],
                       [ [('lo', 8), ('tunl0', 4)], [] ],
                       [ [('lo', 4), ('lo', 4), ('tunl0', 4)], [] ]):
            with self.subTest(chunks=chunks), self.assertRaises((AssertionError, FileNotFoundError)):
                oracle.check_view(path, self.snapshot, reader=Mock(side_effect=chunks))
        with self.assertRaises(OSError):
            oracle.check_view(path, self.snapshot, reader=Mock(side_effect=OSError(errno.EIO, 'raw')))
        (path / 'bonding_masters').write_text('')
        with self.assertRaises(AssertionError):
            oracle.check_view(path, self.snapshot, reader=Mock(side_effect=[[('lo', 4), ('tunl0', 4)], []]))

    def test_stale_cookie_contract(self):
        path = self.base / 'devices/virtual/net'
        for chunks in ([[]], [[('lo', 4)], []], [OSError(errno.EIO, 'stale')],
                       [[('lo', 4)], OSError(errno.EIO, 'stale')]):
            oracle.check_stale(0, path, self.snapshot, Mock(side_effect=chunks))
        for error in (errno.EINVAL, errno.EACCES, errno.ENOENT):
            with self.assertRaises(AssertionError):
                oracle.check_stale(0, path, self.snapshot, Mock(side_effect=OSError(error, 'stale')))
        (path / 'foreign').mkdir()
        with self.assertRaises(AssertionError):
            oracle.check_stale(0, path, self.snapshot, Mock(side_effect=[[('foreign', 4)], OSError(errno.EIO, 'stale')]))

    def test_shared_handle_stale_then_rewind_then_complete_on_same_fd(self):
        path = self.base / 'devices/virtual/net'
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        # Consume one interface, leaving another for the stale-cookie phase.
        while True:
            primed = oracle.raw_chunk(fd, 40)
            self.assertTrue(primed)
            if any(name in self.snapshot for name, _ in primed):
                break
        real_lseek = os.lseek
        initial_offset = real_lseek(fd, 0, os.SEEK_CUR)
        self.assertGreater(initial_offset, 0)
        events = []

        def read(actual_fd):
            self.assertEqual(actual_fd, fd)
            offset = real_lseek(actual_fd, 0, os.SEEK_CUR)
            entries = oracle.raw_chunk(actual_fd, 40)
            events.append(('read', actual_fd, offset, entries))
            return entries

        def rewind(actual_fd, offset, whence):
            result = real_lseek(actual_fd, offset, whence)
            events.append(('rewind', actual_fd, result))
            return result

        with patch.object(oracle.os, 'lseek', side_effect=rewind) as seek:
            oracle.check_shared_handle(fd, path, self.snapshot, reader=read)
        seek.assert_called_once_with(fd, 0, os.SEEK_SET)
        split = next(i for i, event in enumerate(events) if event[0] == 'rewind')
        stale, full = events[:split], events[split + 1:]
        self.assertEqual(events[split], ('rewind', fd, 0))
        self.assertTrue(stale)
        self.assertEqual(stale[0][2], initial_offset)
        self.assertTrue(stale[0][3])
        self.assertEqual(stale[-1][3], [])
        self.assertTrue(full)
        self.assertEqual(full[0][2], 0)
        self.assertEqual(full[-1][3], [])
        self.assertTrue(all(event[1] == fd for event in events))
        stale_names = oracle.checked_names(path, [entry for event in stale for entry in event[3]])
        full_names = oracle.checked_names(path, [entry for event in full for entry in event[3]])
        self.assertLess(stale_names, set(self.snapshot))
        self.assertEqual(full_names, set(self.snapshot))

    def test_shared_handle_rejects_incomplete_rewound_snapshot(self):
        path = self.base / 'devices/virtual/net'
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertTrue(oracle.raw_chunk(fd, 40))
        with self.assertRaisesRegex(AssertionError, 'rewound shared handle incomplete'):
            oracle.check_shared_handle(fd, path, dict(self.snapshot, missing=(9, 1500)))

    def test_shared_handle_rejects_foreign_stale_entries_before_rewind(self):
        path = self.base / 'devices/virtual/net'
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertTrue(oracle.raw_chunk(fd, 40))
        with patch.object(oracle.os, 'lseek', wraps=os.lseek) as seek:
            with self.assertRaisesRegex(AssertionError, 'foreign network entry'):
                oracle.check_shared_handle(fd, path, {})
        seek.assert_not_called()

    def test_renamed_dentry_layout_preserves_lo_absence(self):
        self.snapshot = {'issue5-hidden': (1, 65536), 'tunl0': (7, 1480)}
        self.build(self.snapshot, attr=True)
        self.check()
        oracle.check_absent(self.base / 'devices/virtual/net', ('lo',))
        (self.base / 'devices/virtual/net/lo').mkdir()
        with self.assertRaises(AssertionError):
            self.check()

    def test_interleave_caller_checks_defaults_controlled_and_stale_metadata(self):
        tree = ast.parse((RUNTIME / 'sysfs-interleave.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'check')
        self.inherited_native()
        scope = {'path': self.base / 'devices/virtual/net'}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<interleave check>', 'exec'), scope)
        def check_fuse_network(base, **kwargs):
            return oracle.check_fuse_network(base, observer=lambda: self.snapshot, **kwargs)
        scope['check_fuse_network'] = check_fuse_network
        scope['check']('lo', 65536, {'foreign'}, dict(self.snapshot))
        with self.assertRaises(AssertionError):
            scope['check']('lo', 1202, {'foreign'}, dict(self.snapshot))
        with self.assertRaises(AssertionError):
            scope['check']('lo', 65536, {'foreign'}, {'lo': (1, 65536)})
        source = (RUNTIME / 'sysfs-interleave.py').read_text()
        self.assertIn("'issue5-prime','issue5-peer'", source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'check_shared_handle']
        self.assertEqual(len(calls), 1)
        self.assertEqual([ast.dump(arg) for arg in calls[0].args],
                         [ast.dump(ast.Name(id=name, ctx=ast.Load()))
                          for name in ('shared', 'path', 'expected')])
        # Execute the actual parent priming and repeated-parent oracle calls too.
        for statement in tree.body:
            if isinstance(statement, ast.FunctionDef):
                continue
            for call in ast.walk(statement):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id in ('check_fuse_network', 'check_fresh_network')):
                    result = eval(compile(ast.Expression(call), '<parent oracle>', 'eval'), scope)
                    self.assertEqual(result, self.snapshot)
        target = self.base / oracle.FUSE_VIEW / 'tunl0/mtu'
        target.write_text('999')
        with self.assertRaises(AssertionError):
            scope['check']('lo', 65536, {'foreign'}, dict(self.snapshot))

    def test_dentry_absent_phase_reaches_shared_oracle(self):
        self.snapshot = {'issue5-hidden': (1, 65536), 'tunl0': (7, 1480)}
        self.build(self.snapshot, attr=True)
        self.inherited_native()
        source = (RUNTIME / 'sysfs-dentry-protection.py').read_text()
        tree = ast.parse(source)
        attack = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'attack')
        fake_os = SimpleNamespace(fork=lambda: 0, _exit=Mock(),
                                  stat=Mock(side_effect=FileNotFoundError()),
                                  listdir=Mock(side_effect=FileNotFoundError(errno.ENOENT, 'absent')),
                                  waitpid=lambda *_: (0, 0), waitstatus_to_exitcode=lambda _: 0)
        def observe(base, **kwargs):
            self.assertEqual(base, '/sys')
            return oracle.check_fuse_network(self.base, observer=lambda: self.snapshot, **kwargs)
        observer = Mock(side_effect=observe)
        scope = dict(os=fake_os, libc=Mock(unshare=Mock(return_value=0)),
                     subprocess=Mock(), check_fuse_network=observer, base='/sys/devices/virtual/net',
                     errno=errno, ctypes=Mock())
        exec(compile(ast.Module(body=[attack], type_ignores=[]), '<dentry attack>', 'exec'), scope)
        scope['attack']('absent-interface')
        observer.assert_called_once_with('/sys', absent=())
        fake_os._exit.assert_called_once_with(0)
        fake_os.listdir.assert_called_once_with('/sys/devices/virtual/net/lo')
        self.assertIn('check(paths, identities, mount_ids)', source)
        self.assertIn("paths = protected + [target + path[4:] for path in protected]", source)
        fake_os._exit.reset_mock()
        (self.base / oracle.FUSE_VIEW / 'issue5-hidden/mtu').write_text('999')
        with patch('builtins.print'):
            scope['attack']('absent-interface')
        fake_os._exit.assert_called_once_with(1)

    def test_fresh_wrapper_and_network_entrypoint_reject_inherited_native(self):
        network = load('sysfs-network')
        with patch.object(network.sys, 'argv', ['sysfs-network.py', str(self.base)]), \
             patch.object(network, 'check_fresh_network', side_effect=lambda base:
                          oracle.check_fresh_network(base, observer=lambda: self.snapshot)):
            network.main()
            self.inherited_native()
            with self.assertRaises(AssertionError):
                network.main()
        with self.assertRaises(AssertionError):
            self.check()
        self.assertEqual(oracle.check_fuse_network(self.base, observer=lambda: self.snapshot), self.snapshot)
        # Matching names still cannot hide wrong native metadata in a fresh mount.
        shutil.rmtree(self.base / 'mount-network')
        self.inherited_native(self.snapshot)
        for attribute in ('ifindex', 'mtu'):
            target = self.base / 'mount-network/lo' / attribute
            before = target.read_text()
            target.write_text('999')
            with self.assertRaises(AssertionError):
                self.check()
            target.write_text(before)

    def test_fuse_contract_rejects_names_metadata_types_attributes_and_observer_errors(self):
        self.inherited_native()
        def check():
            return oracle.check_fuse_network(self.base, observer=lambda: self.snapshot)
        path = self.base / oracle.FUSE_VIEW
        for attribute in ('ifindex', 'mtu'):
            target = path / 'tunl0' / attribute
            before = target.read_text()
            target.write_text('999')
            with self.assertRaises(AssertionError):
                check()
            target.unlink()
            target.symlink_to(path / 'lo' / attribute)
            with self.assertRaises(AssertionError):
                check()
            target.unlink()
            target.write_text(before)
        for name in ('foreign', 'bonding_masters'):
            target = path / name
            target.mkdir()
            with self.assertRaises(AssertionError):
                check()
            target.rmdir()
        shutil.rmtree(path / 'tunl0')
        (path / 'tunl0').symlink_to(self.base / 'mount-network/lo')
        with self.assertRaises(AssertionError):
            check()
        for observer in (lambda: {}, Mock(side_effect=OSError(errno.EIO, 'observer'))):
            with self.assertRaises((AssertionError, OSError)):
                oracle.check_fuse_network(self.base, observer=observer)

    def test_write_policy_only_protected_fuse_with_unrelated_native(self):
        self.inherited_native()
        target = self.base / oracle.FUSE_VIEW / 'lo/mtu'
        native = self.base / 'class/net/lo/mtu'
        self.assertEqual(native.read_text(), '9000')
        denied = Mock(side_effect=OSError(errno.EACCES, 'denied'))
        actual_stat = Path.stat
        stats = []
        def nobody(path, *args, **kwargs):
            attrs = actual_stat(path, *args, **kwargs)
            if path == target:
                stats.append(path)
                return os.stat_result((*attrs[:4], 65534, 65534, *attrs[6:]))
            # Native ownership is deliberately different and outside this policy.
            return os.stat_result((*attrs[:4], 1, 1, *attrs[6:]))
        with patch.object(Path, 'stat', nobody):
            policy.check_policy(self.base, lambda: self.snapshot, denied)
        self.assertEqual(stats, [target] * 3)
        self.assertEqual([(call.args[0], call.args[1]) for call in denied.call_args_list],
                         [(target, flags) for flags in
                          (os.O_WRONLY, os.O_RDWR, os.O_WRONLY | os.O_TRUNC)])
        self.assertTrue(all(call.args[0] != native for call in denied.call_args_list))
        def wrong_owner(path, *args, **kwargs):
            attrs = nobody(path, *args, **kwargs)
            return os.stat_result((*attrs[:4], 1, 1, *attrs[6:]))
        with patch.object(Path, 'stat', wrong_owner), self.assertRaises(AssertionError):
            policy.check_policy(self.base, lambda: self.snapshot, denied)
        def writable(path, flags):
            self.assertEqual(path, target)
            return os.open(os.devnull, os.O_WRONLY)
        with patch.object(Path, 'stat', nobody), self.assertRaises(AssertionError):
            policy.check_policy(self.base, lambda: self.snapshot, writable)
        with patch.object(Path, 'stat', nobody):
            with self.assertRaises(AssertionError):
                policy.check_policy(self.base, Mock(side_effect=[self.snapshot, {'lo': (1, 1)}]), denied)
            def mutate(path, flags):
                self.assertEqual(path, target)
                target.write_text('1')
                raise OSError(errno.EROFS, 'denied')
            with self.assertRaises(AssertionError):
                policy.check_policy(self.base, lambda: self.snapshot, mutate)
        with self.assertRaises(OSError):
            policy.check_policy(self.base, Mock(side_effect=OSError(errno.EIO, 'observer')), denied)


class Parsers(unittest.TestCase):
    def test_dirents_bounds_names_and_all_records(self):
        data = record('.') + record('lo') + record('bonding_masters', 8)
        self.assertEqual(oracle.parse_dirents(data), [('.', 4), ('lo', 4), ('bonding_masters', 8)])
        valid = bytearray(record('lo'))
        broken = [b'x', bytes(valid[:-1]), bytes(24), record('a/b'), record('lo', 99)]
        for length in (0, 19, 23, 25, 65535):
            item = valid.copy()
            struct.pack_into('=H', item, 16, length)
            broken.append(bytes(item))
        item = valid.copy()
        item[19:] = b'x' * (len(item) - 19)
        broken.append(bytes(item))
        for item in broken:
            with self.subTest(item=item), self.assertRaises(AssertionError):
                oracle.parse_dirents(record('first') + item)

    def test_raw_syscall_negative_and_real_parser(self):
        fake = Mock()
        fake.syscall.return_value = -1
        with patch.object(oracle.ctypes, 'CDLL', return_value=fake), patch.object(oracle.ctypes, 'get_errno', return_value=errno.EIO):
            with self.assertRaises(OSError) as error:
                oracle.raw_chunk(0)
            self.assertEqual(error.exception.errno, errno.EIO)
        with tempfile.TemporaryDirectory() as work:
            for name in ('lo', 'tunl0', 'bonding_masters'):
                (Path(work) / name).touch()
            fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
            try:
                entries = oracle.raw_entries(fd, lambda fd: oracle.raw_chunk(fd, 48))
                self.assertEqual(oracle.checked_names(Path(work), entries), {'lo', 'tunl0', 'bonding_masters'})
                os.lseek(fd, 0, os.SEEK_SET)
                self.assertEqual(set(oracle.raw_entries(fd)), set(entries))
            finally:
                os.close(fd)

    def test_netlink_link_and_message_parsers(self):
        self.assertEqual(oracle.link_info(link()), ('lo', (1, 65536)))
        for payload in (b'', link()[:-1], link() + b'x', link(index=0), link(mtu=0),
                        link() + attribute(3, b'duplicate\0'),
                        link()[:16] + attribute(3, b'lo\0'),
                        link()[:16] + attribute(3, b'lo\0') + attribute(4, b'x')):
            with self.assertRaises((AssertionError, KeyError)):
                oracle.link_info(payload)
        for data in (b'x', message(16, link())[:-1], bytes(16)):
            with self.assertRaises(AssertionError):
                list(oracle.messages(data))

    def test_netlink_dump_fail_closed(self):
        def observe(datagrams):
            sock = Mock()
            sock.getsockname.return_value = (42, 0)
            sock.recvmsg.side_effect = [(data, [], flags, (0, 0)) for data, flags in datagrams]
            context = Mock()
            context.__enter__ = Mock(return_value=sock)
            context.__exit__ = Mock(return_value=False)
            with patch.object(oracle.socket, 'socket', return_value=context):
                return oracle.netlink_snapshot()
        good = message(16, link()) + message(16, link('tunl0', 7, 1480))
        self.assertEqual(observe([(good, 0), (message(3, struct.pack('=i', 0)), 0)]),
                         {'lo': (1, 65536), 'tunl0': (7, 1480)})
        for data, flags in ((good, socket.MSG_TRUNC), (message(16, link(), flags=0x12), 0),
                            (message(2, struct.pack('=i', -errno.EPERM)), 0),
                            (message(3, struct.pack('=i', -errno.EIO)), 0),
                            (message(16, link(), seq=2), 0), (message(16, link(), pid=43), 0), (good + message(16, link()), 0),
                            (message(3), 0), (b'bad', 0)):
            with self.subTest(data=data, flags=flags), self.assertRaises((AssertionError, OSError)):
                observe([(data, flags)])
        with patch.object(oracle.socket, 'socket', side_effect=PermissionError(errno.EPERM, 'observer')):
            with self.assertRaises(PermissionError):
                oracle.netlink_snapshot()


class IndirectCallers(unittest.TestCase):
    def test_thread_and_checkpoint_construct_same_oracle_command(self):
        # Execute the real C verify() command construction with only statvfs and
        # system stubbed. No mount or network operation is reached (count=0).
        with tempfile.TemporaryDirectory() as work:
            for caller in ('thread-sysfs.c', 'checkpoint-sysfs.c'):
                source = Path(work) / 'command.c'
                source.write_text(
                    ('#define main fixture_main\n' if caller == 'thread-sysfs.c' else
                     '#define CHECKPOINT_SYSFS_MAIN fixture_main\n') +
                    '#define system capture_command\n'
                    '#define statvfs fixture_statvfs\n#include "' + str(RUNTIME / caller) + '"\n'
                    '#undef main\n#undef statvfs\n'
                    'int fixture_statvfs(const char *p, struct fixture_statvfs *v) { '
                    '(void)p; v->f_flag=ST_NOSUID|ST_NODEV|ST_NOEXEC; return 0; }\n'
                    'int capture_command(const char *cmd) { puts(cmd); return 0; }\n'
                    'int main(void) { target="/tmp/issue5-target"; verify(); return 0; }\n')
                binary = Path(work) / 'command'
                subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                                str(source), '-o', str(binary)], check=True)
                result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.splitlines()[0],
                                 '/usr/bin/python3 /tmp/issue5-repo/tests/runtime/sysfs-network.py /tmp/issue5-target')
            # Python ignoring environment starts from an unrelated cwd. The exact relative
            # layout under the existing repository bind must resolve its sibling
            # module without PYTHONPATH or rewriting either source file.
            copied = Path(work) / 'repo/tests/runtime'
            copied.mkdir(parents=True)
            for name in ('sysfs-network.py', 'sysfs_oracle.py'):
                shutil.copyfile(RUNTIME / name, copied / name)
            result = subprocess.run([sys.executable, '-E', str(copied / 'sysfs-network.py')],
                                    cwd=work, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('IndexError', result.stderr)  # CLI imported shared module before parsing argv.
            self.assertNotIn('ModuleNotFoundError', result.stderr)

    def test_lifecycle_command_binds_repo(self):
        tree = ast.parse((RUNTIME / 'checkpoints.py').read_text())
        command = next(node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'command' for t in node.targets))
        for filesystem in ('sysfs', 'proc'):
            scope = dict(args=SimpleNamespace(prefix=['exec-fixture'], requester='/tmp/requester',
                                             requester_kind='nonleader', filesystem=filesystem),
                         code='supervisor', base='/tmp/owned', token='owned-token')
            exec(compile(ast.Module(body=[command], type_ignores=[]), '<checkpoint command>', 'exec'), scope)
            argv = scope['command']
            repo = '/tmp/issue5-repo'
            if filesystem == 'sysfs':
                i = argv.index(repo)
                self.assertEqual(argv[i-1:i+2], ['--ro-bind', repo, repo])
                self.assertLess(argv.index('--tmpfs'), i)
            else:
                self.assertNotIn(repo, argv)


class Ownership(unittest.TestCase):
    def preflight(self, *, mapped=True, fresh=True, owner=True, unshare=0):
        lib = Mock()
        lib.unshare.return_value = unshare
        identity = [(1, 10), (1, 20), (1, 10)]
        attrs = Mock(st_dev=1, st_ino=10 if owner else 11)
        net = Mock(st_dev=1, st_ino=21 if fresh else 20)
        with patch.object(oracle.os, 'geteuid', return_value=0), \
             patch.object(Path, 'read_text', return_value='0 1000 65536' if mapped else '0 0 4294967295'), \
             patch.object(oracle, 'namespace_identity', side_effect=identity), \
             patch.object(oracle.ctypes, 'CDLL', return_value=lib), \
             patch.object(oracle.os, 'open', return_value=80) as opened, \
             patch.object(oracle.os, 'fstat', side_effect=[attrs, net]), \
             patch.object(oracle.fcntl, 'ioctl', return_value=81) as ioctl, \
             patch.object(oracle.os, 'close'):
            try:
                oracle.create_owned_network()
            finally:
                for call in opened.call_args_list:
                    self.assertFalse(call.args[1] & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC))
            ioctl.assert_called_once_with(80, 0xb701)
            lib.unshare.assert_called_once_with(0x40000000)

    def test_owner_identity_and_bounded_map_required(self):
        self.preflight()
        for failure in ({'mapped': False}, {'fresh': False}, {'owner': False}, {'unshare': -1}):
            with self.subTest(failure=failure), self.assertRaises(AssertionError):
                self.preflight(**failure)

    def test_unavailable_owner_query_fails_before_writable_open(self):
        lib = Mock(unshare=Mock(return_value=0))
        for error in (PermissionError(errno.EPERM, 'owner'), OSError(errno.ENOTTY, 'owner')):
            with patch.object(oracle.os, 'geteuid', return_value=0), \
                 patch.object(Path, 'read_text', return_value='0 1000 65536'), \
                 patch.object(oracle, 'namespace_identity', side_effect=[(1, 10), (1, 20)]), \
                 patch.object(oracle.ctypes, 'CDLL', return_value=lib), \
                 patch.object(oracle.os, 'open', return_value=80) as opened, \
                 patch.object(oracle.fcntl, 'ioctl', side_effect=error), \
                 patch.object(oracle.os, 'close'):
                with self.assertRaises(type(error)):
                    oracle.create_owned_network()
                opened.assert_called_once_with('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)

    def test_main_preflight_before_any_policy_open(self):
        events = []
        with patch.object(policy, 'create_owned_network', side_effect=lambda: events.append('private')), \
             patch.object(policy, 'check_policy', side_effect=lambda: events.append('opens')):
            policy.main()
        self.assertEqual(events, ['private', 'opens'])
        with patch.object(policy, 'create_owned_network', side_effect=PermissionError('unavailable')), \
             patch.object(policy, 'check_policy') as check:
            with self.assertRaises(PermissionError):
                policy.main()
            check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
