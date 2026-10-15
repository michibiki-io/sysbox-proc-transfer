#!/usr/bin/env python3
"""Disposable capable direct-child sandbox only, with registered network policy.
Requires an OCI mask on lo/ifalias and readonly self-bind on lo/statistics.
Negative/rejected/error LOOKUP must not detach either original or transferred
protections through the shared FUSE dcache. No existing daemon is configured.
"""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--failure-switch', type=Path, help='fresh task-owned switch for the separately configured test failure helper')
args = parser.parse_args()
assert os.getuid() == 0, 'capable mapped direct-child observer required'
assert int(Path('/proc/self/uid_map').read_text().split()[2]) < 4294967295
signal.alarm(90)
libc = ctypes.CDLL(None, use_errno=True)
base = '/sys/devices/virtual/net'
protected = [base + '/lo/ifalias', base + '/lo/statistics']

def mounts():
    return {line.split()[4]: int(line.split()[0]) for line in Path('/proc/self/mountinfo').read_text().splitlines()}

def check(paths, identities, mount_ids):
    current = mounts()
    for path in paths:
        assert current.get(path) == mount_ids[path], ('protection mount detached/replaced', path)
        stat = os.stat(path)
        device, inode, floor = identities[path]
        assert (stat.st_dev, stat.st_ino) == (device, inode), path
        assert os.statvfs(path).f_flag & floor == floor, path
        assert libc.umount2(path.encode(), 2) == -1, ('detach permitted', path)
        assert libc.mount(None, path.encode(), None, 4096 | 32, None) == -1, ('RO clear permitted', path)

def attack(phase):
    pid = os.fork()
    if not pid:
        try:
            if phase == 'deeper-user':
                script = "import os;\nfor p in ['/sys/devices/virtual/net','/sys/devices/virtual/net/lo']:\n try: os.stat(p)\n except OSError: pass\ntry: os.listdir('/sys/devices/virtual/net')\nexcept OSError: pass\nelse: raise AssertionError('unsupported graph enumerated')"
                subprocess.run(['unshare', '--user', '--map-root-user', '--', 'unshare', '--user', '--map-root-user', '--', '/usr/bin/python3', '-c', script], check=True, timeout=25)
            else:
                assert libc.unshare(0x40000000) == 0, ctypes.get_errno()
                subprocess.run(['ip', 'link', 'set', 'lo', 'name', 'issue5-hidden'], check=True, timeout=5)
                assert {name for _, name in socket.if_nameindex()} == {'issue5-hidden'}
                assert set(os.listdir(base)) == {'issue5-hidden'}, 'enumeration must use actual Network'
                for path in [base + '/lo', base + '/lo/ifalias', base + '/lo/statistics']:
                    try:
                        os.stat(path)
                    except OSError:
                        pass  # Only policy traversal metadata may remain visible.
                try:
                    os.listdir(base + '/lo')
                except OSError as error:
                    assert error.errno == errno.ENOENT, error
                else:
                    raise AssertionError('absent interface returned successful enumeration')
            os._exit(0)
        except BaseException as error:
            print(repr(error), flush=True)
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, phase

# The target exists only in this sandbox's private Mount namespace. The outer
# and transferred views share the protected FUSE dentries but retain distinct IDs.
target = tempfile.mkdtemp(prefix='issue5-dentry-')
assert libc.mount(b'sysfs', target.encode(), b'sysfs', 15, None) == 0, ctypes.get_errno()
paths = protected + [target + path[4:] for path in protected]
identities = {}
for path in paths:
    stat = os.stat(path)
    floor = os.statvfs(path).f_flag & (os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC)
    if path.endswith('/statistics'):
        assert floor & os.ST_RDONLY, path
    identities[path] = (stat.st_dev, stat.st_ino, floor)
mount_ids = {path: mounts()[path] for path in paths}
for phase in ['deeper-user', 'absent-interface']:
    attack(phase)
    check(paths, identities, mount_ids)
    print('PASS ' + phase + ': original/transferred mount IDs, identities, floors and detach/remount denial retained', flush=True)

if args.failure_switch:
    switch = args.failure_switch
    assert switch.is_absolute() and str(switch).startswith('/tmp/issue5-')
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with switch.open('x'):
            pass
        try:
            os.stat(base + '/lo')
        except OSError:
            pass
        try:
            os.listdir(fd)
        except OSError as error:
            assert error.errno == errno.EIO, error
        else:
            raise AssertionError('injected backing failure returned successful enumeration')
    finally:
        switch.unlink(missing_ok=True)
        os.close(fd)
    check(paths, identities, mount_ids)
    print('PASS injected failure: explicit EIO and original/transferred protections retained', flush=True)
print('PASS protected-dentry negative/denied lookup regression', flush=True)
