#!/usr/bin/env python3
"""Inside a disposable registered outer container using a failing test helper.
A task-owned switch file permits a good open followed by a failed backing read.
"""
import ctypes
import errno
import os
from pathlib import Path
import sys
import tempfile

switch = Path(sys.argv[1])
path = '/sys/devices/virtual/net'
libc = ctypes.CDLL(None,use_errno=True)
libc.syscall.restype = ctypes.c_long
switch.unlink(missing_ok=True)
# Genuine missing entries must still be missing when backing succeeds.
try:
    os.stat(path+'/absent-issue5-interface')
except FileNotFoundError:
    pass
else:
    raise AssertionError('missing entry visible')
fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY)
switch.touch()
try:
    buffer = ctypes.create_string_buffer(8192)
    r = libc.syscall({'x86_64':217,'aarch64':61}[os.uname().machine],fd,buffer,len(buffer))
    assert r == -1 and ctypes.get_errno() == errno.EIO, ('backing raw enumeration failure',r,ctypes.get_errno())
    try:
        os.listdir(fd)
    except OSError as e:
        assert e.errno == errno.EIO,e
    else:
        raise AssertionError('backing failure returned successful empty directory')
    with tempfile.TemporaryDirectory(prefix='issue5-failed-target-') as target:
        assert libc.mount(b'sysfs',target.encode(),b'sysfs',14,None) == -1
        assert not os.listdir(target), 'failed transfer mutated target'
    print('PASS genuine missing, raw/high-level explicit backing failure, failed target unchanged')
finally:
    switch.unlink(missing_ok=True)
    os.close(fd)
