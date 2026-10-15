#!/usr/bin/env python3
"""Disposable sandbox only. Compare sysfs against namespace-local netlink.
Never accepts an enumeration alone as success; raw getdents must also succeed.
"""
import ctypes
import os
from pathlib import Path
import socket
import sys

base = Path(sys.argv[1])
expected = dict((name, index) for index, name in socket.if_nameindex())
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
raw_call = {'x86_64': 217, 'aarch64': 61}[os.uname().machine]
for relative in ('class/net', 'devices/virtual/net'):
    path = base / relative
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        buf = ctypes.create_string_buffer(8192)
        assert libc.syscall(raw_call, fd, buf, len(buf)) > 0, ('raw getdents', ctypes.get_errno())
    finally:
        os.close(fd)
    names = set(os.listdir(path))
    # The disposable fixture uses loopback/veth/dummy interfaces only.
    assert names == set(expected), (relative, names, expected)
    for name, index in expected.items():
        entry = path / name
        assert int((entry / 'ifindex').read_text()) == index, (entry, index)
        assert int((entry / 'mtu').read_text()) > 0
        if relative == 'class/net':
            assert entry.is_symlink() and os.readlink(entry) and entry.resolve().exists()
        assert (entry / 'subsystem').is_symlink() and os.readlink(entry / 'subsystem')
    try:
        (path / 'absent-issue5-interface' / 'ifindex').stat()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError('absent entry leaked across namespaces')
print('PASS raw/high-level network lists, symlinks, ifindex and mtu vs netlink')
