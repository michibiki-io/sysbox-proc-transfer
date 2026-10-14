#!/usr/bin/env python3
"""Disposable private Network only: preserve virtual-net nobody/write policy.
Run once as registered outer root and once as capable direct-child root, each
inside a newly created Network namespace. Never run against host interfaces.
"""
import errno
import os
from pathlib import Path
import socket

assert os.geteuid() == 0
assert {name for _,name in socket.if_nameindex()} == {'lo'}, 'private loopback-only Network required'
assert int(Path('/proc/self/uid_map').read_text().split()[2]) < 4294967295, 'bounded mapped User required'
path=Path('/sys/devices/virtual/net/lo/mtu')
before=path.read_text()
for _ in range(3):
    # Repeated stat includes Getattr on a previously looked-up FUSE inode.
    attrs=path.stat()
    assert (attrs.st_uid,attrs.st_gid)==(65534,65534), (attrs.st_uid,attrs.st_gid)
for flags in (os.O_WRONLY,os.O_RDWR,os.O_WRONLY|os.O_TRUNC):
    try:
        fd=os.open(path,flags)
    except OSError as e:
        assert e.errno in (errno.EACCES,errno.EPERM,errno.EROFS),e
    else:
        os.close(fd)
        raise AssertionError('virtual-net writable Open permitted')
# An independently read raw sysfs class path must retain the original value.
assert path.read_text()==before
assert Path('/sys/class/net/lo/mtu').read_text()==before
print('PASS mapped root nobody Lookup/Getattr and write denial; private mtu unchanged')
