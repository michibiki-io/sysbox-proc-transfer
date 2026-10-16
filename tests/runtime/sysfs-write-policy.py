#!/usr/bin/env python3
"""Disposable mapped-root fixture only; creates and proves its own private Net.
Run once as registered outer root and once as capable direct-child root.
"""
import errno
import os
from pathlib import Path
from sysfs_oracle import VIEWS, create_owned_network, netlink_snapshot


def check_policy(base=Path('/sys'), observer=netlink_snapshot, opener=os.open):
    snapshot = observer()
    assert 'lo' in snapshot, 'private loopback required'
    before = snapshot['lo'][1]
    paths = [Path(base) / view / 'lo/mtu' for view in VIEWS]
    for path in paths:
        assert int(path.read_text()) == before, ('initial MTU', path)
        for _ in range(3):
            attrs = path.stat()
            assert (attrs.st_uid, attrs.st_gid) == (65534, 65534), (path, attrs.st_uid, attrs.st_gid)
        for flags in (os.O_WRONLY, os.O_RDWR, os.O_WRONLY | os.O_TRUNC):
            try:
                fd = opener(path, flags)
            except OSError as error:
                assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
            else:
                os.close(fd)
                raise AssertionError(('virtual-net writable Open permitted', path))
    assert observer() == snapshot, 'Network metadata changed during denied writes'
    for path in paths:
        assert int(path.read_text()) == before, ('MTU changed', path)


def main():
    create_owned_network()
    check_policy()
    print('PASS mapped root nobody Lookup/Getattr and write denial; private MTU unchanged')


if __name__ == '__main__':
    main()
