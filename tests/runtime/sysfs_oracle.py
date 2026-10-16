"""Independent Network observations shared by disposable sysfs runtime fixtures.

No sysfs input is used to construct the expected interface snapshot. Observer,
path and parsing errors propagate; callers must never turn them into a pass.
"""
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat
import struct

VIEWS = ('class/net', 'devices/virtual/net')
OPTIONAL_ATTRIBUTE = 'bonding_masters'


def aligned(length):
    return (length + 3) & ~3


def messages(data):
    """Yield bounded, aligned nlmsghdr messages from one datagram."""
    offset = 0
    while offset < len(data):
        assert len(data) - offset >= 16, 'short netlink header'
        length, kind, flags, seq, pid = struct.unpack_from('=IHHII', data, offset)
        assert 16 <= length <= len(data) - offset, 'invalid netlink length'
        assert offset + aligned(length) <= len(data), 'short netlink padding'
        yield kind, flags, seq, pid, data[offset + 16:offset + length]
        offset += aligned(length)


def link_info(payload):
    assert len(payload) >= 16, 'short ifinfomsg'
    index = struct.unpack_from('=i', payload, 4)[0]
    attrs = {}
    offset = 16
    while offset < len(payload):
        assert len(payload) - offset >= 4, 'short rtattr'
        length, kind = struct.unpack_from('=HH', payload, offset)
        assert 4 <= length <= len(payload) - offset, 'invalid rtattr length'
        assert offset + aligned(length) <= len(payload), 'short rtattr padding'
        if kind in (3, 4):  # IFLA_IFNAME, IFLA_MTU
            assert kind not in attrs, 'duplicate link attribute'
            attrs[kind] = payload[offset + 4:offset + length]
        offset += aligned(length)
    name = attrs[3]
    assert name.endswith(b'\0') and b'\0' not in name[:-1], 'invalid interface name'
    name = os.fsdecode(name[:-1])
    assert name and '/' not in name and name not in ('.', '..'), 'invalid interface name'
    assert len(attrs[4]) == 4, 'invalid MTU attribute'
    mtu = struct.unpack('=I', attrs[4])[0]
    assert index > 0 and mtu > 0, 'invalid interface metadata'
    return name, (index, mtu)


def netlink_snapshot():
    """RTM_GETLINK dump in the calling thread's Network, including index/MTU."""
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.settimeout(5)
        sock.bind((0, 0))
        seq = 1
        payload = struct.pack('=BBHiII', socket.AF_UNSPEC, 0, 0, 0, 0, 0)
        sock.sendto(struct.pack('=IHHII', 16 + len(payload), 18, 0x301, seq, 0) + payload, (0, 0))
        result = {}
        indices = set()
        while True:
            data, _, flags, address = sock.recvmsg(1024 * 1024)
            assert data and not flags & socket.MSG_TRUNC and address[0] == 0, 'invalid netlink datagram'
            done = False
            for kind, header_flags, received_seq, pid, payload in messages(data):
                assert received_seq == seq and pid == sock.getsockname()[0], 'unrelated netlink reply'
                assert not header_flags & 0x10, 'interrupted netlink dump'
                assert not done, 'data after netlink completion'
                if kind == 3:  # NLMSG_DONE (may carry a negative dump error)
                    assert len(payload) in (0, 4), 'invalid dump completion'
                    if payload:
                        error = struct.unpack('=i', payload)[0]
                        if error:
                            raise OSError(abs(error), 'netlink dump failed')
                    done = True
                elif kind == 2:
                    assert len(payload) >= 4, 'short netlink error'
                    error = struct.unpack_from('=i', payload)[0]
                    raise OSError(abs(error) or errno.EPROTO, 'netlink error')
                else:
                    assert kind == 16 and header_flags & 2, 'unexpected link reply'
                    name, metadata = link_info(payload)
                    assert name not in result and metadata[0] not in indices, 'duplicate interface'
                    result[name] = metadata
                    indices.add(metadata[0])
            if done:
                assert result, 'empty link dump'
                return result


def parse_dirents(data):
    """Parse every linux_dirent64, rejecting truncated or malformed records."""
    entries = []
    offset = 0
    while offset < len(data):
        assert len(data) - offset >= 20, 'short getdents header'
        length = struct.unpack_from('=H', data, offset + 16)[0]
        assert length >= 24 and length % 8 == 0 and length <= len(data) - offset, 'invalid d_reclen'
        raw_name = data[offset + 19:offset + length]
        assert b'\0' in raw_name, 'unterminated directory name'
        name = os.fsdecode(raw_name.split(b'\0', 1)[0])
        assert name and '/' not in name, 'invalid directory name'
        kind = data[offset + 18]
        assert kind in (0, 1, 2, 4, 6, 8, 10, 12), 'invalid d_type'
        entries.append((name, kind))
        offset += length
    return entries


def raw_chunk(fd, size=8192):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    number = {'x86_64': 217, 'aarch64': 61}[os.uname().machine]
    buf = ctypes.create_string_buffer(size)
    count = libc.syscall(number, fd, buf, size)
    if count < 0:
        error = ctypes.get_errno()
        raise OSError(error, 'getdents64')
    assert count <= size, 'oversized getdents result'
    return parse_dirents(buf.raw[:count])


def raw_entries(fd, reader=raw_chunk):
    entries = []
    while True:
        chunk = reader(fd)
        if not chunk:
            return entries
        entries.extend(chunk)


def checked_names(path, entries):
    names = set()
    for name, kind in entries:
        assert name not in names, ('duplicate directory entry', name)
        names.add(name)
        actual = path.lstat() if name == '.' else path.parent.lstat() if name == '..' else (path / name).lstat()
        # DT_UNKNOWN is allowed by getdents; lstat still supplies the required type.
        assert kind == 0 or kind == stat.S_IFMT(actual.st_mode) >> 12, ('wrong d_type', name)
    return names - {'.', '..'}


def interface_names(path, names, snapshot):
    """Only the exact, regular optional attribute may be excluded."""
    names = set(names)
    if OPTIONAL_ATTRIBUTE in names and OPTIONAL_ATTRIBUTE not in snapshot:
        assert stat.S_ISREG((path / OPTIONAL_ATTRIBUTE).lstat().st_mode), 'malformed bonding_masters'
        names.remove(OPTIONAL_ATTRIBUTE)
    assert names <= set(snapshot), ('foreign network entry', path, names, snapshot)
    return names


def check_absent(path, names):
    for name in names:
        try:
            (path / name / 'ifindex').stat()
        except FileNotFoundError:
            pass
        else:
            raise AssertionError(('namespace cache bleed', name))


def check_view(path, snapshot, *, class_view=False, absent=(), reader=raw_chunk):
    path = Path(path)
    assert stat.S_ISDIR(path.stat().st_mode), ('network directory type', path)
    high_entries = set(os.listdir(path))
    high = interface_names(path, high_entries, snapshot)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        raw = checked_names(path, raw_entries(fd, reader))
    finally:
        os.close(fd)
    assert raw == high_entries, ('raw/high-level entries differ', path)
    raw = interface_names(path, raw, snapshot)
    assert high == raw == set(snapshot), ('incomplete network view', path, high, raw, snapshot)
    for name, (index, mtu) in snapshot.items():
        entry = path / name
        mode = entry.lstat().st_mode
        if class_view:
            assert stat.S_ISLNK(mode) and os.readlink(entry), ('interface symlink', entry)
            assert entry.resolve(strict=True).is_dir(), ('interface target type', entry)
        else:
            assert stat.S_ISDIR(mode), ('virtual interface type', entry)
        for attribute in ('ifindex', 'mtu'):
            assert stat.S_ISREG((entry / attribute).lstat().st_mode), ('metadata type', entry, attribute)
        assert int((entry / 'ifindex').read_text()) == index, ('ifindex', entry)
        assert int((entry / 'mtu').read_text()) == mtu, ('MTU', entry)
        assert (entry / 'subsystem').is_symlink() and os.readlink(entry / 'subsystem'), ('subsystem', entry)
    check_absent(path, absent)


def check_network(base, *, observer=netlink_snapshot, absent=('absent-issue5-interface',)):
    snapshot = observer()
    assert snapshot, 'empty independent snapshot'
    for relative in VIEWS:
        check_view(Path(base) / relative, snapshot, class_view=relative == 'class/net', absent=absent)
    return snapshot


def check_stale(fd, path, snapshot, reader=raw_chunk):
    # Old cookies may yield a partial/empty view or EIO, but never foreign entries.
    seen = set()
    while True:
        try:
            entries = reader(fd)
        except OSError as error:
            assert error.errno == errno.EIO, error
            return
        if not entries:
            return
        names = checked_names(Path(path), entries)
        assert not seen & names, 'duplicate stale directory entry'
        seen.update(names)
        interface_names(Path(path), names, snapshot)


def check_shared_handle(fd, path, snapshot, reader=raw_chunk):
    check_stale(fd, path, snapshot, reader)
    # A stale cookie is not a complete enumeration. Rewind the same FD in
    # this Network and require its entire current view, reading to EOF.
    os.lseek(fd, 0, os.SEEK_SET)
    names = checked_names(path, raw_entries(fd, reader))
    assert interface_names(path, names, snapshot) == set(snapshot), 'rewound shared handle incomplete'


def namespace_identity(path):
    attrs = os.stat(path)
    return attrs.st_dev, attrs.st_ino


def create_owned_network():
    """Refuse before any writable open unless fresh Net ownership is proven."""
    assert os.geteuid() == 0, 'mapped root required'
    for name in ('uid_map', 'gid_map'):
        rows = [tuple(map(int, row.split())) for row in Path('/proc/self', name).read_text().splitlines()]
        assert rows and all(len(row) == 3 and row[0] >= 0 and row[1] >= 0 and row[2] > 0
                            for row in rows), 'invalid User map'
        assert sum(row[2] for row in rows) < 4294967295, 'bounded mapped User required'
    user = namespace_identity('/proc/self/ns/user')
    before = namespace_identity('/proc/self/ns/net')
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.unshare(0x40000000) == 0, ('private Network unavailable', ctypes.get_errno())
    fd = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    try:
        owner = fcntl.ioctl(fd, 0xb701)  # NS_GET_USERNS returns an owned FD.
        try:
            attrs = os.fstat(owner)
            assert (attrs.st_dev, attrs.st_ino) == user, 'Network not owned by current User'
        finally:
            os.close(owner)
        attrs = os.fstat(fd)
        assert (attrs.st_dev, attrs.st_ino) != before, 'Network identity did not change'
        assert namespace_identity('/proc/self/ns/user') == user, 'User changed during preflight'
    finally:
        os.close(fd)
