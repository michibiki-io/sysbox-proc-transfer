#!/usr/bin/env python3
"""Run inside a capable direct-child sandbox, never on a consumer host.
Create two owned Network namespaces; interleave uncached FUSE requests with
outer/shared namespace priming of present and absent entries and attributes.
"""
import ctypes
import os
from pathlib import Path
import socket
import subprocess
import sys
import struct

path = Path(sys.argv[1]) / 'devices/virtual/net'
libc = ctypes.CDLL(None, use_errno=True)
import signal
signal.alarm(120)

def check(name, mtu, absent):
    assert set(os.listdir(path)) == {name}
    index = dict((n, i) for i, n in socket.if_nameindex())[name]
    assert int((path/name/'ifindex').read_text()) == index
    assert int((path/name/'mtu').read_text()) == mtu
    assert os.readlink(path/name/'subsystem')
    for n in absent:
        try:
            (path/n/'ifindex').stat()
        except FileNotFoundError:
            pass
        else:
            raise AssertionError(('namespace cache bleed', n, name))

# This parent Network must also be owned by the direct child User namespace.
# A veth pair exists only in this disposable network, never in an outer network.
subprocess.run(['ip','link','add','issue5-prime','type','veth','peer','name','issue5-peer'],check=True)
shared = os.open(path,os.O_RDONLY|os.O_DIRECTORY)
raw_call={'x86_64':217,'aarch64':61}[os.uname().machine]
def raw_names(fd,size):
    buf=ctypes.create_string_buffer(size)
    n=libc.syscall(raw_call,fd,buf,size)
    assert n>=0,('raw directory read',ctypes.get_errno())
    data=buf.raw[:n];names=[];offset=0
    while offset<len(data):
        length=struct.unpack_from('H',data,offset+16)[0]
        assert length>0
        names.append(data[offset+19:offset+length].split(b'\0')[0].decode())
        offset+=length
    return names
assert raw_names(shared,40), 'prime a partial directory read'
workers = []
try:
    for name, mtu in [('issue5a', 1101), ('issue5b', 1202)]:
        command_r, command_w = os.pipe()
        reply_r, reply_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(command_w); os.close(reply_r)
                for _, old_command, old_reply in workers:
                    os.close(old_command); os.close(old_reply)
                parent = os.getppid()
                assert libc.prctl(1, 9, 0, 0, 0) == 0 and os.getppid() == parent
                assert libc.unshare(0x40000000) == 0, ('unshare net', ctypes.get_errno())
                subprocess.run(['ip','link','set','lo','name',name],check=True)
                subprocess.run(['ip','link','set',name,'mtu',str(mtu)],check=True)
                # The shared handle has a nonzero offset primed in another Network.
                # Cache reuse may leak the parent's remaining interface names.
                assert set(raw_names(shared,8192)) <= {name}, 'per-handle namespace cache bleed'
                os.write(reply_w,b'R')
                while os.read(command_r,1) == b'C':
                    check(name,mtu,{'lo','issue5a','issue5b'}-{name})
                    os.write(reply_w,b'P')
                os._exit(0)
            except BaseException as e:
                print(repr(e),file=sys.stderr,flush=True)
                os._exit(1)
        os.close(command_r); os.close(reply_w)
        workers.append((pid, command_w, reply_r))
        assert os.read(reply_r,1) == b'R'
    # Prime the shared/outer network's positive/negative and attribute results.
    assert 'lo' in os.listdir(path)
    assert int((path/'lo/ifindex').read_text()) == socket.if_nametoindex('lo')
    for name in ('issue5a','issue5b'):
        try:
            (path/name/'ifindex').stat()
        except FileNotFoundError:
            pass
        else:
            raise AssertionError('outer negative prime failed')
    for _ in range(8):
        for pid, command, reply in workers:
            os.write(command,b'C')
            assert os.read(reply,1) == b'P', ('worker failure',pid)
        assert 'lo' in os.listdir(path)
        assert int((path/'lo/ifindex').read_text()) == socket.if_nametoindex('lo')
    print('PASS interleaved two Network namespaces and outer/shared cache priming')
finally:
    os.close(shared)
    for _, command, reply in workers:
        os.close(command); os.close(reply)
    for pid, _, _ in workers:
        _, status = os.waitpid(pid,0)
        assert os.waitstatus_to_exitcode(status) == 0
