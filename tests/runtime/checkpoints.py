#!/usr/bin/env python3
"""Trusted launcher ONLY: disposable own sandbox, real notification, C helper.
Never deploy the test helper. No service changes. Requires CAP_SYS_PTRACE for
pidfd_getfd and parent-user root for namespace metadata and helper launch.
Run one case per invocation; binary paths must be visible inside the container.
"""
import argparse
import ctypes
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--filesystem', choices=['proc','sysfs'], default='proc')
parser.add_argument('--outer-pid', type=int, required=True)
parser.add_argument('--helper', type=Path, required=True, help='tests/unit/helper-checkpoint.c binary ONLY')
parser.add_argument('--requester', required=True, help='checkpoint-requester binary visible inside sandbox')
parser.add_argument('--uid', type=int, required=True)
parser.add_argument('--gid', type=int, required=True)
parser.add_argument('--stage', choices=['launch', 'staging', 'transfer', 'commit'], required=True)
parser.add_argument('--action', choices=['interrupt', 'thread-exit', 'process-exit', 'exec'], required=True)
parser.add_argument('--requester-kind', choices=['leader', 'nonleader'], default='nonleader')
parser.add_argument('--exec', dest='prefix', nargs=argparse.REMAINDER, required=True)
args = parser.parse_args()
if os.geteuid() != 0 or not args.prefix or args.outer_pid <= 1 or min(args.uid, args.gid) < 0:
    parser.error('trusted parent-user root, outer PID, mapped IDs and exec prefix required')
if os.uname().machine not in ('x86_64', 'aarch64'):
    parser.error('only existing amd64/arm64 test compilation is supported')
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
fds = []
helper = None
actor = None
observer = None
supervisor_fd = None
observer_fd = None
checkpoint = None
control_fd = None
listener = None
thread_fd = None
copies = []
control_copy = None
child_sock = None
base = '/tmp/issue3-' + uuid.uuid4().hex
token = 'sysbox-issue3-' + uuid.uuid4().hex
# Persistent sandbox supervisor keeps PID 1 alive when the owned requester dies.
code = "import subprocess,sys,time; p=subprocess.Popen(sys.argv[1:],stdin=sys.stdin); p.wait(); time.sleep(40)"
command = args.prefix + ['bwrap', '--die-with-parent', '--unshare-all', '--share-net',
                          '--ro-bind', '/', '/', '--dev-bind', '/dev', '/dev', '--tmpfs', '/tmp',
                          '--ro-bind', args.requester, args.requester,
                          *(['--ro-bind','/tmp/issue5-repo','/tmp/issue5-repo'] if args.filesystem=='sysfs' else []), '--cap-add', 'CAP_SYS_ADMIN', '--', '/usr/bin/python3', '-c', code,
                          args.requester, base+'-proc', base+'-control', args.requester_kind, token]
p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
start = time.monotonic()

def line(timeout=15):
    if not select.select([p.stdout], [], [], timeout)[0]:
        detail = os.read(p.stderr.fileno(), 4096).decode(errors='replace') if select.select([p.stderr], [], [], 0)[0] else ''
        raise AssertionError('requester readiness timeout: ' + detail)
    data = p.stdout.readline().decode().strip()
    if not data:
        detail = os.read(p.stderr.fileno(), 4096).decode(errors='replace') if select.select([p.stderr], [], [], 0)[0] else ''
        raise AssertionError('requester exited before readiness: ' + detail)
    return data

def find(sandbox_pid):
    # Inspect only cmdline to locate this harness's unpredictable token; never
    # signal an operator-supplied arbitrary process. Match NSpid for each actor.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if token.encode() not in (entry/'cmdline').read_bytes().split(b'\0'):
                continue
            status = (entry/'status').read_text().splitlines()
            ids = next(x for x in status if x.startswith('NSpid:')).split()[1:]
            if int(ids[-1]) == sandbox_pid:
                return int(entry.name)
        except (OSError, StopIteration):
            pass
    raise AssertionError('owned actor not found')

def live(fd):
    poll = select.poll(); poll.register(fd, select.POLLIN)
    return not poll.poll(0)

def valid():
    try:
        fcntl.ioctl(listener, 0x40082102, struct.pack('Q', ident))
        return True
    except OSError as e:
        assert e.errno == 2, ('unexpected notification error', e.errno)
        return False

def fifo(name, byte):
    deadline = time.monotonic()+3
    while True:
        try:
            fd = os.open((base+'-control/'+name).lstrip('/'), os.O_WRONLY|os.O_NONBLOCK, dir_fd=control_fd)
            break
        except OSError as e:
            if e.errno != 6 or time.monotonic() >= deadline: raise
            time.sleep(.01)
    try:
        assert os.write(fd, byte) == 1
    finally:
        os.close(fd)

def invalidate():
    if args.action in ('interrupt', 'thread-exit'):
        assert libc.syscall(234 if os.uname().machine == 'x86_64' else 131, actor, tid, signal.SIGUSR1) == 0
        assert line() == 'INTERRUPTED'
        assert live(fds[7]), 'signal invalidation must leave requester alive'
        if args.action == 'thread-exit':
            fifo('exit', b'T')
    elif args.action == 'process-exit':
        signal.pidfd_send_signal(process_fd, signal.SIGKILL)
    else:
        fifo('actor', b'E')
    deadline = time.monotonic()+3
    while valid() and time.monotonic() < deadline:
        time.sleep(.01)
    assert not valid(), 'original notification still valid'
    should_live = args.action == 'interrupt' or (args.action in ('exec', 'thread-exit') and args.requester_kind == 'leader')
    while live(fds[7]) != should_live and time.monotonic() < deadline:
        time.sleep(.01)
    assert live(fds[7]) == should_live, 'unexpected thread pidfd outcome'
    if args.action in ('thread-exit', 'exec'):
        assert live(process_fd), 'another thread/process must survive'

try:
    fields = line().split()
    assert len(fields) == 4 and fields[0] == 'READY', fields
    sandbox_tid, sandbox_observer, listener_number = map(int, fields[1:])
    observer = find(sandbox_observer)
    observer_fd = os.pidfd_open(observer)
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try:
            argv = (entry/'cmdline').read_bytes().split(b'\0')
            if argv[:3] == [b'/usr/bin/python3', b'-c', code.encode()] and token.encode() in argv:
                supervisor_fd = os.pidfd_open(int(entry.name)); break
        except OSError: continue
    assert supervisor_fd is not None, 'owned sandbox supervisor not found'
    # Nonleaders do not appear in /proc iteration. Identify the owned process
    # using cmdline, then the TID using its task NSpid rather than TGID substitution.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try:
            if token.encode() not in (entry/'cmdline').read_bytes().split(b'\0'): continue
            for task in (entry/'task').iterdir():
                ids = next(x for x in (task/'status').read_text().splitlines() if x.startswith('NSpid:')).split()[1:]
                if int(ids[-1]) == sandbox_tid:
                    actor, tid = int(entry.name), int(task.name)
                    break
        except (OSError, StopIteration): continue
        if actor: break
    assert actor and ((actor == tid) == (args.requester_kind == 'leader'))
    control_fd = os.open(f'/proc/{observer}/root', os.O_PATH|os.O_DIRECTORY)
    process_fd = os.pidfd_open(actor)
    # Do not replace the original notifying TID with actor/TGID.
    thread_fd = os.pidfd_open(tid, 0x80)
    copied_listener = libc.syscall(438, thread_fd, listener_number, 0)
    if copied_listener < 0:
        raise OSError(ctypes.get_errno(), 'pidfd_getfd requires trusted ptrace access')
    listener = copied_listener
    message = bytearray(80)
    assert select.select([listener], [], [], 10)[0], 'notification receive deadline'
    fcntl.ioctl(listener, 0xc0502100, message, True)
    ident, notification_tid = struct.unpack_from('QI', message)
    assert notification_tid == tid and valid()
    for pid, ns in [(args.outer_pid,'user'), (args.outer_pid,'mnt'), (tid,'user'), (tid,'mnt'), (tid,'net' if args.filesystem=='sysfs' else 'pid')]:
        fds.append(os.open(f'/proc/{pid}/ns/{ns}', os.O_RDONLY))
    fds.append(os.open(f'/proc/{tid}/root{base}-proc', os.O_PATH|os.O_DIRECTORY))
    fds.append(os.open(f'/proc/{args.outer_pid}/root', os.O_PATH|os.O_DIRECTORY))
    fds.append(thread_fd)
    # All visible outer proc submounts are included; no hard-coded maps/policy.
    paths = []
    for raw in Path(f'/proc/{args.outer_pid}/mountinfo').read_text().splitlines():
        path = raw.split()[4]
        if not path.startswith('/sys/' if args.filesystem=='sysfs' else '/proc/') or path in paths: continue
        assert '\\' not in path
        paths.append(path)
        fds.append(os.open(f'/proc/{args.outer_pid}/root'+path, os.O_PATH))
    assert paths and len(paths) <= 128
    if args.stage == 'launch':
        invalidate()
        # Mirror the daemon's actual pre-launch ioctl: no child exists yet.
        assert not valid() and helper is None
        fifo('observe', b'U')
    else:
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        checkpoint = parent_sock
        copies = [fcntl.fcntl(f, fcntl.F_DUPFD_CLOEXEC, 210) for f in fds]
        control_copy = fcntl.fcntl(child_sock.fileno(), fcntl.F_DUPFD_CLOEXEC, 210)
        def launch():
            for number, source in enumerate(copies, 3): os.dup2(source, number)
            os.dup2(control_copy, 200)
            os.closerange(3+len(copies), 200)
            os.closerange(201, max(copies+[control_copy])+1)
        assert valid(), 'pre-launch notification invalid'
        launch_time = time.monotonic()
        helper = subprocess.Popen([str(args.helper), str(args.uid), str(args.gid), '15',
                                   *[path[5:] if args.filesystem=='sysfs' else path[6:] for path in paths]], close_fds=False,
                                  preexec_fn=launch, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for fd in copies+[control_copy]: os.close(fd)
        copies = []; control_copy = None
        child_sock.close(); child_sock = None
        selected = {'staging':b'S', 'transfer':b'T', 'commit':b'C'}[args.stage]
        while True:
            assert select.select([checkpoint], [], [], 22)[0], 'helper checkpoint timeout'
            event = checkpoint.recv(1)
            assert event in (b'S',b'T',b'C'), ('missing checkpoint', event)
            children = Path(f'/proc/{helper.pid}/task/{helper.pid}/children').read_text().strip()
            assert not children, 'locker was not synchronously reaped before checkpoint'
            if event == selected:
                invalidate()
                checkpoint.send(b'A')
                break
            checkpoint.send(b'A')
        # Resume later checkpoints. Exit paths may close without another event.
        while helper.poll() is None:
            if select.select([checkpoint], [], [], .05)[0]:
                event = checkpoint.recv(1)
                if event: checkpoint.send(b'A')
                else: break
        stdout, stderr = helper.communicate(timeout=27)
        exits_detected = args.action == 'process-exit' or (args.action in ('thread-exit','exec') and args.requester_kind=='nonleader')
        commit = args.stage=='commit' or not exits_detected
        assert (helper.returncode==0) == commit, (helper.returncode, stderr.decode(errors='replace'))
        if not commit: assert helper.returncode==3 and b'requester alive' in stderr
        assert not valid(), 'invalid original request must never receive success'
        response = struct.pack('QqiI', ident, 0, 0, 0)
        try: fcntl.ioctl(listener, 0xc0182101, response)
        except OSError as e: assert e.errno==2
        else: raise AssertionError('success delivered to invalid notification')
        fifo('observe', b'V' if commit else b'U')
    assert line(30).startswith('PASS '), 'surviving observer failed'
    # Check synchronous worker/locker cleanup, including owned FDs/mounts:
    # no child remains under the exited worker; pinned trees close at exit.
    if helper:
        assert not Path(f'/proc/{helper.pid}').exists(), 'helper not reaped'
        assert time.monotonic()-launch_time < 30, 'helper cleanup exceeded bound'
    assert time.monotonic()-start < 40, 'case exceeded cleanup/test bound'
    print('PASS', args.requester_kind, args.stage, args.action)
finally:
    if helper and helper.poll() is None:
        helper.kill(); helper.wait(timeout=5)
    if checkpoint: checkpoint.close()
    for owned in (locals().get('process_fd'), observer_fd, supervisor_fd):
        if owned is not None:
            try: signal.pidfd_send_signal(owned, signal.SIGKILL)
            except ProcessLookupError: pass
    if child_sock: child_sock.close()
    for fd in copies + ([control_copy] if control_copy is not None else []): os.close(fd)
    if thread_fd is not None and thread_fd not in fds: os.close(thread_fd)
    for fd in fds: os.close(fd)
    for fd in (listener, control_fd, locals().get('process_fd'), observer_fd, supervisor_fd):
        if fd is not None: os.close(fd)
    if p.poll() is None:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
