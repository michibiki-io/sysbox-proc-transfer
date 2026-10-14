"""Exercise existing helper rejection cases against a disposable owned sandbox.
Run from the trusted launcher environment with an explicit outer PID, helper,
actor IDs and container-exec prefix; this script does not configure a runtime.
"""
import argparse
import os, subprocess, time, pathlib, uuid, signal, fcntl
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--outer-pid', type=int, required=True)
parser.add_argument('--helper', type=pathlib.Path, required=True)
parser.add_argument('--uid', type=int, required=True)
parser.add_argument('--gid', type=int, required=True)
parser.add_argument('--mode', choices=['wrong-owner', 'dead-requester', 'unsupported-flags', 'mapped-launcher'], required=True)
parser.add_argument('--exec', dest='prefix', nargs=argparse.REMAINDER, required=True)
args = parser.parse_args()
if os.geteuid() != 0 or args.outer_pid <= 1 or args.uid < 0 or args.gid < 0 or not args.prefix:
    parser.error('trusted root launcher, live outer PID, mapped IDs and exec prefix required')
prefix = args.prefix
token='sysbox-proc-hidden-check-'+uuid.uuid4().hex
code=r'''import os,sys,time,ctypes
p='/tmp/proc-hidden';os.mkdir(p)
for _ in range(1200):
 if os.path.exists(p+'/1/ns/pid'):break
 time.sleep(.1)
else:raise RuntimeError('helper timeout')
assert os.readlink(p+'/1/ns/pid')==os.readlink('/proc/self/ns/pid')
assert os.getpid()>0
libc=ctypes.CDLL(None,use_errno=True)
for n in ['sys','bus','fs','irq','sysrq-trigger','interrupts','keys','timer_list']:
 r=libc.umount2((p+'/'+n).encode(),2)
 assert r==-1,('detach allowed',n)
for n in ['interrupts','keys','timer_list']:assert open(p+'/'+n,'rb').read(1)==b''
if int(sys.argv[1])&1:
 for n in ['', '/sys','/bus','/fs','/irq','/keys']:assert os.statvfs(p+n).f_flag&os.ST_RDONLY
 print('PASS recursive readonly proc',flush=True)
print('PASS sandbox PID identity, locked submounts and masked files',flush=True)
'''
procflags='14'
p=subprocess.Popen(prefix+['bwrap','--die-with-parent','--unshare-all','--share-net','--ro-bind','/','/','--dev-bind','/dev','/dev','--tmpfs','/tmp','--cap-add','CAP_SYS_ADMIN','--','/usr/bin/python3','-c',code,procflags,token])
fds=[]
mode=args.mode
try:
 target=None
 for _ in range(100):
  for d in pathlib.Path('/proc').iterdir():
   if not d.name.isdigit():continue
   try:
    cmd=(d/'cmdline').read_bytes().split(b'\0')
    if len(cmd)>3 and cmd[0]==b'/usr/bin/python3' and cmd[-2]==token.encode():target=int(d.name);break
   except (OSError,ProcessLookupError):pass
  if target:break
  time.sleep(.1)
 assert target,'own sandbox child not found'
 for _ in range(100):
  if pathlib.Path(f'/proc/{target}/root/tmp/proc-hidden').is_dir():break
  time.sleep(.05)
 else:raise RuntimeError('sandbox directory readiness timeout')
 outer=args.outer_pid
 for pid,n in [(outer,'user'),(outer,'mnt'),(target,'user'),(target,'mnt'),(target,'pid')]:
  fds.append(os.open(f'/proc/{pid}/ns/{n}',os.O_RDONLY))
 fds.append(os.open(f'/proc/{target}/root/tmp/proc-hidden',os.O_PATH|os.O_DIRECTORY))
 fds.append(os.open(f'/proc/{outer}/root',os.O_PATH|os.O_DIRECTORY))
 fds.append(os.pidfd_open(target))
 names=[]
 for n in ['uptime','swaps','sys','bus','fs','irq','sysrq-trigger','asound','interrupts','keys','timer_list']:
  try:f=os.open(f'/proc/{outer}/root/proc/{n}',os.O_PATH)
  except FileNotFoundError:continue
  names.append(n);fds.append(f)
 # Duplicate safely: original descriptors may overlap destination numbers.
 if mode=='wrong-owner':os.close(fds[3]);fds[3]=os.dup(fds[1])
 if mode=='dead-requester':signal.pidfd_send_signal(fds[7],signal.SIGKILL)
 copies=[__import__('fcntl').fcntl(f,__import__('fcntl').F_DUPFD_CLOEXEC,200) for f in fds]
 def launch():
  for i,f in enumerate(copies,3):os.dup2(f,i,inheritable=True)
  if mode=="mapped-launcher":os.setns(3,0);os.setgid(0);os.setuid(0)
 r=subprocess.Popen([str(args.helper),str(args.uid),str(args.gid),('9223372036854775808' if mode=='unsupported-flags' else procflags),*names],close_fds=False,preexec_fn=launch,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 time.sleep(.3)
 stdout,stderr=r.communicate(timeout=25)
 expected={
  'wrong-owner':(b'requester mount owner',),
  'dead-requester':(b'requester alive',),
  'unsupported-flags':(b'supported proc flags',),
  'mapped-launcher':(b'outer user parent',b'trusted parent-user launcher'),
 }[mode]
 assert any(reason in stderr for reason in expected),(mode,'unexpected rejection',stderr.decode(errors='replace'))
 result=r.returncode
 if mode:
  assert result!=0,('negative request accepted',mode)
  if mode!='dead-requester':assert not pathlib.Path(f'/proc/{target}/root/tmp/proc-hidden/1').exists(),'failed request changed target'
  print('PASS fail-closed '+mode,flush=True)
  raise SystemExit(0)
finally:
 if p.poll() is None:
  if len(fds)>7:
   try:signal.pidfd_send_signal(fds[7],signal.SIGKILL)
   except ProcessLookupError:pass
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=10)
 for f in fds:os.close(f)
 for f in locals().get('copies',[]):os.close(f)
