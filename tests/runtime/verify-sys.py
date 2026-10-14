import ctypes
import json
import os
import sys

mode, manifest = sys.argv[1:]
if mode == "capture":
    entries = {}
    with open("/proc/self/mountinfo") as stream:
        for line in stream:
            path = line.split()[4]
            if not path.startswith("/sys/"):
                continue
            assert "\\" not in path, "escaped mount path unsupported in diagnostic"
            stat = os.stat(path)
            entries[path] = [stat.st_dev, stat.st_ino, os.statvfs(path).f_flag]
    assert entries, "no /sys protection submounts"
    with open(manifest, "w") as stream:
        json.dump(entries, stream)
else:
    assert mode == "check"
    with open("/proc/self/status") as stream:
        status = dict(line.rstrip().split(":", 1) for line in stream)
    assert int(status["CapEff"], 16) & (1 << 21), "CAP_SYS_ADMIN required"
    assert int(status["Seccomp"]) == 2
    libc = ctypes.CDLL(None, use_errno=True)
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    with open(manifest) as stream:
        entries = json.load(stream)
    for path, (device, inode, flags) in entries.items():
        stat = os.stat(path)
        assert (stat.st_dev, stat.st_ino) == (device, inode), path
        assert not flags & os.ST_RDONLY or os.statvfs(path).f_flag & os.ST_RDONLY, path
        ctypes.set_errno(0)
        result = libc.umount2(path.encode(), 2)
        print(f"sys protection {path}: inode retained, detach={result}, errno={ctypes.get_errno()}")
        assert result == -1, "sys protection detached"
    print(f"PASS {len(entries)} sys submount identities, readonly attributes and detach denial")
